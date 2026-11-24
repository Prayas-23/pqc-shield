"""Drift measurement.

Quantifies how feature distributions differ between groups (e.g. handshake profiles):
  - psi:            population stability index (one feature, two samples)
  - mmd2_rbf:       unbiased squared MMD with an RBF kernel (multivariate) + permutation p-value
  - eta_squared:    one-way effect size, SS_between / SS_total
  - two_way_effects: partial eta-squared for two factors and their interaction
  - drift_table:    all of the above for a reference group vs other groups
  - pqc_contrast_table: the fixed CIC-PQC_OAV contrasts (kem at fixed auth, auth at fixed kem,
                    two-way on the crossed block, pooled-and-confounded cell comparisons)

Effect sizes are the headline numbers; p-values are secondary (with tens of thousands of rows
they are tiny for any difference). Functions that take a DataFrame call assert_single_source.
NaNs are dropped (per feature for psi/eta, row-wise for MMD).
"""

from __future__ import annotations

import warnings
from dataclasses import dataclass, field
from typing import Any, Sequence

import numpy as np
import pandas as pd
from scipy.spatial.distance import cdist, pdist
from statsmodels.formula.api import ols
from statsmodels.stats.anova import anova_lm

from pqdl.features import FEATURES_VERSION, PQC_DRIFT_FEATURES
from pqdl.loaders import assert_single_source

PSI_EPS = 1e-4
MAX_CATEGORIES = 20
SS_TOL = 1e-12  # an ANOVA sum of squares below this fraction of the total is treated as exactly 0


# ------------------------------------------------------------------------------------- PSI
def _clean_1d(x: Any) -> np.ndarray:
    arr = np.asarray(x, dtype=float).ravel()
    arr = arr[np.isfinite(arr)]
    if arr.size == 0:
        raise ValueError("sample is empty after dropping NaN/inf")
    return arr


def psi_mode(ref: Any, new: Any, max_categories: int = MAX_CATEGORIES) -> str:
    """'categorical' if ref and new together have <= max_categories distinct values, else 'quantile'."""
    distinct = np.unique(np.concatenate([_clean_1d(ref), _clean_1d(new)])).size
    return "categorical" if distinct <= max_categories else "quantile"


def _bin_counts(ref: np.ndarray, new: np.ndarray, bins: int, mode: str) -> tuple[np.ndarray, np.ndarray]:
    if mode == "categorical":
        cats = np.unique(np.concatenate([ref, new]))
        k = cats.size
        return (np.bincount(np.searchsorted(cats, ref), minlength=k),
                np.bincount(np.searchsorted(cats, new), minlength=k))
    # Reference-quantile bins: interior edges only, so values outside the reference range fall
    # into the two open-ended tail bins. Ties in the quantiles collapse into fewer bins.
    inner = np.unique(np.quantile(ref, np.linspace(0.0, 1.0, bins + 1)[1:-1]))
    k = inner.size + 1
    return (np.bincount(np.searchsorted(inner, ref, side="left"), minlength=k),
            np.bincount(np.searchsorted(inner, new, side="left"), minlength=k))


def _smooth(counts: np.ndarray, eps: float) -> np.ndarray:
    p = np.maximum(counts / counts.sum(), eps)
    return p / p.sum()


def psi(ref: Any, new: Any, bins: int = 10, eps: float = PSI_EPS,
        max_categories: int = MAX_CATEGORIES) -> float:
    """Population stability index, PSI = sum((p - q) * ln(p / q)); p = reference, q = new.

    Categorical path: if ref and new together have <= `max_categories` distinct values, use one
    bin per distinct value. Otherwise use `bins` bins with edges from the reference quantiles.
    Proportions are floored at `eps` and renormalised (smoothing) so empty bins stay finite.
    """
    if bins < 2:
        raise ValueError("bins must be >= 2")
    r, n = _clean_1d(ref), _clean_1d(new)
    c_ref, c_new = _bin_counts(r, n, bins, psi_mode(r, n, max_categories))
    p, q = _smooth(c_ref, eps), _smooth(c_new, eps)
    return float(np.sum((p - q) * np.log(p / q)))


# ------------------------------------------------------------------------------------- MMD
@dataclass(frozen=True)
class MMDResult:
    """Result of mmd2_rbf. p_value is NaN when n_perm == 0."""

    mmd2: float
    p_value: float
    gamma: float
    n_x: int
    n_y: int
    note: str = ""


def _as_2d(a: Any) -> np.ndarray:
    arr = np.asarray(a, dtype=float)
    arr = arr.reshape(-1, 1) if arr.ndim == 1 else arr
    return arr[np.isfinite(arr).all(axis=1)]


def _subsample(a: np.ndarray, max_n: int, rng: np.random.Generator) -> np.ndarray:
    if len(a) <= max_n:
        return a
    return a[np.sort(rng.choice(len(a), size=max_n, replace=False))]


def _standardise(z: np.ndarray) -> np.ndarray:
    sd = z.std(axis=0)
    return (z - z.mean(axis=0)) / np.where(sd > 0, sd, 1.0)


def _median_gamma(z: np.ndarray) -> float | None:
    """RBF gamma = 1 / (2 sigma^2) with sigma the median pairwise distance.

    If the median is 0, sigma falls back to the mean of the nonzero distances; if there are
    none, return None.
    """
    dist = pdist(z)
    sigma = float(np.median(dist))
    if sigma == 0.0:
        nonzero = dist[dist > 0]
        sigma = float(nonzero.mean()) if nonzero.size else 0.0
    return 1.0 / (2.0 * sigma**2) if sigma > 0 else None


def _mmd2_from_membership(k: np.ndarray, row_sums: np.ndarray, total: float, a: np.ndarray) -> float:
    """Unbiased MMD^2 for the split given by indicator `a` (1 = X). Uses K_ii = 1."""
    m = float(a.sum())
    n = float(len(a) - m)
    aka = float(a @ (k @ a))
    ar = float(a @ row_sums)
    akb = ar - aka
    bkb = total - 2.0 * ar + aka
    return (aka - m) / (m * (m - 1)) + (bkb - n) / (n * (n - 1)) - 2.0 * akb / (m * n)


def mmd2_rbf(X: Any, Y: Any, gamma: float | str = "median", max_n: int = 2000, n_perm: int = 200,
             seed: int = 0, standardise: bool = True) -> MMDResult:
    """Unbiased squared MMD with an RBF kernel, plus a permutation p-value.

    X, Y: (n, d) arrays (rows with NaN/inf are dropped). Each is subsampled to `max_n` rows with
    a fixed `seed` to bound memory (the kernel matrix is (nx+ny)^2 floats). With
    `standardise=True`, columns are z-scored using the pooled subsample first. gamma='median'
    uses the median heuristic (see _median_gamma); if every pairwise distance is 0 a warning is
    raised and mmd2 = 0.0 is returned. The p-value is (1 + #{perm >= observed}) / (1 + n_perm),
    permuting the X/Y membership; it is NaN if n_perm == 0.
    """
    rng = np.random.default_rng(seed)
    x, y = _subsample(_as_2d(X), max_n, rng), _subsample(_as_2d(Y), max_n, rng)
    if len(x) < 2 or len(y) < 2:
        raise ValueError("need at least 2 finite rows in each sample")
    z = np.vstack([x, y])
    z = _standardise(z) if standardise else z
    g = _median_gamma(z) if gamma == "median" else float(gamma)
    p_zero = 1.0 if n_perm > 0 else float("nan")
    if g is None:
        msg = "all pairwise distances are 0; MMD is undefined, returning 0.0"
        warnings.warn(msg, UserWarning, stacklevel=2)
        return MMDResult(0.0, p_zero, float("nan"), len(x), len(y), msg)
    if g <= 0:
        raise ValueError("gamma must be > 0")
    k = cdist(z, z, "sqeuclidean")
    np.multiply(k, -g, out=k)
    np.exp(k, out=k)
    row_sums = k.sum(axis=1)
    total = float(row_sums.sum())
    a = np.zeros(len(z))
    a[: len(x)] = 1.0
    observed = _mmd2_from_membership(k, row_sums, total, a)
    p_value = float("nan")
    if n_perm > 0:
        hits = 0
        for _ in range(n_perm):
            perm = np.zeros(len(z))
            perm[rng.permutation(len(z))[: len(x)]] = 1.0
            hits += _mmd2_from_membership(k, row_sums, total, perm) >= observed
        p_value = (1 + hits) / (1 + n_perm)
    return MMDResult(observed, p_value, g, len(x), len(y))


# ----------------------------------------------------------------------------- effect sizes
def eta_squared(df: pd.DataFrame, feature: str, factor: str) -> float:
    """One-way eta squared = SS_between / SS_total. NaN if the feature is constant (SS_total = 0).

    Rows with NaN in `feature` or `factor` are dropped.
    """
    assert_single_source(df)
    sub = df[[feature, factor]].dropna()
    y = sub[feature].to_numpy(dtype=float)
    if y.size == 0:
        return float("nan")
    if np.ptp(y) == 0.0:  # exactly constant: effect undefined (and avoids dividing round-off by round-off)
        return float("nan")
    grand = y.mean()
    ss_total = float(((y - grand) ** 2).sum())
    stats = sub.groupby(factor, observed=True)[feature].agg(["mean", "size"])
    ss_between = float((stats["size"] * (stats["mean"] - grand) ** 2).sum())
    return ss_between / ss_total


@dataclass(frozen=True)
class TwoWayResult:
    """design: 'two_way' (effects are partial eta^2 for each factor and the interaction) or
    'one_way_only' (effects are one-way eta^2 per factor; `reason` says why)."""

    design: str
    reason: str
    effect_kind: str
    effects: dict[str, float]
    cell_sizes: dict[str, int] = field(default_factory=dict)


def _cell_sizes(sub: pd.DataFrame, a: str, b: str) -> dict[str, int]:
    return {f"{ka}+{kb}": int(n) for (ka, kb), n in sub.groupby([a, b], observed=True).size().items()}


def _design_problem(sub: pd.DataFrame, a: str, b: str) -> str:
    counts = pd.crosstab(sub[a], sub[b])
    empty = [f"{i}+{j}" for i in counts.index for j in counts.columns if counts.loc[i, j] == 0]
    if empty:
        return f"not crossed: empty cells {empty}"
    small = [f"{i}+{j}" for i in counts.index for j in counts.columns if counts.loc[i, j] < 2]
    return f"cells with fewer than 2 rows: {small}" if small else ""


def two_way_effects(df: pd.DataFrame, feature: str, factor_a: str, factor_b: str) -> TwoWayResult:
    """Partial eta^2 for factor_a, factor_b and their interaction (Type II ANOVA, statsmodels).

    Only done if the cell table supports it: every factor_a x factor_b combination present with
    >= 2 rows. Otherwise returns one-way eta^2 for each factor and the reason. Rows with NaN in
    any of the three columns are dropped. Partial eta^2 = SS_effect / (SS_effect + SS_residual).
    """
    assert_single_source(df)
    sub = df[[feature, factor_a, factor_b]].dropna()
    sizes = _cell_sizes(sub, factor_a, factor_b)
    problem = _design_problem(sub, factor_a, factor_b)
    if problem:
        one_way = {f: eta_squared(sub.assign(source=df["source"].iloc[0]), feature, f) for f in (factor_a, factor_b)}
        return TwoWayResult("one_way_only", problem, "eta2", one_way, sizes)
    y = sub[feature].astype(float).to_numpy()
    names = {"C(A)": factor_a, "C(B)": factor_b, "C(A):C(B)": f"{factor_a}:{factor_b}"}
    if np.ptp(y) == 0.0:  # exactly constant feature: effects are undefined
        return TwoWayResult("two_way", "feature is constant", "partial_eta2",
                            {label: float("nan") for label in names.values()}, sizes)
    data = pd.DataFrame({"y": y - y.mean(), "A": sub[factor_a].astype(str).to_numpy(),
                         "B": sub[factor_b].astype(str).to_numpy()})  # centred: round-off scales with SS_total
    table = anova_lm(ols("y ~ C(A) * C(B)", data=data).fit(), typ=2)
    ss_res = float(table.loc["Residual", "sum_sq"])
    ss_total = float(table["sum_sq"].sum())
    effects = {}
    for term, label in names.items():
        ss = float(table.loc[term, "sum_sq"])
        # An effect below SS_TOL of the total variation is round-off, not signal: report exactly 0.
        effects[label] = 0.0 if ss <= SS_TOL * ss_total else ss / (ss + ss_res)
    return TwoWayResult("two_way", "", "partial_eta2", effects, sizes)


# ------------------------------------------------------------------------------ drift table
def drift_table(
    df: pd.DataFrame, group_col: str, ref_group: Any, features: Sequence[str],
    compare_groups: Sequence[Any] | None = None, n_perm: int = 200, max_n: int = 2000, seed: int = 0,
) -> pd.DataFrame:
    """Reference group vs each compared group: one row per (compared group, feature).

    Columns: eta2 (feature, ref vs that group only), eta2_all_groups (feature over every group in
    `df`), psi, psi_mode, and the multivariate MMD on the whole `features` set (computed once per
    compared group and repeated on its feature rows: mmd2, mmd2_p_value, mmd_gamma, mmd_n_ref,
    mmd_n_group, note), plus n_ref / n_group (rows in each group).
    """
    assert_single_source(df)
    features = list(features)
    present = list(pd.unique(df[group_col].dropna()))
    if ref_group not in present:
        raise ValueError(f"reference group {ref_group!r} not in {group_col!r}")
    compare = [g for g in (compare_groups if compare_groups is not None else sorted(present, key=str))
               if g != ref_group]
    unknown = [g for g in compare if g not in present]
    if unknown:
        raise ValueError(f"groups not in {group_col!r}: {unknown}")
    eta_all = {f: eta_squared(df, f, group_col) for f in features}
    ref_df = df[df[group_col] == ref_group]
    rows: list[dict[str, Any]] = []
    for g in compare:
        new_df = df[df[group_col] == g]
        pair = pd.concat([ref_df, new_df])
        mmd = mmd2_rbf(ref_df[features].to_numpy(dtype=float), new_df[features].to_numpy(dtype=float),
                       max_n=max_n, n_perm=n_perm, seed=seed)
        for f in features:
            rows.append({
                "ref_group": ref_group, "compared_group": g, "feature": f,
                "eta2": eta_squared(pair, f, group_col), "eta2_all_groups": eta_all[f],
                "psi": psi(ref_df[f], new_df[f]), "psi_mode": psi_mode(ref_df[f], new_df[f]),
                "mmd2": mmd.mmd2, "mmd2_p_value": mmd.p_value, "mmd_gamma": mmd.gamma,
                "mmd_n_ref": mmd.n_x, "mmd_n_group": mmd.n_y, "note": mmd.note,
                "n_ref": len(ref_df), "n_group": len(new_df),
            })
    return pd.DataFrame(rows)


# ------------------------------------------------------------------- CIC-PQC_OAV contrasts
KEM_AT_RSA: tuple[str, ...] = ("X25519", "mlkem768", "mlkem1024")
AUTH_AT_KEM: tuple[str, ...] = ("rsa", "mldsa65", "mldsa87")
BLOCK_KEMS: tuple[str, ...] = ("mlkem768", "mlkem1024")
BLOCK_AUTHS: tuple[str, ...] = ("mldsa65", "mldsa87", "rsa")
POOLED_REF: tuple[str, str] = ("X25519", "ecdsa_p256")
PQC_DESIGN_CELLS: tuple[tuple[str, str], ...] = (
    ("X25519", "ecdsa_p256"), ("X25519", "ecdsa_p384"), ("X25519", "rsa"), ("X25519", "rsa3072"),
    ("mlkem768", "mldsa65"), ("mlkem768", "mldsa87"), ("mlkem768", "rsa"),
    ("mlkem1024", "mldsa65"), ("mlkem1024", "mldsa87"), ("mlkem1024", "rsa"),
)
EFFECT_COLUMNS = ["eta2", "eta2_all_groups", "partial_eta2", "psi", "mmd2", "mmd2_p_value"]
ID_COLUMNS = ["contrast", "contrast_kind", "factor", "fixed", "ref_group", "compared_group", "term",
              "feature", "psi_mode", "cell_sizes", "n_ref", "n_group", "mmd_n_ref", "mmd_n_group",
              "mmd_gamma", "note", "source", "features_version"]


def _fmt_sizes(sizes: pd.Series) -> str:
    return ";".join(f"{k}={int(v)}" for k, v in sizes.items())


def _pairwise(sub: pd.DataFrame, col: str, groups: Sequence[str], features: Sequence[str],
              **kw: Any) -> pd.DataFrame:
    """drift_table for every unordered pair of `groups` (each pair once, earlier group = reference)."""
    parts = [drift_table(sub, col, ref, features, compare_groups=list(groups[i + 1:]), **kw)
             for i, ref in enumerate(groups[:-1])]
    return pd.concat(parts, ignore_index=True)


def _label(frame: pd.DataFrame, sizes: pd.Series, **cols: str) -> pd.DataFrame:
    out = frame.copy()
    for key, value in cols.items():
        out[key] = value
    out["cell_sizes"] = _fmt_sizes(sizes)
    return out


def _two_way_rows(block: pd.DataFrame, features: Sequence[str]) -> pd.DataFrame:
    sizes = block.groupby(["kem_scenario", "auth_scenario"]).size()
    sizes.index = [f"{k}+{a}" for k, a in sizes.index]
    rows = []
    for f in features:
        res = two_way_effects(block, f, "kem_scenario", "auth_scenario")
        for term, value in res.effects.items():
            rows.append({"feature": f, "term": term, "note": res.reason or res.design,
                         ("partial_eta2" if res.effect_kind == "partial_eta2" else "eta2"): value})
    return _label(pd.DataFrame(rows), sizes, contrast="two-way factorial on the crossed block",
                  contrast_kind="two_way_crossed", factor="kem_scenario x auth_scenario",
                  fixed=f"kem in {list(BLOCK_KEMS)}; auth in {list(BLOCK_AUTHS)}")


def pqc_contrast_table(normal: pd.DataFrame, features: Sequence[str] = PQC_DRIFT_FEATURES,
                       n_perm: int = 200, max_n: int = 2000, seed: int = 0) -> pd.DataFrame:
    """The fixed CIC-PQC_OAV contrasts on NORMAL rows only; each reported separately.

    a) kem at fixed auth=rsa (X25519, mlkem768, mlkem1024), all pairs
    b) auth at fixed kem (rsa, mldsa65, mldsa87), all pairs, for mlkem768 and for mlkem1024
    c) two-way effects on the crossed block {mlkem768, mlkem1024} x {mldsa65, mldsa87, rsa}
    d) X25519+ecdsa_p256 vs every other cell, labelled 'pooled, confounded' (kem and auth differ
       together, so a pooled difference is never reported as a kem effect or an auth effect)
    Every row carries the contrast name and the cell sizes. Effect-size columns come first.
    """
    assert_single_source(normal)
    if not (normal["label_raw"] == "Normal").all():
        raise ValueError("pqc_contrast_table expects Normal rows only")
    missing = [c for c in PQC_DESIGN_CELLS
               if not ((normal["kem_scenario"] == c[0]) & (normal["auth_scenario"] == c[1])).any()]
    if missing:
        raise ValueError(f"design cells missing from the data: {missing}")
    kw = {"n_perm": n_perm, "max_n": max_n, "seed": seed}
    parts: list[pd.DataFrame] = []

    sub = normal[normal["auth_scenario"] == "rsa"]
    sub = sub[sub["kem_scenario"].isin(KEM_AT_RSA)]
    parts.append(_label(_pairwise(sub, "kem_scenario", KEM_AT_RSA, features, **kw),
                        sub.groupby("kem_scenario").size(), contrast="kem comparison at fixed auth=rsa",
                        contrast_kind="kem_at_fixed_auth", factor="kem_scenario", fixed="auth_scenario=rsa"))
    for kem in BLOCK_KEMS:
        sub = normal[(normal["kem_scenario"] == kem) & normal["auth_scenario"].isin(AUTH_AT_KEM)]
        parts.append(_label(_pairwise(sub, "auth_scenario", AUTH_AT_KEM, features, **kw),
                            sub.groupby("auth_scenario").size(), contrast=f"auth comparison at fixed kem={kem}",
                            contrast_kind="auth_at_fixed_kem", factor="auth_scenario",
                            fixed=f"kem_scenario={kem}"))
    block = normal[normal["kem_scenario"].isin(BLOCK_KEMS) & normal["auth_scenario"].isin(BLOCK_AUTHS)]
    parts.append(_two_way_rows(block, features))

    cells = normal.assign(cell=normal["kem_scenario"] + "+" + normal["auth_scenario"])
    ref_cell = "+".join(POOLED_REF)
    others = [f"{k}+{a}" for k, a in PQC_DESIGN_CELLS if f"{k}+{a}" != ref_cell]
    parts.append(_label(drift_table(cells, "cell", ref_cell, features, compare_groups=others, **kw),
                        cells.groupby("cell").size(),
                        contrast=f"pooled, confounded: {ref_cell} vs each other cell",
                        contrast_kind="pooled_confounded", factor="kem+auth (confounded)", fixed=""))
    out = pd.concat(parts, ignore_index=True)
    out["source"] = normal["source"].iloc[0]
    out["features_version"] = FEATURES_VERSION
    ordered = EFFECT_COLUMNS + ID_COLUMNS
    return out.reindex(columns=ordered + [c for c in out.columns if c not in ordered])


# =========================================================================================
# Profile-invariance and two-way analyses for the lab flows (H1 / H3 / H4)
# =========================================================================================
N_NOISE = 200          # label permutations used for the noise floors
NOISE_QUANTILE = 95.0


def eta2_from_codes(y: np.ndarray, codes: np.ndarray, k: int) -> float:
    """One-way eta squared from integer group codes (0..k-1); NaN if y is exactly constant."""
    if y.size == 0 or np.ptp(y) == 0.0:
        return float("nan")
    grand = y.mean()
    counts = np.bincount(codes, minlength=k)
    sums = np.bincount(codes, weights=y, minlength=k)
    means = np.divide(sums, counts, out=np.zeros(k), where=counts > 0)
    return float((counts * (means - grand) ** 2).sum() / ((y - grand) ** 2).sum())


def eta2_noise_floor(y: np.ndarray, codes: np.ndarray, k: int, n_perm: int = N_NOISE, seed: int = 0,
                     q: float = NOISE_QUANTILE) -> float:
    """The q-th percentile of eta squared when the group labels are randomly permuted (what chance gives)."""
    rng = np.random.default_rng(seed)
    values = [eta2_from_codes(y, rng.permutation(codes), k) for _ in range(n_perm)]
    return float(np.nanpercentile(values, q)) if not np.all(np.isnan(values)) else float("nan")


def max_psi_vs_reference(values: np.ndarray, codes: np.ndarray, ref: int, k: int) -> float:
    """Largest PSI of any non-reference group against the reference group (NaN if none can be computed)."""
    ref_vals = values[codes == ref]
    found = []
    for g in range(k):
        if g != ref:
            try:
                found.append(psi(ref_vals, values[codes == g]))
            except ValueError:           # a group with no finite values
                continue
    return max(found) if found else float("nan")


def psi_noise_floor(values: np.ndarray, codes: np.ndarray, ref: int, k: int, n_perm: int = N_NOISE, seed: int = 0,
                    q: float = NOISE_QUANTILE) -> float:
    """The q-th percentile of the maximum-over-groups PSI under randomly permuted group labels."""
    rng = np.random.default_rng(seed)
    stats = [max_psi_vs_reference(values, rng.permutation(codes), ref, k) for _ in range(n_perm)]
    return float(np.nanpercentile(stats, q)) if not np.all(np.isnan(stats)) else float("nan")


def invariance_table(df: pd.DataFrame, group_col: str, ref_group: Any, features: Sequence[str],
                     n_noise: int = N_NOISE, max_n: int = 2000, seed: int = 0) -> pd.DataFrame:
    """drift_table (psi, eta2, MMD vs the reference group) plus per-feature permutation noise floors.

    Adds noise95_eta2 (eta squared that random labels exceed 5% of the time) and noise95_max_psi (same for the
    largest PSI over groups). MMD p-values are not computed (effect sizes only). One flow per row; NaN in a
    feature is dropped for that feature's statistics.
    """
    assert_single_source(df)
    table = drift_table(df, group_col, ref_group, features, n_perm=0, max_n=max_n, seed=seed)
    cat = pd.Categorical(df[group_col])
    codes, k = np.asarray(cat.codes), len(cat.categories)
    ref = list(cat.categories).index(ref_group)
    rows = []
    for f in features:
        y = df[f].to_numpy(dtype=float)
        keep = np.isfinite(y)
        rows.append({"feature": f,
                     "noise95_eta2": eta2_noise_floor(y[keep], codes[keep], k, n_noise, seed),
                     "noise95_max_psi": psi_noise_floor(y[keep], codes[keep], ref, k, n_noise, seed)})
    return table.merge(pd.DataFrame(rows), on="feature", how="left")


def summarise_invariance(table: pd.DataFrame) -> pd.DataFrame:
    """One row per feature: eta2 across all groups, the largest PSI, their noise floors and whether each exceeds it.

    A feature is 'not invariant' if its eta squared or its largest PSI exceeds what randomly permuted group labels
    give 95% of the time at the same sample size. Effect sizes are reported alongside; this is a yardstick for
    them, not a significance claim.
    """
    g = table.groupby("feature", sort=False).agg(
        eta2_all_groups=("eta2_all_groups", "first"), noise95_eta2=("noise95_eta2", "first"),
        max_psi=("psi", "max"), noise95_max_psi=("noise95_max_psi", "first"),
        max_mmd2=("mmd2", "max")).reset_index()
    g["eta2_above_noise"] = g["eta2_all_groups"] > g["noise95_eta2"]
    g["psi_above_noise"] = g["max_psi"] > g["noise95_max_psi"]
    g["not_invariant"] = g["eta2_above_noise"] | g["psi_above_noise"]
    return g


def two_way_table(df: pd.DataFrame, features: Sequence[str], factor_a: str = "kem",
                  factor_b: str = "auth") -> pd.DataFrame:
    """Partial eta squared of factor_a, factor_b and their interaction for each feature, plus a determinism flag.

    `deterministic` is True when the feature has zero spread inside every (factor_a, factor_b) cell, in which
    case its partial eta squared is trivially 1 for any factor that changes it (there is no residual).
    """
    assert_single_source(df)
    rows = []
    for f in features:
        res = two_way_effects(df, f, factor_a, factor_b)
        within = df.groupby([factor_a, factor_b])[f].std(ddof=0).fillna(0.0)
        deterministic = bool((within == 0.0).all())
        for term, value in res.effects.items():
            rows.append({"feature": f, "term": term, "partial_eta2": value if res.design == "two_way" else float("nan"),
                         "eta2_one_way": value if res.design != "two_way" else float("nan"),
                         "deterministic": deterministic, "design": res.design, "note": res.reason,
                         "max_within_cell_std": float(within.max())})
    return pd.DataFrame(rows)
