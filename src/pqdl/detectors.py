"""Intrusion detectors for the lab flows (source "pq_lab") and the maths around them.

Three detectors behind one interface: RandomForest (supervised), an autoencoder (sklearn MLPRegressor trained on
benign flows only, score = reconstruction MSE on standardised features) and IsolationForest (benign only). Every
detector returns a score where HIGHER = more attack-like. The operating point is fixed in advance: threshold = 95th
percentile of the scores of benign VALIDATION flows of the training domain; a flow is flagged when score > threshold.
Nothing is ever tuned on the test block.

Labels: benign = benign_web + benign_api; attack = handshake_flood + slow_send. These are SCRIPTED attack-like
workloads on a local lab network, not real attacks.

Feature views are explicit lists (V_FLOW, V_APP). hs_* features and everything in LAB_EXCLUDED are never allowed
into a detector: `assert_clean_features` enforces it.
"""

from __future__ import annotations

import warnings
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

import numpy as np
import pandas as pd
from scipy.stats import rankdata
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.exceptions import ConvergenceWarning
from sklearn.neural_network import MLPRegressor
from sklearn.preprocessing import StandardScaler

from pqdl.features import LAB_APP_FEATURES, LAB_EXCLUDED, LAB_FLOW_FEATURES, LAB_HS_FEATURES
from pqdl.loaders import assert_single_source

V_FLOW: tuple[str, ...] = LAB_FLOW_FEATURES     # what an off-the-shelf flow detector sees
V_APP: tuple[str, ...] = LAB_APP_FEATURES       # handshake removed; needs TLS parsing
VIEWS: dict[str, tuple[str, ...]] = {"V_FLOW": V_FLOW, "V_APP": V_APP}

BENIGN_WORKLOADS: tuple[str, ...] = ("benign_web", "benign_api")
ATTACK_WORKLOADS: tuple[str, ...] = ("handshake_flood", "slow_send")
DETECTORS: tuple[str, ...] = ("rf", "ae", "iforest")
TRAIN_FRAC, VAL_FRAC = 0.4, 0.2                  # time-blocked: first 40% train, next 20% validation, last 40% test
DESIGN_FPR = 0.05
THRESHOLD_Q = 1.0 - DESIGN_FPR
METRICS: tuple[str, ...] = ("fpr", "tpr_all", "tpr_handshake_flood", "tpr_slow_send", "auroc", "fa_per_10k", "fpr_ratio")

Scorer = Callable[[np.ndarray], np.ndarray]


# --------------------------------------------------------------------------- leakage guard and labels
def assert_clean_features(cols: Sequence[str]) -> None:
    """Raise unless every column is in V_FLOW or V_APP and none is an hs_* or LAB_EXCLUDED column."""
    bad = [c for c in cols if c.startswith("hs_") or c in LAB_EXCLUDED or c in LAB_HS_FEATURES]
    if bad:
        raise ValueError(f"forbidden detector features (hs_* or LAB_EXCLUDED): {bad}")
    unknown = [c for c in cols if c not in V_FLOW and c not in V_APP]
    if unknown:
        raise ValueError(f"features outside the V_FLOW / V_APP views: {unknown}")


def add_labels(df: pd.DataFrame) -> pd.DataFrame:
    """Add boolean `attack` and string `attack_type` ("" for benign) from the workload; check the `label` column agrees."""
    assert_single_source(df)
    out = df.copy()
    known = set(BENIGN_WORKLOADS) | set(ATTACK_WORKLOADS)
    if not set(out["workload"]) <= known:
        raise ValueError(f"unknown workloads: {sorted(set(out['workload']) - known)}")
    out["attack"] = out["workload"].isin(ATTACK_WORKLOADS)
    out["attack_type"] = np.where(out["attack"], out["workload"], "")
    if "label" in out.columns and not (out["label"] == np.where(out["attack"], "attack", "benign")).all():
        raise ValueError("`label` column disagrees with the workload-based labelling")
    out["profile"] = out["kem"] + "|" + out["auth"] + "|" + out["chain"]
    return out


# --------------------------------------------------------------------------- time-blocked split
def block_sizes(n: int, train: float = TRAIN_FRAC, val: float = VAL_FRAC) -> tuple[int, int, int]:
    """(n_train, n_val, n_test): floors of 40% and 20% of n; the test block takes the remainder."""
    n_tr, n_va = int(np.floor(train * n + 1e-9)), int(np.floor(val * n + 1e-9))
    return n_tr, n_va, n - n_tr - n_va


def time_block_split(df: pd.DataFrame, train: float = TRAIN_FRAC, val: float = VAL_FRAC) -> pd.DataFrame:
    """Add `block` in {train, val, test}: inside every pcap (one profile x workload x replicate), flows are put in
    capture order (conn_index) and cut into consecutive blocks. Blocks never interleave in time."""
    assert_single_source(df)
    if (df.groupby("pcap_file")["workload"].nunique() > 1).any():
        raise ValueError("a pcap holds more than one workload")
    parts = []
    for _, g in df.groupby("pcap_file", sort=True):
        g = g.sort_values("conn_index")
        if g["conn_index"].duplicated().any():
            raise ValueError("duplicate conn_index inside a pcap")
        n_tr, n_va, n_te = block_sizes(len(g), train, val)
        g = g.copy()
        g["block"] = ["train"] * n_tr + ["val"] * n_va + ["test"] * n_te
        parts.append(g)
    return pd.concat(parts, ignore_index=True)


# --------------------------------------------------------------------------- detectors
@dataclass
class FitLog:
    """Counts MLPRegressor fits that stopped at max_iter instead of converging (reported, not hidden)."""
    ae_fits: int = 0
    ae_not_converged: int = 0
    notes: list[str] = field(default_factory=list)


FIT_LOG = FitLog()
AE_HIDDEN, AE_MAX_ITER = (16, 4, 16), 500


def design_matrix(df: pd.DataFrame, cols: Sequence[str]) -> np.ndarray:
    """Feature matrix as float. NaN in the size_k columns means 'packet k does not exist' and is filled with 0."""
    assert_clean_features(cols)
    return np.nan_to_num(df[list(cols)].to_numpy(dtype=float), nan=0.0)


def fit_detector(name: str, X: np.ndarray, attack: np.ndarray, seed: int) -> Scorer:
    """Fit one detector; return a scorer (higher = more attack-like). ae/iforest use the benign rows only."""
    if name == "rf":
        if attack.all() or not attack.any():
            raise ValueError("RandomForest needs both classes in the training block")
        rf = RandomForestClassifier(n_estimators=100, random_state=seed, n_jobs=1).fit(X, attack.astype(int))
        return lambda Z: rf.predict_proba(Z)[:, 1]
    benign = X[~attack]
    if len(benign) == 0:
        raise ValueError("no benign rows to train on")
    scaler = StandardScaler().fit(benign)
    Xb = scaler.transform(benign)
    if name == "iforest":
        iso = IsolationForest(n_estimators=100, random_state=seed).fit(Xb)
        return lambda Z: -iso.score_samples(scaler.transform(Z))
    if name == "ae":
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", ConvergenceWarning)
            ae = MLPRegressor(hidden_layer_sizes=AE_HIDDEN, max_iter=AE_MAX_ITER, random_state=seed).fit(Xb, Xb)
        FIT_LOG.ae_fits += 1
        FIT_LOG.ae_not_converged += int(ae.n_iter_ >= AE_MAX_ITER)

        def score(Z: np.ndarray) -> np.ndarray:
            Zs = scaler.transform(Z)
            return ((ae.predict(Zs) - Zs) ** 2).mean(axis=1)
        return score
    raise ValueError(f"unknown detector {name!r}")


def threshold_at(benign_val_scores: np.ndarray, q: float = THRESHOLD_Q) -> float:
    """Operating point: the q-quantile (linear interpolation) of benign VALIDATION scores. Flag when score > threshold."""
    if len(benign_val_scores) == 0:
        raise ValueError("no benign validation scores")
    return float(np.quantile(benign_val_scores, q))


@dataclass
class Domain:
    """One trained detector family for one training domain: a scorer and a threshold per model seed."""
    scorers: list[Scorer]
    thresholds: np.ndarray

    def score(self, X: np.ndarray) -> np.ndarray:
        """(n_seeds, n) scores."""
        return np.stack([s(X) for s in self.scorers])


def fit_domain(name: str, cols: Sequence[str], train: pd.DataFrame, val: pd.DataFrame, seeds: Sequence[int]) -> Domain:
    """Train on the `train` block, threshold on the benign rows of the `val` block, once per model seed."""
    if not (train["block"] == "train").all() or not (val["block"] == "val").all():
        raise ValueError("fit_domain needs train rows from the train block and val rows from the val block")
    assert_single_source(train)
    assert_single_source(val)
    Xtr, ytr = design_matrix(train, cols), train["attack"].to_numpy()
    Xva = design_matrix(val[~val["attack"]], cols)
    scorers = [fit_detector(name, Xtr, ytr, s) for s in seeds]
    thr = np.array([threshold_at(sc(Xva)) for sc in scorers])
    return Domain(scorers, thr)


# --------------------------------------------------------------------------- metrics
def _auroc_rows(scores: np.ndarray, n_benign: int) -> np.ndarray:
    """AUROC per row of `scores` (rows x [benign..., attack...]); ties count 1/2 (average ranks)."""
    n_att = scores.shape[1] - n_benign
    if n_benign == 0 or n_att == 0:
        return np.full(scores.shape[0], np.nan)
    ranks = rankdata(scores, axis=1)
    return (ranks[:, n_benign:].sum(axis=1) - n_att * (n_att + 1) / 2) / (n_att * n_benign)


def _derived(fpr: np.ndarray) -> dict[str, np.ndarray]:
    return {"fa_per_10k": fpr * 1e4, "fpr_ratio": fpr / DESIGN_FPR}


def metrics_point(scores: np.ndarray, attack_type: np.ndarray, thr: np.ndarray) -> dict[str, np.ndarray]:
    """Per-seed metrics on one test block. scores (S, n); attack_type (n,) with "" for benign; thr (S,)."""
    flag = scores > thr[:, None]
    benign = attack_type == ""
    nan = np.full(scores.shape[0], np.nan)
    fpr = flag[:, benign].mean(axis=1) if benign.any() else nan
    out = {"fpr": fpr, "tpr_all": flag[:, ~benign].mean(axis=1) if (~benign).any() else nan}
    for t in ("handshake_flood", "slow_send"):
        m = attack_type == t
        out[f"tpr_{t}"] = flag[:, m].mean(axis=1) if m.any() else nan
    order = np.concatenate([np.where(benign)[0], np.where(~benign)[0]])
    out["auroc"] = _auroc_rows(scores[:, order], int(benign.sum()))
    return {**out, **_derived(fpr)}


def bootstrap_metrics(scores: np.ndarray, attack_type: np.ndarray, thr: np.ndarray, n_boot: int = 1000,
                      seed: int = 0) -> dict[str, np.ndarray]:
    """Bootstrap distribution (n_boot,) of each metric, averaged over the model seeds. Flows are resampled with
    replacement within strata (benign, each attack type) using the SAME indices for every model seed, so the
    interval reflects test-flow sampling only. The generator depends only on `seed` and the strata sizes."""
    rng = np.random.default_rng(seed)
    strata = {t: np.where(attack_type == t)[0] for t in ["", *sorted(set(attack_type) - {""})]}
    draws = {t: pos[rng.integers(0, len(pos), size=(n_boot, len(pos)))] for t, pos in strata.items() if len(pos)}
    n_seeds = scores.shape[0]
    acc: dict[str, np.ndarray] = {m: np.zeros(n_boot) for m in METRICS}
    benign_idx = draws.get("")
    att_types = [t for t in draws if t != ""]
    for s in range(n_seeds):
        flag = scores[s] > thr[s]
        fpr = flag[benign_idx].mean(axis=1) if benign_idx is not None else np.full(n_boot, np.nan)
        att_flags = {t: flag[draws[t]] for t in att_types}
        for t in ("handshake_flood", "slow_send"):
            acc[f"tpr_{t}"] += att_flags[t].mean(axis=1) if t in att_flags else np.nan
        acc["tpr_all"] += (np.concatenate([att_flags[t] for t in att_types], axis=1).mean(axis=1)
                           if att_types else np.nan)
        acc["fpr"] += fpr
        if benign_idx is not None and att_types:
            both = np.concatenate([scores[s][benign_idx]] + [scores[s][draws[t]] for t in att_types], axis=1)
            acc["auroc"] += _auroc_rows(both, benign_idx.shape[1])
        else:
            acc["auroc"] += np.nan
    out = {m: v / n_seeds for m, v in acc.items() if m in ("fpr", "tpr_all", "tpr_handshake_flood", "tpr_slow_send", "auroc")}
    return {**out, **_derived(out["fpr"])}


@dataclass(frozen=True)
class MetricSummary:
    value: float        # mean over model seeds
    seed_sd: float      # sd over model seeds (ddof=1; NaN for one seed)
    ci_lo: float        # 95% bootstrap interval of the seed-mean
    ci_hi: float


def summarise(scores: np.ndarray, attack_type: np.ndarray, thr: np.ndarray, n_boot: int, seed: int) -> dict[str, MetricSummary]:
    point = metrics_point(scores, attack_type, thr)
    boot = bootstrap_metrics(scores, attack_type, thr, n_boot, seed)
    out = {}
    for m in METRICS:
        p, b = point[m], boot[m]
        lo, hi = np.nanquantile(b, [0.025, 0.975]) if np.isfinite(b).any() else (np.nan, np.nan)
        out[m] = MetricSummary(float(np.mean(p)), float(np.std(p, ddof=1)) if len(p) > 1 else float("nan"),
                               float(lo), float(hi))
    return out


def binomial_band(n: int, p: float = DESIGN_FPR, level: float = 0.99) -> tuple[float, float]:
    """Central `level` interval of the false-positive RATE if n benign flows were independent at rate p."""
    from scipy.stats import binom
    a = (1 - level) / 2
    return float(binom.ppf(a, n, p) / n), float(binom.ppf(1 - a, n, p) / n)
