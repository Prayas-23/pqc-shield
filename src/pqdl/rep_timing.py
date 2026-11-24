"""Pcap-level analysis of the replicate captures: is a timing difference a crypto effect or pcap-to-pcap noise?

Unit of analysis = one pcap (its per-feature median over connections). With k profiles and n pcaps per profile
(balanced), the maths below are: one-way random-effects variance components and ICC, the one-way ANOVA F ratio with
a permutation test that shuffles profile labels across pcaps, a within-profile bootstrap of the ICC, a range check,
Spearman correlation with run order, and Holm's multiple-comparison correction. Every random function takes a seed.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pandas as pd
from scipy import stats

TIMING_FEATURES = ("hs_duration", "flow_duration", "app_duration", "app_iat_mean", "app_iat_std", "app_iat_max")


@dataclass(frozen=True)
class Components:
    """One-way random-effects ANOVA on a (k profiles, n pcaps) array. Variances are floored at 0."""
    msb: float
    msw: float
    var_between: float      # between-profile variance component (crypto-profile effect + shared batch effect)
    var_within: float       # between-pcap variance within a profile (pcap-to-pcap noise)
    icc: float              # var_between / (var_between + var_within); NaN if both are 0
    f_ratio: float          # msb / msw; inf if msw == 0 and msb > 0, NaN if both 0


def variance_components(values: np.ndarray) -> Components:
    """Balanced one-way ANOVA estimators: sigma2_w = MSW, sigma2_b = max(0, (MSB - MSW) / n), ICC = b / (b + w)."""
    k, n = values.shape
    if k < 2 or n < 2:
        raise ValueError("need at least 2 profiles and 2 pcaps per profile")
    group_means = values.mean(axis=1)
    msb = n * float(((group_means - values.mean()) ** 2).sum()) / (k - 1)
    msw = float(((values - group_means[:, None]) ** 2).sum()) / (k * (n - 1))
    var_b = max(0.0, (msb - msw) / n)
    total = var_b + msw
    icc = var_b / total if total > 0 else float("nan")
    if msw > 0:
        f = msb / msw
    else:
        f = float("inf") if msb > 0 else float("nan")
    return Components(msb, msw, var_b, msw, icc, f)


def f_ratio_many(values: np.ndarray, labels: np.ndarray) -> np.ndarray:
    """One-way ANOVA F for each row of `labels` (a (B, N) array of integer group codes 0..k-1) on `values` (N,)."""
    values = np.asarray(values, dtype=float)
    n_total = values.size
    k = int(labels.max()) + 1
    grand = values.mean()
    ss_b = np.zeros(labels.shape[0])
    ss_w = np.zeros(labels.shape[0])
    for g in range(k):
        mask = labels == g
        cnt = mask.sum(axis=1)
        mean = (mask * values).sum(axis=1) / cnt
        ss_b += cnt * (mean - grand) ** 2
        ss_w += (mask * (values - mean[:, None]) ** 2).sum(axis=1)
    with np.errstate(divide="ignore", invalid="ignore"):
        return (ss_b / (k - 1)) / (ss_w / (n_total - k))


def permutation_f_test(values: np.ndarray, labels: np.ndarray, n_perm: int, seed: int) -> tuple[float, float]:
    """(observed F, permutation p) with profile labels shuffled across pcaps. p = (1 + #{F* >= F}) / (1 + n_perm)."""
    rng = np.random.default_rng(seed)
    obs = float(f_ratio_many(values, labels[None, :])[0])
    perms = np.stack([rng.permutation(labels) for _ in range(n_perm)])
    null = f_ratio_many(values, perms)
    if np.isnan(obs):
        return obs, float("nan")
    return obs, (1 + int(np.sum(null >= obs - 1e-12 * abs(obs)))) / (1 + n_perm)


def bootstrap_icc(values: np.ndarray, n_boot: int, seed: int, level: float = 0.95) -> tuple[float, float]:
    """Percentile CI of the ICC when pcaps are resampled with replacement within each profile."""
    rng = np.random.default_rng(seed)
    k, n = values.shape
    draws = []
    for _ in range(n_boot):
        idx = rng.integers(0, n, size=(k, n))
        icc = variance_components(np.take_along_axis(values, idx, axis=1)).icc
        if not np.isnan(icc):
            draws.append(icc)
    if not draws:
        return float("nan"), float("nan")
    lo, hi = np.quantile(draws, [(1 - level) / 2, 1 - (1 - level) / 2])
    return float(lo), float(hi)


def holm(p: np.ndarray) -> np.ndarray:
    """Holm step-down adjusted p-values (monotone, capped at 1). NaNs stay NaN and do not count as tests."""
    p = np.asarray(p, dtype=float)
    out = np.full(p.shape, np.nan)
    ok = ~np.isnan(p)
    pv = p[ok]
    order = np.argsort(pv)
    m = pv.size
    adj = np.minimum(1.0, (m - np.arange(m)) * pv[order])
    adj = np.maximum.accumulate(adj)
    res = np.empty(m)
    res[order] = adj
    out[ok] = res
    return out


def range_check(reference: float, replicates: np.ndarray) -> tuple[bool, float]:
    """(is `reference` within [min, max] of `replicates]?, distance outside the range as a fraction of the replicate median)."""
    lo, hi = float(np.min(replicates)), float(np.max(replicates))
    inside = lo <= reference <= hi
    outside = 0.0 if inside else min(abs(reference - lo), abs(reference - hi))
    med = float(np.median(replicates))
    return inside, outside / abs(med) if med != 0 else float("nan")


def spearman(x: np.ndarray, y: np.ndarray) -> tuple[float, float]:
    """(rho, two-sided p); NaN if either input is constant."""
    if np.ptp(x) == 0 or np.ptp(y) == 0:
        return float("nan"), float("nan")
    r = stats.spearmanr(x, y)
    return float(r.statistic), float(r.pvalue)


def pcap_medians(flows: pd.DataFrame, features: tuple[str, ...] = TIMING_FEATURES) -> pd.DataFrame:
    """One row per pcap (pcap_file) with the median of each feature over its connections, plus identifying columns."""
    keys = ["kem", "auth", "chain", "workload", "replicate_id", "run_order", "pcap_file"]
    return flows.groupby(keys, as_index=False, dropna=False)[list(features)].median()
