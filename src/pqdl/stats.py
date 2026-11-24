"""Statistics for the detector / CANON comparison: conformal coverage spread, Friedman + Nemenyi, paired bootstrap of
median differences, exact McNemar, and the rule that turns a measured share into PASS / PARTIAL / FAIL.

All thresholds used for claim statuses are passed in by the caller and written down in scripts/stats_eval.py BEFORE
the results exist. Random functions take a seed.
"""

from __future__ import annotations

import numpy as np
import pandas as pd
from scipy import stats

from pqdl.canon import ALPHA, conformal_rank


# --------------------------------------------------------------------------- conformal coverage spread
def conformal_fpr_distribution(n: int, alpha: float = ALPHA, slack: float = 0.02) -> tuple[float, float, float]:
    """Theory for split conformal with n exchangeable calibration scores: the true false-positive rate of the
    threshold is Beta(n + 1 - l, l) with l = ceil((n + 1)(1 - alpha)). Returns (mean, sd, P(FPR <= alpha + slack)).
    A vacuous threshold (l > n, nothing is ever flagged) gives (0, 0, 1)."""
    rank = conformal_rank(n, alpha)
    if rank > n:
        return 0.0, 0.0, 1.0
    a, b = n + 1 - rank, rank
    d = stats.beta(a, b)
    return float(d.mean()), float(d.std()), float(d.cdf(alpha + slack))


# --------------------------------------------------------------------------- Friedman + Nemenyi
def average_ranks(table: pd.DataFrame) -> pd.Series:
    """Mean rank of each column over the rows (blocks); rank 1 = smallest value (lower is better), ties averaged."""
    ranks = table.rank(axis=1, method="average", ascending=True)
    return ranks.mean(axis=0)


def friedman(table: pd.DataFrame) -> tuple[float, float]:
    """(chi-square, p) of the Friedman test over the columns of `table` (blocks x treatments); NaN if degenerate."""
    if table.shape[1] < 3 or table.shape[0] < 2:
        raise ValueError("Friedman needs >= 3 treatments and >= 2 blocks")
    if (table.nunique(axis=1) == 1).all():
        return float("nan"), float("nan")
    r = stats.friedmanchisquare(*[table[c].to_numpy() for c in table.columns])
    return float(r.statistic), float(r.pvalue)


def nemenyi_cd(k: int, n_blocks: int, alpha: float = 0.05) -> float:
    """Nemenyi critical difference of average ranks: q_alpha * sqrt(k (k + 1) / (6 n)), q = studentized range / sqrt(2)."""
    q = float(stats.studentized_range.ppf(1 - alpha, k, np.inf)) / np.sqrt(2.0)
    return q * float(np.sqrt(k * (k + 1) / (6.0 * n_blocks)))


def nemenyi_pairs(ranks: pd.Series, cd: float) -> pd.DataFrame:
    """All pairs with their rank difference and whether it exceeds the critical difference."""
    rows = []
    names = list(ranks.index)
    for i, a in enumerate(names):
        for b in names[i + 1:]:
            d = float(ranks[a] - ranks[b])
            rows.append({"a": a, "b": b, "rank_diff": d, "significant": abs(d) > cd})
    return pd.DataFrame(rows)


def paired_median_diff_ci(a: np.ndarray, b: np.ndarray, n_boot: int = 10_000, seed: int = 0,
                          level: float = 0.95) -> tuple[float, float, float]:
    """(median(a - b), lo, hi): percentile bootstrap over the paired blocks (profiles)."""
    d = np.asarray(a, float) - np.asarray(b, float)
    rng = np.random.default_rng(seed)
    idx = rng.integers(0, len(d), size=(n_boot, len(d)))
    meds = np.median(d[idx], axis=1)
    lo, hi = np.quantile(meds, [(1 - level) / 2, 1 - (1 - level) / 2])
    return float(np.median(d)), float(lo), float(hi)


# --------------------------------------------------------------------------- McNemar
def mcnemar_exact(flag_a: np.ndarray, flag_b: np.ndarray) -> tuple[int, int, float]:
    """Exact two-sided McNemar on paired boolean decisions: (n_only_a, n_only_b, p). p = 1 when there are no
    discordant pairs."""
    fa, fb = np.asarray(flag_a, bool), np.asarray(flag_b, bool)
    if fa.shape != fb.shape:
        raise ValueError("paired decisions must have the same length")
    only_a, only_b = int((fa & ~fb).sum()), int((~fa & fb).sum())
    n = only_a + only_b
    p = 1.0 if n == 0 else float(stats.binomtest(min(only_a, only_b), n, 0.5, alternative="two-sided").pvalue)
    return only_a, only_b, p


# --------------------------------------------------------------------------- claim status
def status_from_share(share: float, pass_at: float, partial_at: float) -> str:
    """PASS if share >= pass_at, PARTIAL if share >= partial_at, else FAIL (NaN counts as FAIL)."""
    if not np.isfinite(share):
        return "FAIL"
    return "PASS" if share >= pass_at else "PARTIAL" if share >= partial_at else "FAIL"


def combine_status(statuses: list[str]) -> str:
    """PASS if all PASS, FAIL if all FAIL, otherwise PARTIAL."""
    if all(s == "PASS" for s in statuses):
        return "PASS"
    if all(s == "FAIL" for s in statuses):
        return "FAIL"
    return "PARTIAL"
