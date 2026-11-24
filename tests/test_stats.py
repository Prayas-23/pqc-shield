import numpy as np
import pandas as pd
import pytest
from scipy.stats import norm

from pqdl import stats as st


def test_conformal_fpr_distribution_known_values():
    mean, sd, p = st.conformal_fpr_distribution(100)            # rank 96 -> Beta(5, 96)
    assert mean == pytest.approx(5 / 101)
    assert sd == pytest.approx(np.sqrt(5 * 96 / (101 ** 2 * 102)))
    assert 0.8 < p < 1.0
    assert st.conformal_fpr_distribution(10) == (0.0, 0.0, 1.0)  # vacuous at n = 10
    m30, _, _ = st.conformal_fpr_distribution(30)               # rank 30 -> Beta(1, 30)
    assert m30 == pytest.approx(1 / 31)


def test_conformal_beta_matches_simulation():
    rng = np.random.default_rng(0)
    n, fprs = 50, []
    for _ in range(4000):
        tau = np.sort(rng.normal(size=n))[st.conformal_rank(n) - 1]
        fprs.append(float(norm.sf(tau)))
    mean, sd, _ = st.conformal_fpr_distribution(n)
    assert np.mean(fprs) == pytest.approx(mean, abs=0.004) and np.std(fprs) == pytest.approx(sd, abs=0.005)


def test_average_ranks_ties_and_direction():
    t = pd.DataFrame({"a": [1.0, 1.0, 5.0], "b": [2.0, 2.0, 5.0], "c": [3.0, 0.0, 1.0]})
    r = st.average_ranks(t)
    assert r["a"] == pytest.approx((1 + 2 + 2.5) / 3) and r["b"] == pytest.approx((2 + 3 + 2.5) / 3)
    assert r["c"] == pytest.approx((3 + 1 + 1) / 3)


def test_friedman_detects_consistent_ordering_and_handles_degenerate():
    rng = np.random.default_rng(1)
    base = rng.normal(size=(17, 1))
    t = pd.DataFrame({"x": base[:, 0], "y": base[:, 0] + 1, "z": base[:, 0] + 2})
    chi, p = st.friedman(t)
    assert p < 1e-5 and chi > 20
    assert np.isnan(st.friedman(pd.DataFrame(np.zeros((5, 3)), columns=list("abc")))[0])
    with pytest.raises(ValueError):
        st.friedman(t[["x", "y"]])


def test_nemenyi_cd_matches_demsar_table():
    # Demsar (2006): q_0.05 for k = 8 is 3.031 ; CD = q * sqrt(k(k+1)/(6N))
    assert st.nemenyi_cd(8, 17) == pytest.approx(3.031 * np.sqrt(72 / (6 * 17)), rel=0.01)
    assert st.nemenyi_cd(3, 10) == pytest.approx(2.343 * np.sqrt(12 / 60), rel=0.01)


def test_nemenyi_pairs():
    r = pd.Series({"a": 1.0, "b": 2.0, "c": 6.0})
    p = st.nemenyi_pairs(r, cd=2.5)
    assert len(p) == 3
    assert p.set_index(["a", "b"]).loc[("a", "c"), "significant"] and not p.set_index(["a", "b"]).loc[("a", "b"), "significant"]


def test_paired_median_diff_ci_is_seeded_and_brackets():
    a, b = np.arange(17) * 0.1 + 1.0, np.arange(17) * 0.1
    med, lo, hi = st.paired_median_diff_ci(a, b, 2000, seed=3)
    assert med == pytest.approx(1.0) and lo <= med <= hi and hi - lo < 1e-9 + 0.0
    assert st.paired_median_diff_ci(a, b, 500, seed=3) == st.paired_median_diff_ci(a, b, 500, seed=3)
    noisy = np.random.default_rng(0).normal(size=17)
    m, lo, hi = st.paired_median_diff_ci(noisy, np.zeros(17), 2000, seed=1)
    assert lo < m < hi


def test_mcnemar_exact_known_values():
    a = np.array([True] * 10 + [False] * 5)
    b = np.array([False] * 10 + [False] * 5)
    only_a, only_b, p = st.mcnemar_exact(a, b)
    assert (only_a, only_b) == (10, 0) and p == pytest.approx(2 * 0.5 ** 10)
    assert st.mcnemar_exact(a, a) == (0, 0, 1.0)
    _, _, p2 = st.mcnemar_exact(np.array([1, 0, 1, 0], bool), np.array([0, 1, 0, 1], bool))
    assert p2 == 1.0                                              # 2 vs 2 discordant
    with pytest.raises(ValueError):
        st.mcnemar_exact(np.ones(3, bool), np.ones(4, bool))


def test_status_rules():
    assert st.status_from_share(0.9, 0.75, 0.25) == "PASS"
    assert st.status_from_share(0.5, 0.75, 0.25) == "PARTIAL"
    assert st.status_from_share(0.1, 0.75, 0.25) == "FAIL"
    assert st.status_from_share(float("nan"), 0.75, 0.25) == "FAIL"
    assert st.combine_status(["PASS", "PASS"]) == "PASS" and st.combine_status(["FAIL", "FAIL"]) == "FAIL"
    assert st.combine_status(["PASS", "FAIL"]) == "PARTIAL"


def test_calibration_error_ranking_prefers_hitting_target_over_conservative():
    t = pd.DataFrame({"conservative": [0.0, 0.0, 0.0], "on_target": [0.05, 0.06, 0.04], "over": [0.5, 0.4, 0.3]})
    assert st.average_ranks(t)["conservative"] == 1.0                        # raw FPR ranking favours FPR = 0
    cal = st.calibration_error_table(t)
    assert cal.loc[0, "conservative"] == pytest.approx(0.05) and cal.loc[0, "on_target"] == pytest.approx(0.0)
    r = st.average_ranks(cal)
    assert r["on_target"] == 1.0 and r["conservative"] == 2.0 and r["over"] == 3.0
