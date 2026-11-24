import numpy as np
import pandas as pd
import pytest

from pqdl import rep_timing as rt


def test_components_pure_noise_has_zero_between():
    v = np.array([[1.0, 3.0], [1.0, 3.0], [1.0, 3.0]])      # every profile has the same two pcap values
    c = rt.variance_components(v)
    assert c.msb == 0 and c.var_between == 0 and c.icc == 0
    assert c.msw == pytest.approx(2.0)


def test_components_pure_profile_effect():
    v = np.array([[1.0, 1.0, 1.0], [5.0, 5.0, 5.0]])
    c = rt.variance_components(v)
    assert c.msw == 0 and c.icc == pytest.approx(1.0) and np.isinf(c.f_ratio)


def test_components_known_numbers():
    v = np.array([[1.0, 3.0], [5.0, 7.0]])                  # group means 2, 6; grand 4; n=2, k=2
    c = rt.variance_components(v)
    assert c.msb == pytest.approx(2 * (4 + 4) / 1)          # 16
    assert c.msw == pytest.approx((2 + 2) / 2)              # SSW 4 over k(n-1)=2 df
    assert c.var_between == pytest.approx((16 - 2) / 2)     # 7
    assert c.icc == pytest.approx(7 / 9)


def test_components_needs_two_by_two():
    with pytest.raises(ValueError):
        rt.variance_components(np.ones((1, 3)))


def test_f_ratio_many_matches_scipy():
    from scipy import stats
    rng = np.random.default_rng(0)
    x = rng.normal(size=12)
    lab = np.repeat(np.arange(3), 4)
    got = rt.f_ratio_many(x, lab[None, :])[0]
    assert got == pytest.approx(stats.f_oneway(x[:4], x[4:8], x[8:]).statistic)


def test_permutation_detects_strong_effect_and_not_noise():
    lab = np.repeat(np.arange(4), 4)
    strong = lab * 10.0 + np.random.default_rng(1).normal(scale=0.1, size=16)
    _, p = rt.permutation_f_test(strong, lab, 2000, seed=3)
    assert p < 0.01
    noise = np.random.default_rng(2).normal(size=16)
    _, p0 = rt.permutation_f_test(noise, lab, 2000, seed=3)
    assert p0 > 0.05


def test_permutation_is_seeded():
    lab = np.repeat(np.arange(4), 4)
    x = np.random.default_rng(5).normal(size=16)
    assert rt.permutation_f_test(x, lab, 500, 7) == rt.permutation_f_test(x, lab, 500, 7)


def test_bootstrap_icc_bounds_and_seed():
    v = np.array([[1.0, 1.1, 0.9, 1.0], [5.0, 5.1, 4.9, 5.0], [9.0, 9.1, 8.9, 9.0]])
    lo, hi = rt.bootstrap_icc(v, 300, seed=1)
    assert 0.9 <= lo <= hi <= 1.0
    assert rt.bootstrap_icc(v, 300, seed=1) == (lo, hi)


def test_holm_known_values_and_nan():
    adj = rt.holm(np.array([0.01, 0.04, 0.03, np.nan]))
    assert adj[0] == pytest.approx(0.03) and adj[2] == pytest.approx(0.06) and adj[1] == pytest.approx(0.06)
    assert np.isnan(adj[3])


def test_range_check():
    assert rt.range_check(2.0, np.array([1.0, 3.0, 2.5])) == (True, 0.0)
    inside, dist = rt.range_check(4.0, np.array([1.0, 3.0, 2.0]))
    assert not inside and dist == pytest.approx(1.0 / 2.0)


def test_spearman_monotone_and_constant():
    rho, _ = rt.spearman(np.arange(10.0), np.arange(10.0) ** 2)
    assert rho == pytest.approx(1.0)
    assert np.isnan(rt.spearman(np.arange(5.0), np.ones(5))[0])


def test_pcap_medians_uses_pcap_as_unit():
    flows = pd.DataFrame({"kem": "k", "auth": "a", "chain": "c", "workload": "w", "replicate_id": 1, "run_order": 1,
                          "pcap_file": ["p1"] * 3 + ["p2"] * 3,
                          **{f: [1.0, 2.0, 9.0, 4.0, 5.0, 6.0] for f in rt.TIMING_FEATURES}})
    out = rt.pcap_medians(flows).sort_values("pcap_file")
    assert out["hs_duration"].tolist() == [2.0, 5.0]
