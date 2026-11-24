"""Tests for pqdl.detectors on a SYNTHETIC fixture (no lab data): split, threshold rule, metrics, leakage guard."""

import numpy as np
import pandas as pd
import pytest

from pqdl import detectors as dt
from pqdl.loaders import MixedSourceError

N_PER = {"benign_web": 50, "benign_api": 50, "handshake_flood": 40, "slow_send": 10}


def synthetic_frame(seed: int = 0, attack_shift: float = 6.0, source: str = "SYNTHETIC") -> pd.DataFrame:
    """SYNTHETIC lab-like flows: 2 profiles x 4 workloads, one pcap each. Benign ~ N(0,1), attack ~ N(shift,1)."""
    rng = np.random.default_rng(seed)
    rows = []
    for kem in ("X25519", "mlkem768"):
        for wl, n in N_PER.items():
            shift = attack_shift if wl in dt.ATTACK_WORKLOADS else 0.0
            vals = rng.normal(shift, 1.0, size=(n, len(dt.V_FLOW)))
            for i in range(n):
                row = {"source": source, "kem": kem, "auth": "a", "chain": "c", "workload": wl,
                       "label": "attack" if wl in dt.ATTACK_WORKLOADS else "benign",
                       "pcap_file": f"{kem}_{wl}.pcap", "conn_index": i}
                row.update(dict(zip(dt.V_FLOW, vals[i])))
                rows.append(row)
    df = pd.DataFrame(rows)
    for c in dt.V_APP:                                   # the app view needs its columns, some with NaN
        if c not in df.columns:
            df[c] = rng.normal(size=len(df))
    df.loc[df.index % 7 == 0, "app_c2s_size_9"] = np.nan
    return df


def prepared(seed: int = 0) -> pd.DataFrame:
    return dt.time_block_split(dt.add_labels(synthetic_frame(seed)))


# ---- split
def test_block_sizes():
    assert dt.block_sizes(300) == (120, 60, 120)
    assert dt.block_sizes(200) == (80, 40, 80)
    assert dt.block_sizes(50) == (20, 10, 20)
    assert sum(dt.block_sizes(37)) == 37


def test_split_is_time_blocked_per_pcap_and_does_not_interleave():
    df = prepared()
    for _, g in df.groupby("pcap_file"):
        g = g.sort_values("conn_index")
        assert g["conn_index"].is_monotonic_increasing
        order = {"train": 0, "val": 1, "test": 2}
        codes = g["block"].map(order).to_numpy()
        assert (np.diff(codes) >= 0).all()                         # train, then val, then test; never mixed
        n_tr, n_va, n_te = dt.block_sizes(len(g))
        assert (codes == 0).sum() == n_tr and (codes == 1).sum() == n_va and (codes == 2).sum() == n_te


def test_split_is_independent_of_row_order():
    df = dt.add_labels(synthetic_frame())
    a = dt.time_block_split(df).set_index(["pcap_file", "conn_index"])["block"]
    b = dt.time_block_split(df.sample(frac=1.0, random_state=3)).set_index(["pcap_file", "conn_index"])["block"]
    assert a.sort_index().equals(b.sort_index())


def test_split_rejects_mixed_source_and_mixed_workload_pcap():
    df = dt.add_labels(synthetic_frame())
    bad = df.copy()
    bad.loc[0, "source"] = "other"
    with pytest.raises(MixedSourceError):
        dt.time_block_split(bad)
    bad = df.copy()
    bad.loc[0, "workload"] = "slow_send"
    with pytest.raises(ValueError):
        dt.time_block_split(bad)


def test_labels_follow_workload_and_check_label_column():
    df = dt.add_labels(synthetic_frame())
    assert df.loc[df.workload == "slow_send", "attack"].all() and not df.loc[df.workload == "benign_api", "attack"].any()
    assert set(df.loc[df.attack, "attack_type"]) == {"handshake_flood", "slow_send"}
    bad = synthetic_frame()
    bad.loc[bad.workload == "benign_web", "label"] = "attack"
    with pytest.raises(ValueError):
        dt.add_labels(bad)


# ---- leakage guard
def test_feature_guard_accepts_views_and_rejects_hs_and_excluded():
    dt.assert_clean_features(dt.V_FLOW)
    dt.assert_clean_features(dt.V_APP)
    for bad in ("hs_s2c_bytes", "hs_duration", "flow_first12_c2s_size_1", "flow_first12_s2c_size_12", "kem", "workload", "start_time", "sh_group_id"):
        with pytest.raises(ValueError):
            dt.assert_clean_features([*dt.V_FLOW, bad])
    with pytest.raises(ValueError):
        dt.assert_clean_features(["some_new_column"])
    assert not set(dt.V_FLOW) & set(dt.LAB_EXCLUDED) and not set(dt.V_APP) & set(dt.LAB_EXCLUDED)
    assert not any(c.startswith("hs_") for c in (*dt.V_FLOW, *dt.V_APP))


def test_design_matrix_fills_missing_packet_sizes_with_zero():
    df = synthetic_frame()
    X = dt.design_matrix(df, dt.V_APP)
    assert not np.isnan(X).any()
    assert (X[df["app_c2s_size_9"].isna().to_numpy(), list(dt.V_APP).index("app_c2s_size_9")] == 0).all()


# ---- threshold rule
def test_threshold_is_95th_percentile_and_flag_is_strictly_greater():
    s = np.arange(1.0, 101.0)
    thr = dt.threshold_at(s)
    assert thr == pytest.approx(np.quantile(s, 0.95)) == pytest.approx(95.05)
    assert ((s > thr).mean()) == pytest.approx(0.05)
    with pytest.raises(ValueError):
        dt.threshold_at(np.array([]))


def test_fit_domain_threshold_uses_only_benign_validation_scores():
    df = prepared()
    tr, va = df[df.block == "train"], df[df.block == "val"]
    dom = dt.fit_domain("iforest", dt.V_FLOW, tr, va, seeds=(1, 2))
    Xb = dt.design_matrix(va[~va.attack], dt.V_FLOW)
    for sc, thr in zip(dom.scorers, dom.thresholds):
        assert thr == pytest.approx(np.quantile(sc(Xb), 0.95))
    with pytest.raises(ValueError):                      # test rows must not be accepted as validation
        dt.fit_domain("iforest", dt.V_FLOW, tr, df[df.block == "test"], seeds=(1,))


# ---- metrics
def test_point_metrics_known_values():
    scores = np.array([[0.1, 0.9, 0.2, 0.8, 0.7, 0.3]])
    at = np.array(["", "", "", "handshake_flood", "handshake_flood", "slow_send"])
    m = dt.metrics_point(scores, at, np.array([0.5]))
    assert m["fpr"][0] == pytest.approx(1 / 3)                      # only the 0.9 benign flow is flagged
    assert m["tpr_all"][0] == pytest.approx(2 / 3)
    assert m["tpr_handshake_flood"][0] == 1.0 and m["tpr_slow_send"][0] == 0.0
    assert m["fa_per_10k"][0] == pytest.approx(1e4 / 3) and m["fpr_ratio"][0] == pytest.approx((1 / 3) / 0.05)
    # AUROC by brute force over pairs
    ben, att = [0.1, 0.9, 0.2], [0.8, 0.7, 0.3]
    brute = np.mean([(a > b) + 0.5 * (a == b) for a in att for b in ben])
    assert m["auroc"][0] == pytest.approx(brute)


def test_auroc_extremes_and_ties():
    at = np.array(["", "", "slow_send", "slow_send"])
    assert dt.metrics_point(np.array([[0, 0, 1, 1.0]]), at, np.array([0.5]))["auroc"][0] == 1.0
    assert dt.metrics_point(np.array([[1, 1, 0, 0.0]]), at, np.array([0.5]))["auroc"][0] == 0.0
    assert dt.metrics_point(np.array([[1, 1, 1, 1.0]]), at, np.array([0.5]))["auroc"][0] == 0.5


def test_bootstrap_is_seeded_and_brackets_the_point_estimate():
    rng = np.random.default_rng(0)
    at = np.array([""] * 400 + ["handshake_flood"] * 150 + ["slow_send"] * 50)
    scores = np.concatenate([rng.normal(0, 1, 400), rng.normal(1.5, 1, 200)])[None, :].repeat(2, axis=0)
    scores[1] += rng.normal(0, 0.01, scores.shape[1])
    thr = np.array([1.645, 1.645])
    a = dt.summarise(scores, at, thr, 300, seed=5)
    b = dt.summarise(scores, at, thr, 300, seed=5)
    assert a == b
    for m, s in a.items():
        assert s.ci_lo <= s.value <= s.ci_hi, m
    assert a["fpr"].ci_hi - a["fpr"].ci_lo < 0.1
    assert np.isfinite(a["fpr"].seed_sd)


def test_bootstrap_degenerate_class_gives_nan_not_crash():
    at = np.array([""] * 10)
    s = dt.summarise(np.arange(10.0)[None, :], at, np.array([4.5]), 50, seed=1)
    assert np.isnan(s["tpr_all"].value) and np.isnan(s["auroc"].value) and s["fpr"].value == 0.5


def test_binomial_band_contains_design_rate():
    lo, hi = dt.binomial_band(240)
    assert lo < 0.05 < hi


# ---- detectors end to end on the synthetic fixture
@pytest.mark.parametrize("name", dt.DETECTORS)
def test_detectors_separate_a_large_synthetic_shift_and_are_seeded(name):
    df = prepared()
    tr, va, te = (df[df.block == b] for b in ("train", "val", "test"))
    dom = dt.fit_domain(name, dt.V_FLOW, tr, va, seeds=(1, 2))
    again = dt.fit_domain(name, dt.V_FLOW, tr, va, seeds=(1, 2))
    X = dt.design_matrix(te, dt.V_FLOW)
    assert np.allclose(dom.score(X), again.score(X))
    m = dt.metrics_point(dom.score(X), te["attack_type"].to_numpy(), dom.thresholds)
    assert m["auroc"].min() > 0.95 and m["tpr_all"].min() > 0.8


def test_fit_detector_errors():
    X = np.zeros((4, 2))
    with pytest.raises(ValueError):
        dt.fit_detector("rf", X, np.zeros(4, dtype=bool), 0)
    with pytest.raises(ValueError):
        dt.fit_detector("ae", X, np.ones(4, dtype=bool), 0)
    with pytest.raises(ValueError):
        dt.fit_detector("nope", X, np.array([0, 1, 0, 1], dtype=bool), 0)
