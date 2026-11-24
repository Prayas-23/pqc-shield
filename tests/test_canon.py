"""Tests for pqdl.canon on SYNTHETIC fixtures (no lab data)."""

import numpy as np
import pandas as pd
import pytest

from pqdl import canon
from pqdl.features import CONTEXT_FEATURES

CLS = canon.CLASSICAL_CONTEXT
PQ = "mlkem768|mldsa65|leaf_int"


# ---- CANON-A: model-based differences
def test_classical_delta_is_zero_and_known_pq_delta():
    d0 = canon.handshake_delta(CLS)
    assert (d0.s2c_bytes, d0.c2s_bytes, d0.s2c_pkts, d0.c2s_pkts) == (0, 0, 0, 0)
    d = canon.handshake_delta(PQ)
    # B_S diff = (1088-32) + 2*((1952-64)+(3309-64)) + (3309-64) = 14567 ; B_C diff = 1184-32 = 1152
    assert d.s2c_bytes == 14567 and d.c2s_bytes == 1152
    assert d.s2c_pkts == 10                                    # ceil(B_S / 1448) difference (LAB_MSS, not 1460)
    assert d.c2s_pkts in (0, 1)


def test_delta_uses_lab_mss_not_default():
    from pqdl.handshake import n_packets, server_flight_bytes
    p, r = canon.context_profile(PQ), canon.context_profile(CLS)
    by_default = n_packets(server_flight_bytes(p)) - n_packets(server_flight_bytes(r))
    assert canon.handshake_delta(PQ).s2c_pkts == n_packets(server_flight_bytes(p), 1448) - n_packets(server_flight_bytes(r), 1448)
    assert isinstance(by_default, int)


def test_context_profile_maps_chain_and_names():
    assert canon.context_profile("X25519MLKEM768|mldsa87|leaf").n_certs == 1
    assert canon.context_profile("mlkem768|ecdsa_p256|leaf_int").kem == "MLKEM768"
    with pytest.raises(KeyError):
        canon.context_profile("rsa|x|leaf")


def flows(n=4) -> pd.DataFrame:
    return pd.DataFrame({"flow_c2s_bytes": [3000.0] * n, "flow_s2c_bytes": [20000.0] * n,
                         "flow_c2s_pkts": [10.0] * n, "flow_s2c_pkts": [30.0] * n, "flow_pkt_len_mean": [999.0] * n,
                         "flow_pkt_len_std": [1.0] * n, "flow_pkt_len_max": [1448.0] * n, "flow_iat_mean": [0.1] * n})


def test_correct_a_bytes_only_subtracts_model_difference_and_floors_at_zero():
    f = flows(2)
    f.loc[1, "flow_s2c_bytes"] = 100.0                              # smaller than the delta: floored
    out = canon.correct_a(f, [PQ, PQ], ["bytes"])
    d = canon.handshake_delta(PQ)
    assert out.loc[0, "flow_s2c_bytes"] == 20000 - d.s2c_bytes and out.loc[0, "flow_c2s_bytes"] == 3000 - d.c2s_bytes
    assert out.loc[1, "flow_s2c_bytes"] == 0.0
    assert (out["flow_s2c_pkts"] == f["flow_s2c_pkts"]).all() and (out["flow_pkt_len_mean"] == 999.0).all()
    assert (f["flow_s2c_bytes"].iloc[0] == 20000)                    # input not modified


def test_correct_a_classical_context_is_identity():
    f = flows(3)
    out = canon.correct_a(f, [CLS] * 3, ["bytes", "pkts", "pktlen"])
    assert out["flow_s2c_bytes"].equals(f["flow_s2c_bytes"]) and out["flow_s2c_pkts"].equals(f["flow_s2c_pkts"])


def test_correct_a_pkts_and_pktlen_mean_recomputed_from_corrected_totals():
    f = flows(1)
    out = canon.correct_a(f, [PQ], ["bytes", "pkts", "pktlen"])
    d = canon.handshake_delta(PQ)
    b = max(3000 - d.c2s_bytes, 0) + max(20000 - d.s2c_bytes, 0)
    p = max(10 - d.c2s_pkts, 0) + max(30 - d.s2c_pkts, 0)
    assert out.loc[0, "flow_s2c_pkts"] == 30 - d.s2c_pkts
    assert out.loc[0, "flow_pkt_len_mean"] == pytest.approx(b / p)
    assert out.loc[0, "flow_pkt_len_std"] == 1.0 and out.loc[0, "flow_pkt_len_max"] == 1448.0


def test_correct_a_rejects_time_group_and_bad_inputs():
    with pytest.raises(ValueError):
        canon.correct_a(flows(1), [PQ], ["time"])
    with pytest.raises(ValueError):
        canon.correct_a(flows(2), [PQ], ["bytes"])
    with pytest.raises(ValueError):
        canon.group_features(["nope"])
    assert canon.group_features(["bytes"]) == ["flow_c2s_bytes", "flow_s2c_bytes"]


# ---- conformal rule
def test_conformal_rank_and_threshold():
    assert canon.conformal_rank(10) == 11 and canon.conformal_rank(30) == 30
    assert canon.conformal_rank(100) == 96 and canon.conformal_rank(19) == 19
    assert np.isinf(canon.conformal_threshold(np.arange(10.0)))              # rank 11 > n = 10: vacuous
    assert canon.conformal_threshold(np.arange(1.0, 101.0)) == 96.0
    assert canon.conformal_threshold(np.arange(1.0, 31.0)) == 30.0           # k=30: the maximum
    assert canon.conformal_threshold(np.array([5.0, 1.0, 3.0] + [0.0] * 17)) == 5.0   # n=20 -> rank 20 = max


def test_conformal_coverage_on_exchangeable_synthetic_scores():
    rng = np.random.default_rng(0)
    taus = [canon.conformal_threshold(rng.normal(size=100)) for _ in range(200)]
    test = rng.normal(size=20000)
    fprs = [(test > t).mean() for t in taus]
    assert np.mean(fprs) == pytest.approx(1 - 96 / 101, abs=0.01)          # expected miscoverage 1 - rank/(n+1)


# ---- CANON-B pieces
def test_location_shift_and_residualise():
    rng = np.random.default_rng(1)
    ref = pd.DataFrame({"a": rng.normal(10, 1, 500), "b": rng.normal(0, 1, 500)})
    cal = pd.DataFrame({"a": rng.normal(110, 1, 100), "b": rng.normal(0, 1, 100)})
    g = canon.location_shift(cal, ref, ["a"])
    assert g[0] == pytest.approx(100, abs=0.5)
    test = pd.DataFrame({"a": [110.0, 111.0], "b": [1.0, 2.0]})
    out = canon.residualise(test, ["c1", "c2"], {"c1": g, "c2": np.array([0.0])}, ["a"])
    assert out.loc[0, "a"] == pytest.approx(110 - g[0]) and out.loc[1, "a"] == 111.0
    assert (out["b"] == test["b"]).all()
    with pytest.raises(KeyError):
        canon.residualise(test, ["c1", "zzz"], {"c1": g}, ["a"])


def test_calibration_draw_is_nested_seeded_benign_only():
    df = pd.DataFrame({"x": np.arange(120.0), "attack": False})
    a, b = canon.calibration_draw(df, 10, 3), canon.calibration_draw(df, 30, 3)
    assert list(a.index) == list(b.index[:10]) and list(canon.calibration_draw(df, 10, 3).index) == list(a.index)
    assert list(canon.calibration_draw(df, 10, 4).index) != list(a.index)
    with pytest.raises(ValueError):
        canon.calibration_draw(df, 121, 3)
    with pytest.raises(ValueError):
        canon.calibration_draw(df.assign(attack=True), 5, 3)


# ---- context estimator (SYNTHETIC context features)
def context_frame(seed=0, n=40, block="train") -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    rows = []
    for kem, base in (("X25519", 300), ("mlkem768", 1400)):
        for auth, add in (("ecdsa_p256", 0), ("mldsa65", 700)):
            for _ in range(n):
                row = {"kem": kem, "auth": auth, "chain": "leaf_int", "block": block}
                for i, c in enumerate(CONTEXT_FEATURES):
                    row[c] = base + add + i + int(rng.integers(0, 3))
                rows.append(row)
    return pd.DataFrame(rows)


def test_context_estimator_recovers_synthetic_contexts_and_confusion_sums():
    tr, te = context_frame(0), context_frame(1, block="test")
    model = canon.fit_context_estimator(tr)
    pred = canon.predict_context(model, te)
    true = (te["kem"] + "|" + te["auth"] + "|" + te["chain"]).to_numpy()
    assert (pred == true).all()
    cm = canon.confusion(true, pred, sorted(set(true)))
    assert cm.to_numpy().sum() == len(te) and (np.diag(cm.to_numpy()) == 40).all()
    with pytest.raises(ValueError):
        canon.fit_context_estimator(te)                                  # test block rejected


def test_context_features_never_accepted_by_detectors():
    from pqdl import detectors as dt
    with pytest.raises(ValueError):
        dt.assert_clean_features([*dt.V_FLOW, CONTEXT_FEATURES[0]])
