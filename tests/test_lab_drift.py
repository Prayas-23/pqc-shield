"""lab_drift pipeline on SYNTHETIC lab flows with planted effects (no real data)."""

from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from pqdl.features import LAB_APP_FEATURES, LAB_FLOW_FEATURES, LAB_HS_FEATURES
from pqdl.lab_drift import (
    EFFECT_COLUMNS,
    REF_PROFILE,
    add_profile,
    fill_absent_sizes,
    require_valid_capture,
    run_lab_drift,
)
from pqdl.loaders import MixedSourceError
from pqdl.synth import SYNTHETIC_SOURCE, synthetic_lab_flows


@pytest.fixture(scope="module")
def result():
    flows = synthetic_lab_flows(n_per_cell=12, seed=3)
    return flows, run_lab_drift(flows, n_noise=40, max_n=300, seed=0)


def test_synthetic_flows_cover_every_lab_feature() -> None:
    flows = synthetic_lab_flows(n_per_cell=3)
    assert set(flows["source"]) == {SYNTHETIC_SOURCE}
    for name in (*LAB_HS_FEATURES, *LAB_APP_FEATURES, *LAB_FLOW_FEATURES):
        assert name in flows.columns
    assert REF_PROFILE in set(add_profile(flows)["profile"])


def test_results_table_layout(result) -> None:
    _, res = result
    table = res.results
    assert list(table.columns)[: len(EFFECT_COLUMNS)] == EFFECT_COLUMNS          # effect sizes first
    assert set(table["test"]) == {"H3_app_invariance", "H1_handshake_two_way", "H4_flow_features"}
    assert set(table["source"]) == {SYNTHETIC_SOURCE}
    assert set(table["workload"]) == {"benign_web", "handshake_flood"}


def test_h3_flags_the_planted_app_violation_only(result) -> None:
    _, res = result
    h3 = res.results[(res.results["test"] == "H3_app_invariance") & (res.results["workload"] == "benign_web")]
    eta = h3.groupby("feature")["eta2_all_groups"].first()
    assert eta["app_s2c_bytes"] > 0.5                 # planted: depends on the KEM
    assert eta["app_c2s_bytes"] < 0.3                 # identically distributed for every profile
    # the notes list app_s2c_bytes as NOT invariant for benign_web, and app_c2s_bytes among the invariant ones
    section = res.notes.split("### benign_web")[1].split("###")[0]
    flagged, invariant = section.split("Invariant within the noise floor")
    assert "app_s2c_bytes" in flagged
    assert "app_c2s_bytes" in invariant


def test_h1_deterministic_and_informative_rows(result) -> None:
    _, res = result
    h1 = res.results[res.results["test"] == "H1_handshake_two_way"]
    web = h1[h1["workload"] == "benign_web"].set_index(["feature", "term"])
    assert bool(web.loc[("hs_s2c_bytes", "kem")]["deterministic"])
    assert web.loc[("hs_s2c_bytes", "kem"), "partial_eta2"] == 1.0
    assert web.loc[("hs_s2c_bytes", "auth"), "partial_eta2"] == 1.0
    assert web.loc[("hs_s2c_bytes", "kem:auth"), "partial_eta2"] == 0.0           # additive
    assert not bool(web.loc[("hs_duration", "auth")]["deterministic"])
    assert web.loc[("hs_duration", "auth"), "partial_eta2"] > web.loc[("hs_duration", "kem"), "partial_eta2"]
    informative = res.notes.split("Non-deterministic (informative)")[1]
    assert "hs_duration" in informative


def test_h4_flow_totals_inherit_the_handshake_and_app_violation(result) -> None:
    _, res = result
    h4 = res.results[(res.results["test"] == "H4_flow_features") & (res.results["workload"] == "benign_web")]
    eta = h4.groupby("feature")["eta2_all_groups"].first()
    assert eta["flow_s2c_bytes"] > 0.5 > eta["flow_c2s_pkts"]


def test_notes_carry_the_required_caveats(result) -> None:
    _, res = result
    for phrase in ("Single lab topology", "Local network", "Session tickets are disabled", "Pinned groups",
                   "Benign workloads are scripted"):
        assert phrase in res.notes


def test_fill_absent_sizes_only_touches_size_columns() -> None:
    df = pd.DataFrame({"app_c2s_size_1": [100.0, np.nan], "app_pkt_len_mean": [5.0, np.nan]})
    out = fill_absent_sizes(df)
    assert out["app_c2s_size_1"].tolist() == [100.0, 0.0]
    assert np.isnan(out["app_pkt_len_mean"].iloc[1])


def test_invalid_captures_and_mixed_sources_are_refused() -> None:
    flows = synthetic_lab_flows(n_per_cell=3)
    bad = flows.copy()
    bad.loc[0, "capture_offload_ok"] = False
    with pytest.raises(ValueError, match="capture_offload_ok"):
        require_valid_capture(bad)
    mixed = flows.copy()
    mixed.loc[0, "source"] = "pq_lab"
    with pytest.raises(MixedSourceError):
        run_lab_drift(mixed, n_noise=5)


# ---------------------------------------------------------------- data-derived caveats and the ECDSA note
from pqdl.lab_drift import cipher_suite_caveat, timing_caveat, timing_flags  # noqa: E402


def _timing_fixture():
    # 5 SYNTHETIC profiles; every flow of a profile has the same flow_duration, so the profile median is that value.
    medians = [0.0010, 0.0011, 0.0012, 0.0013, 0.0050]
    rows, man = [], []
    for i, m in enumerate(medians):
        name = f"SYNTHETIC_{i}.pcap"
        rows += [{"kem": "k", "auth": f"a{i}", "chain": "leaf_int", "workload": "benign_web", "pcap_file": name,
                  "flow_duration": m, "source": SYNTHETIC_SOURCE}] * 3
        man.append({"pcap_file": name, "start_utc": f"2026-01-01T00:0{i}:00Z"})
    return pd.DataFrame(rows), pd.DataFrame(man)


def test_timing_flags_hand_computed() -> None:
    flows, manifest = _timing_fixture()
    t = timing_flags(flows, manifest)
    # M = median(medians) = 0.0012; |dev| = [0.0002, 0.0001, 0, 0.0001, 0.0038]; MAD = median(|dev|) = 0.0001;
    # flag |dev| > 3 * MAD = 0.0003  ->  only the 0.0050 profile
    assert t["flag"].sum() == 1 and t[t["flag"]]["auth"].iloc[0] == "a4"
    assert t[t["flag"]]["dev_in_MADs"].iloc[0] == pytest.approx(38.0)
    assert list(t["start_utc"]) == sorted(t["start_utc"])          # reported in run order
    assert "a4" in timing_caveat(flows, manifest) and "flagged for timing" in timing_caveat(flows, manifest)
    assert "not checked" in timing_caveat(flows, None)


def test_timing_caveat_when_nothing_is_flagged() -> None:
    flows, manifest = _timing_fixture()
    flows.loc[flows["auth"] == "a4", "flow_duration"] = 0.0014
    assert "No benign_web pcap is a timing outlier" in timing_caveat(flows, manifest)


def test_cipher_suite_caveat() -> None:
    one = cipher_suite_caveat(pd.DataFrame({"sh_cipher_suite": [4866, 4866]}))
    assert "One cipher suite" in one and "0x1302" in one
    two = cipher_suite_caveat(pd.DataFrame({"sh_cipher_suite": [4866, 4865]}))
    assert "Cipher suites" in two and "0x1301" in two and "0x1302" in two


def test_ecdsa_byte_spread_is_reported_as_non_deterministic_with_the_reason() -> None:
    flows = synthetic_lab_flows(n_per_cell=12, seed=5)
    jitter = np.random.default_rng(1).integers(0, 3, size=int((flows["auth"] == "ecdsa_p256").sum()))
    flows.loc[flows["auth"] == "ecdsa_p256", "hs_s2c_bytes"] += jitter          # a few bytes of ECDSA-like spread
    res = run_lab_drift(flows, n_noise=10, max_n=200, seed=0)
    h1 = res.h1[(res.h1["workload"] == "benign_web") & (res.h1["feature"] == "hs_s2c_bytes")]
    assert not h1["deterministic"].any()                                       # spread in some cells => not deterministic
    assert (h1["max_within_cell_std"] > 0).all() and (h1["max_within_cell_std"] < 2).all()
    assert h1.set_index("term").loc["kem", "partial_eta2"] > 0.99              # still ~1: spread is tiny vs between-cell gaps
    assert "hs_s2c_bytes (max within-cell std" in res.notes and "variable-length DER" in res.notes
