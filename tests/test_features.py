from pathlib import Path

import pytest

from pqdl import features as f

ROOT = Path(__file__).resolve().parents[1]


def test_no_duplicates_and_disjoint() -> None:
    for feats, excluded in ((f.PQC_HANDSHAKE_FEATURES, f.PQC_EXCLUDED), (f.IDS_FLOW_FEATURES, f.IDS_EXCLUDED)):
        assert len(feats) == len(set(feats))
        assert not set(feats) & set(excluded)


def test_counts() -> None:
    assert len(f.PQC_HANDSHAKE_FEATURES) == 32
    assert len(f.IDS_FLOW_FEATURES) == 77


def test_drift_features_are_the_eight_non_one_hot_ones() -> None:
    assert len(f.PQC_DRIFT_FEATURES) == 8 == len(set(f.PQC_DRIFT_FEATURES))
    assert set(f.PQC_DRIFT_FEATURES) <= set(f.PQC_HANDSHAKE_FEATURES)
    one_hot_prefixes = ("e1_alg_suite_", "e3_sig_alg_", "e8_", "e9_", "e1b_", "e2b_", "e3_cert_parsed")
    assert not [n for n in f.PQC_DRIFT_FEATURES if n.startswith(one_hot_prefixes)]


def test_no_wildcards_or_whitespace_padding() -> None:
    for name in (*f.PQC_HANDSHAKE_FEATURES, *f.IDS_FLOW_FEATURES, *f.PQC_EXCLUDED, *f.IDS_EXCLUDED):
        assert "*" not in name and name == name.strip()


def test_every_exclusion_has_a_reason() -> None:
    assert all(r.strip() for r in (*f.PQC_EXCLUDED.values(), *f.IDS_EXCLUDED.values()))


@pytest.mark.realdata
def test_lists_cover_every_loader_column() -> None:
    from pqdl.loaders import load_cic_ids2017, load_pqc_oav

    pqc, _ = load_pqc_oav()
    ids, _ = load_cic_ids2017()
    assert set(pqc.columns) == set(f.PQC_HANDSHAKE_FEATURES) | set(f.PQC_EXCLUDED)
    assert set(ids.columns) == set(f.IDS_FLOW_FEATURES) | set(f.IDS_EXCLUDED)


@pytest.mark.realdata
def test_drift_features_are_numeric_and_vary_on_normal_rows() -> None:
    from pqdl.loaders import load_pqc_oav

    pqc, _ = load_pqc_oav()
    normal = pqc[pqc["label_raw"] == "Normal"]
    for name in f.PQC_DRIFT_FEATURES:
        assert normal[name].dtype != bool and normal[name].nunique() > 1
        assert normal[name].notna().all()


def test_lab_views_are_disjoint_and_sized() -> None:
    views = [f.LAB_HS_FEATURES, f.LAB_APP_FEATURES, f.LAB_FLOW_FEATURES, tuple(f.LAB_EXCLUDED)]
    assert [len(v) for v in views[:3]] == [6, 32, 11]
    names = [n for v in views for n in v]
    assert len(names) == len(set(names))                      # no column in two lists
    assert all(n.startswith("hs_") for n in f.LAB_HS_FEATURES) and all(n.startswith("app_") for n in f.LAB_APP_FEATURES)
    assert all(n.startswith("flow_") for n in f.LAB_FLOW_FEATURES)


def test_lab_lists_cover_every_flows_column(tmp_path: Path) -> None:
    """Every column of lab_flows.csv (parser output + the 12 columns scripts/pcaps_to_flows.py adds) is in exactly one list."""
    from test_pcap_connections import synthetic_two_connections

    from pqdl.pcap import extract_connections

    parser_columns = set(extract_connections(synthetic_two_connections(tmp_path))[0])
    script_columns = {"source", "kem", "auth", "chain", "workload", "label", "pcap_file", "conn_index",
                      "intended_sessions", "tcpdump_dropped", "capture_offload_ok", "max_tcp_payload"}
    covered = set(f.LAB_HS_FEATURES) | set(f.LAB_APP_FEATURES) | set(f.LAB_FLOW_FEATURES) | set(f.LAB_EXCLUDED)
    assert parser_columns | script_columns == covered
