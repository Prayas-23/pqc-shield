"""Tests for pqdl.loaders. Fixtures are tiny files written here; the only test that touches
the real data is marked `realdata` (run with `pytest -m realdata`)."""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from pqdl import loaders
from pqdl.loaders import (
    MixedSourceError,
    assert_single_source,
    drop_all_nan_rows,
    duplicate_masks,
    load_cic_ids2017,
    load_pqc_oav,
    normalise_label,
    parse_scenario_kem_auth,
    replace_infs,
    row_keys,
    strip_column_names,
)

# Like the real header, the repeated column has the identical raw name (leading space) both times,
# so pandas renames the second copy to " Fwd Header Length.1".
IDS_HEADER = "Flow ID, Source Port, Flow Bytes/s, Flow Packets/s, Fwd Header Length, Fwd Header Length, Label\n"

MONDAY = (
    IDS_HEADER
    + "a,1,10.0,1.0,20,20,BENIGN\n"
    + "b,2,Infinity,-Infinity,20,20,BENIGN\n"
    + "c,3,5.0,2.0,30,30,BENIGN\n"
    + "c,3,5.0,2.0,30,30,BENIGN\n"  # within-file duplicate
    + ",,,,,,\n"  # completely empty row
)
# cp1252 file: 0x96 is the en dash that shows up as a replacement character in the real data.
TUESDAY = (
    IDS_HEADER
    + "a,1,10.0,1.0,20,20,BENIGN\n"  # cross-file duplicate of Monday's first row
    + "d,4,7.0,3.0,40,40,Web Attack – Brute Force\n"  # en dash -> byte 0x96 in cp1252
    + "e,5,8.0,4.0,50,50, BENIGN \n"
    + "f,6,9.0,5.0,60,60, Web Attack – XSS \n"
).encode("cp1252")


def write_ids(root: Path, monday: str | bytes = MONDAY, tuesday: str | bytes = TUESDAY) -> Path:
    folder = root / "cic_ids2017"
    folder.mkdir(parents=True)
    for name, content in (("Monday-WorkingHours.pcap_ISCX.csv", monday),
                          ("Tuesday-WorkingHours.pcap_ISCX.csv", tuesday)):
        data = content.encode("utf-8") if isinstance(content, str) else content
        (folder / name).write_bytes(data)
    return root


# ------------------------------------------------------------------ small pure functions
def test_strip_column_names() -> None:
    df = pd.DataFrame({" a ": [1], "b": [2]})
    assert list(strip_column_names(df).columns) == ["a", "b"]


def test_strip_column_names_rejects_names_that_collide() -> None:
    df = pd.DataFrame([[1, 2]], columns=["a", " a"])
    with pytest.raises(ValueError, match="duplicate column names"):
        strip_column_names(df)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Web Attack – Brute Force", "Web Attack - Brute Force"),
        ("Web Attack � XSS", "Web Attack - XSS"),
        ("Web Attack \x96 Sql Injection", "Web Attack - Sql Injection"),
        ("  BENIGN  ", "BENIGN"),
        ("DoS   Hulk", "DoS Hulk"),
        ("FTP-Patator", "FTP-Patator"),
    ],
)
def test_normalise_label(raw: str, expected: str) -> None:
    assert normalise_label(raw) == expected


def test_normalise_label_keeps_nan() -> None:
    assert pd.isna(normalise_label(np.nan))


def test_replace_infs_counts_and_replaces() -> None:
    df = pd.DataFrame({"x": [1.0, np.inf, -np.inf, 4.0], "y": [1.0, 2.0, 3.0, 4.0]})
    out, counts = replace_infs(df)
    assert counts == {"x": 2}
    assert out["x"].isna().sum() == 2
    assert not np.isinf(out["x"].to_numpy()).any()


def test_drop_all_nan_rows() -> None:
    df = pd.DataFrame({"a": [1.0, np.nan, np.nan], "b": [2.0, np.nan, 3.0]})
    out, n = drop_all_nan_rows(df)
    assert n == 1 and len(out) == 2


def test_duplicate_masks_modes() -> None:
    k1 = row_keys(pd.DataFrame({"a": [1.0, 2.0, 2.0]}))
    k2 = row_keys(pd.DataFrame({"a": [1.0, 3.0]}))
    assert [m.tolist() for m in duplicate_masks([k1, k2], "none")] == [[False] * 3, [False] * 2]
    assert [m.tolist() for m in duplicate_masks([k1, k2], "within_file")] == [[False, False, True], [False, False]]
    assert [m.tolist() for m in duplicate_masks([k1, k2], "global")] == [[False, False, True], [True, False]]
    with pytest.raises(ValueError):
        duplicate_masks([k1], "bogus")


# ----------------------------------------------------------------------- assert_single_source
def test_assert_single_source_ok_and_empty() -> None:
    assert_single_source(pd.DataFrame({"source": ["x", "x"]}))
    assert_single_source(pd.DataFrame({"source": pd.Series([], dtype="object")}))


def test_assert_single_source_rejects_mixed() -> None:
    with pytest.raises(MixedSourceError, match="mixes sources"):
        assert_single_source(pd.DataFrame({"source": ["a", "b"]}))


def test_assert_single_source_rejects_missing_or_null() -> None:
    with pytest.raises(MixedSourceError):
        assert_single_source(pd.DataFrame({"x": [1]}))
    with pytest.raises(MixedSourceError):
        assert_single_source(pd.DataFrame({"source": ["a", None]}))


# -------------------------------------------------------------------------- CIC-IDS2017
def test_ids_global_dedupe_end_to_end(tmp_path: Path) -> None:
    df, rep = load_cic_ids2017(write_ids(tmp_path), use_cache=False)
    # header cleaning
    assert "Source Port" in df.columns and " Source Port" not in df.columns
    # rows: 5 + 4 read; 1 blank; 2 duplicates (Monday 'c' repeat + cross-file 'a')
    assert rep["rows_read"] == 9
    assert rep["rows_dropped"] == {"all_nan_rows": 1, "duplicate_rows": 2}
    assert rep["rows_out"] == len(df) == 6
    assert rep["files"]["Tuesday-WorkingHours.pcap_ISCX.csv"]["encoding"] == "cp1252"
    assert_single_source(df)
    assert set(df["source"]) == {"cic_ids2017"}


def test_ids_labels_normalised_and_binary(tmp_path: Path) -> None:
    df, _ = load_cic_ids2017(write_ids(tmp_path), use_cache=False)
    assert set(df["Label"]) == {"BENIGN", "Web Attack - Brute Force", "Web Attack - XSS"}
    binary = dict(zip(df["Label"], df["label_binary"]))
    assert binary["BENIGN"] == 0 and binary["Web Attack - XSS"] == 1


def test_ids_inf_replaced_and_counted(tmp_path: Path) -> None:
    df, rep = load_cic_ids2017(write_ids(tmp_path), use_cache=False)
    assert rep["inf_replaced_with_nan"] == {"Flow Bytes/s": 1, "Flow Packets/s": 1}
    assert not np.isinf(df.select_dtypes("number").to_numpy(dtype=float)).any()
    assert rep["nan_counts"]["Flow Bytes/s"] == 1


def test_ids_provenance_columns(tmp_path: Path) -> None:
    df, _ = load_cic_ids2017(write_ids(tmp_path), use_cache=False)
    assert set(df["day"]) == {"Monday", "Tuesday"}
    assert set(df["source_file"]) == {"Monday-WorkingHours.pcap_ISCX.csv", "Tuesday-WorkingHours.pcap_ISCX.csv"}


@pytest.mark.parametrize(("mode", "expected_rows"), [("none", 8), ("within_file", 7), ("global", 6)])
def test_ids_dedupe_modes(tmp_path: Path, mode: str, expected_rows: int) -> None:
    df, rep = load_cic_ids2017(write_ids(tmp_path), dedupe=mode, use_cache=False)  # type: ignore[arg-type]
    assert len(df) == expected_rows
    assert rep["rows_dropped"]["duplicate_rows"] == 8 - expected_rows
    # global dedupe keeps the first occurrence, i.e. Monday's copy of row 'a'
    if mode == "global":
        assert df.loc[df["Flow ID"] == "a", "day"].tolist() == ["Monday"]


def test_ids_invalid_dedupe_mode(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        load_cic_ids2017(write_ids(tmp_path), dedupe="everything", use_cache=False)  # type: ignore[arg-type]


def test_ids_removed_rows_per_label_and_warning(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING, logger="pqdl.loaders"):
        _, rep = load_cic_ids2017(write_ids(tmp_path), use_cache=False)
    benign = rep["removed_by_label"]["BENIGN"]
    assert benign == {"before": 6, "removed": 2, "after": 4, "fraction_removed": pytest.approx(2 / 6, abs=1e-5)}
    assert rep["removed_by_label"]["Web Attack - XSS"]["removed"] == 0
    assert any("BENIGN" in w and "33.3%" in w for w in rep["warnings"])
    assert any("DATA QUALITY WARNING" in r.message and "BENIGN" in r.message for r in caplog.records)


def test_ids_no_warning_below_threshold(tmp_path: Path) -> None:
    _, rep = load_cic_ids2017(write_ids(tmp_path), dedupe="none", use_cache=False)
    assert rep["warnings"] == []


def test_ids_fwd_header_identical_second_column_dropped(tmp_path: Path) -> None:
    df, rep = load_cic_ids2017(write_ids(tmp_path), use_cache=False)
    info = rep["fwd_header_length"]
    assert info["second_column_dropped"] is True and info["files_identical"] == 2
    assert "Fwd Header Length" in df.columns
    assert "Fwd Header Length.1" not in df.columns and "Fwd Header Length_dup2" not in df.columns


def test_ids_fwd_header_differing_second_column_kept(tmp_path: Path) -> None:
    monday = MONDAY.replace("a,1,10.0,1.0,20,20", "a,1,10.0,1.0,20,99")
    df, rep = load_cic_ids2017(write_ids(tmp_path, monday=monday), use_cache=False)
    info = rep["fwd_header_length"]
    assert info["second_column_dropped"] is False
    assert info["differing_files"] == ["Monday-WorkingHours.pcap_ISCX.csv"]
    assert "Fwd Header Length_dup2" in df.columns


def test_ids_cache_hit_and_invalidation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = write_ids(tmp_path)
    first, _ = load_cic_ids2017(root)
    assert (root / "cache" / "cic_ids2017_global.pkl").exists()

    def boom(_path: Path) -> None:
        raise AssertionError("cache should have been used")

    monkeypatch.setattr(loaders, "read_csv_text", boom)
    second, _ = load_cic_ids2017(root)
    pd.testing.assert_frame_equal(first, second)
    with pytest.raises(AssertionError):  # different parameter -> different cache -> rebuild
        load_cic_ids2017(root, dedupe="none")


# --------------------------------------------------------------------------- CIC-PQC_OAV
ML_CSV = (
    "e2c_total_bytes,e4_entropy_h,e1_alg_suite_x25519,e1_alg_suite_mlkem768,label,split,taxonomy,ID\n"
    "100,1.0,TRUE,FALSE,0,train,ml_baseline_normal,normal_X25519_ecdsa_p256_cert_run1\n"
    "200,2.0,FALSE,TRUE,0,val,ml_baseline_normal,normal_mlkem768_mldsa65_cert_run1\n"
    "300,3.0,TRUE,FALSE,1,test,eval_test_network,net_high_jitter_classic_run1\n"
    "400,4.0,FALSE,FALSE,1,train,raf_test_correctness,raf_alg_mismatch_run1\n"
    "500,5.0,FALSE,TRUE,0,train,ml_baseline_normal,normal_mlkem768_rsa_cert_run1\n"
)
MANIFEST_ROWS = [
    "normal_X25519_ecdsa_p256_cert_run1.pcap,normal_X25519_ecdsa_p256_cert,ML,baseline_normal,Classical,Normal,1",
    "normal_mlkem768_mldsa65_cert_run1.pcap,normal_mlkem768_mldsa65_cert,ML,baseline_normal,Compliant_mlkem768,Normal,1",
    "net_high_jitter_classic_run1.pcap,net_high_jitter_classic,Network,high_jitter_classic,Classical,Anomaly,1",
    "raf_alg_mismatch_run1.pcap,raf_alg_mismatch,Threat,raf_alg_mismatch,Misconfig,Anomaly,1",
    "normal_mlkem768_rsa_cert_run1.pcap,normal_mlkem768_rsa_cert,ML,baseline_normal,Compliant_mlkem768,Normal,1",
]
MANIFEST_HEADER = "ID,scenario_id,taxonomy_class,subtype,operational_class,anomaly_label,run_idx\n"
SESSIONS = [  # (jsonl scenario_id = taxonomy\ID, raw e1_alg_suite). Row 5 deliberately disagrees.
    ("ml_baseline_normal\\normal_X25519_ecdsa_p256_cert_run1", "x25519"),
    ("ml_baseline_normal\\normal_mlkem768_mldsa65_cert_run1", "mlkem768"),
    ("eval_test_network\\net_high_jitter_classic_run1", "x25519"),
    ("raf_test_correctness\\raf_alg_mismatch_run1", "Unknown(0x11ec)"),
    ("ml_baseline_normal\\normal_mlkem768_rsa_cert_run1", "x25519"),
]


def write_pqc(root: Path, ml: str = ML_CSV, manifest_rows: list[str] | None = None) -> Path:
    folder = root / "cic_pqc_oav"
    folder.mkdir(parents=True)
    rows = MANIFEST_ROWS if manifest_rows is None else manifest_rows
    (folder / "ml_features_and_labels.csv").write_text(ml, encoding="utf-8")
    (folder / "scenario_manifest.csv").write_text(MANIFEST_HEADER + "\n".join(rows) + "\n", encoding="utf-8")
    lines = [json.dumps({"scenario_id": s, "e1_alg_suite": k}) for s, k in SESSIONS]
    (folder / "raw_sessions.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return root


def test_parse_scenario_kem_auth() -> None:
    ids = pd.Series(["normal_mlkem1024_mldsa87_cert", "normal_X25519_ecdsa_p256_cert",
                     "anomaly_kem_mismatch", "raf_alg_mismatch", np.nan], dtype="object")
    out = parse_scenario_kem_auth(ids)
    assert out["kem_scenario"].iloc[:2].tolist() == ["mlkem1024", "X25519"]
    assert out["auth_scenario"].iloc[:2].tolist() == ["mldsa87", "ecdsa_p256"]
    assert out.iloc[2:].isna().all().all()


def test_pqc_join_and_labels(tmp_path: Path) -> None:
    df, rep = load_pqc_oav(write_pqc(tmp_path), use_cache=False)
    assert len(df) == 5 and rep["rows_out"] == 5
    assert set(df["source"]) == {"cic_pqc_oav"}
    assert_single_source(df)
    assert df["label_raw"].tolist() == ["Normal", "Normal", "Anomaly", "Anomaly", "Normal"]
    assert df["label_binary"].tolist() == [0, 0, 1, 1, 0]
    assert rep["labels"]["label_binary_vs_ml_label_disagreements"] == 0
    assert rep["warnings"] == []


def test_pqc_label_disagreement_reported(tmp_path: Path) -> None:
    ml = ML_CSV.replace("100,1.0,TRUE,FALSE,0,", "100,1.0,TRUE,FALSE,1,")
    _, rep = load_pqc_oav(write_pqc(tmp_path, ml=ml), use_cache=False)
    assert rep["labels"]["label_binary_vs_ml_label_disagreements"] == 1
    assert rep["warnings"]


def test_pqc_scenario_columns_normal_rows_only(tmp_path: Path) -> None:
    df, rep = load_pqc_oav(write_pqc(tmp_path), use_cache=False)
    assert df["kem_scenario"].tolist()[:2] == ["X25519", "mlkem768"]
    assert df["kem_scenario"].iloc[4] == "mlkem768"
    assert df["auth_scenario"].tolist()[:2] == ["ecdsa_p256", "mldsa65"]
    assert df["auth_scenario"].iloc[4] == "rsa"
    assert df[["kem_scenario", "auth_scenario"]].iloc[[2, 3]].isna().all().all()
    k = rep["kem_auth"]
    assert (k["kem_scenario_nan"], k["auth_scenario_nan"]) == (2, 2)
    assert k["normal_rows_without_scenario_kem_auth"] == 0
    assert k["non_normal_rows_with_scenario_kem_auth"] == 0


def test_pqc_kem_observed_is_raw_and_separate(tmp_path: Path) -> None:
    df, _ = load_pqc_oav(write_pqc(tmp_path), use_cache=False)
    assert df["kem_observed"].tolist() == ["x25519", "mlkem768", "x25519", "Unknown(0x11ec)", "x25519"]
    assert df["kem_scenario"].iloc[2:4].isna().all()  # observed value never leaks into scenario column


def test_pqc_scenario_vs_observed_disagreements(tmp_path: Path) -> None:
    _, rep = load_pqc_oav(write_pqc(tmp_path), use_cache=False)
    cmp = rep["kem_auth"]["scenario_vs_observed_kem"]
    # 3 normal rows compared; 'X25519' vs 'x25519' agrees case-insensitively; row 5 disagrees
    assert cmp["compared_rows"] == 3
    assert cmp["disagreements"] == 1
    assert cmp["disagreement_pairs"] == {"mlkem768 -> x25519": 1}


def test_pqc_unmatched_manifest_rows_are_nan_not_guessed(tmp_path: Path) -> None:
    df, rep = load_pqc_oav(write_pqc(tmp_path, manifest_rows=MANIFEST_ROWS[:4]), use_cache=False)
    assert rep["labels"]["rows_without_manifest_match"] == 1
    last = df.iloc[4]
    assert pd.isna(last["label_raw"]) and pd.isna(last["label_binary"])
    assert pd.isna(last["kem_scenario"]) and pd.isna(last["auth_scenario"])
    assert rep["nan_counts"]["label_raw"] == 1


def test_pqc_cache_roundtrip(tmp_path: Path) -> None:
    root = write_pqc(tmp_path)
    first, rep1 = load_pqc_oav(root)
    assert (root / "cache" / "cic_pqc_oav.pkl").exists()
    second, rep2 = load_pqc_oav(root)
    pd.testing.assert_frame_equal(first, second)
    assert rep1 == rep2


# ------------------------------------------------------------------ datasets never merge
def test_guard_rejects_concatenated_datasets(tmp_path: Path) -> None:
    ids, _ = load_cic_ids2017(write_ids(tmp_path / "a"), use_cache=False)
    pqc, _ = load_pqc_oav(write_pqc(tmp_path / "b"), use_cache=False)
    with pytest.raises(MixedSourceError):
        assert_single_source(pd.concat([ids, pqc], ignore_index=True))


# ------------------------------------------------------------------------- real data
ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DOC = ROOT / "docs" / "data_schema.md"


def documented_row_counts() -> dict[str, int]:
    text = SCHEMA_DOC.read_text(encoding="utf-8")
    section = text.split("## Row counts", 1)[1].split("\n## ", 1)[0]
    return {m.group(1): int(m.group(2)) for m in re.finditer(r"\| `(data/[^`]+)` \| (\d+) \|", section)}


@pytest.mark.realdata
def test_real_row_counts_match_schema_doc() -> None:
    if not SCHEMA_DOC.exists() or not (ROOT / "data" / "cic_pqc_oav").exists():
        pytest.skip("real data or docs/data_schema.md not available")
    doc = documented_row_counts()
    assert len(doc) == 11

    pqc, pqc_rep = load_pqc_oav()
    assert_single_source(pqc)
    for name, n in pqc_rep["rows_read"].items():
        assert n == doc[f"data/cic_pqc_oav/{name}"]
    assert pqc_rep["rows_out"] == len(pqc) == pqc_rep["rows_read"]["ml_features_and_labels.csv"] - sum(
        pqc_rep["rows_dropped"].values())

    ids, ids_rep = load_cic_ids2017()
    assert_single_source(ids)
    for name, info in ids_rep["files"].items():
        assert info["rows_read"] == doc[f"data/cic_ids2017/{name}"]
    dropped = sum(ids_rep["rows_dropped"].values())
    assert ids_rep["rows_out"] == len(ids) == ids_rep["rows_read"] - dropped
    assert set(pqc["source"]) != set(ids["source"])
