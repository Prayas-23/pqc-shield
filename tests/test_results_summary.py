"""Tests for scripts/make_results_summary.py on the SYNTHETIC API fixture (no real results)."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

import synthetic_api_fixture as fx

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "make_results_summary.py"


@pytest.fixture(scope="module")
def mod():
    spec = importlib.util.spec_from_file_location("make_results_summary", SCRIPT)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def test_summary_is_computed_from_the_files_and_names_sources(mod, tmp_path):
    cfg = fx.build(tmp_path)
    text = mod.build(cfg.results_dir, cfg.flows_path, cfg.root, "SYNTHETIC-commit")
    assert "Results summary (generated)" in text and "SYNTHETIC-commit" in text
    # detector table: median FPR of the SYNTHETIC naive method on the non-classical profile (0.90 by construction)
    assert "| rf | naive |" in text and "0.900" in text
    assert "detector_baseline.csv" in text and "unknown (generated before tracking)" in text
    # sections whose input is absent say so
    assert "Not available" in text and "stats_claims.csv" in text and "rep_timing.csv" in text


def test_sidecar_commit_is_reported(mod, tmp_path):
    cfg = fx.build(tmp_path)
    (cfg.results_dir / "detector_baseline.meta.json").write_text(json.dumps({"code_commit": "abc123-dirty", "generated_at": "2026-01-01T00:00:00+00:00", "script": "scripts/x.py"}))
    text = mod.build(cfg.results_dir, cfg.flows_path, cfg.root, "c")
    assert "abc123-dirty" in text


def test_method_medians_exclude_the_classical_profile(mod, tmp_path):
    import pandas as pd
    cfg = fx.build(tmp_path)
    base = pd.read_csv(cfg.results_dir / "detector_baseline.csv")
    t = mod.method_medians(base, None)
    row = t[(t.detector == "rf") & (t.method == "naive")].iloc[0]
    assert row.fpr == pytest.approx(fx.synthetic_fpr(fx.P1, "naive"))          # only the PQ profile enters the median


def test_md_table_formats_floats(mod):
    import pandas as pd
    assert mod.md_table(pd.DataFrame({"a": [0.12345], "b": ["x"]})) == "| a | b |\n|---|---|\n| 0.123 | x |"
