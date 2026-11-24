"""Tests for pqdl.sidecar on a throwaway git repo in tmp_path (SYNTHETIC; no project data)."""

from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path

import pytest

from pqdl import sidecar

GIT = ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid"]


def git(root: Path, *args: str) -> None:
    subprocess.run([*GIT, *args], cwd=root, check=True, capture_output=True)


@pytest.fixture
def repo(tmp_path) -> Path:
    git(tmp_path, "init", "-q")
    (tmp_path / "a.txt").write_text("one")
    (tmp_path / ".gitignore").write_text("results/\ndocs/\n")                  # like the project: outputs are ignored
    git(tmp_path, "add", "a.txt", ".gitignore")
    git(tmp_path, "commit", "-q", "-m", "first")
    (tmp_path / "results").mkdir()
    return tmp_path


def head(root: Path) -> str:
    return subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, capture_output=True, text=True, check=True).stdout.strip()


def test_code_version_clean_dirty_and_not_a_repo(repo, tmp_path_factory):
    sha = head(repo)
    assert sidecar.code_version(repo) == sha
    (repo / "a.txt").write_text("changed")
    assert sidecar.code_version(repo) == sha + "-dirty"
    git(repo, "checkout", "--", "a.txt")
    (repo / "new_untracked.txt").write_text("x")
    assert sidecar.code_version(repo) == sha + "-dirty"                       # untracked files count, like run_matrix.sh
    other = tmp_path_factory.mktemp("norepo")
    old = os.environ.get("GIT_CEILING_DIRECTORIES")
    os.environ["GIT_CEILING_DIRECTORIES"] = str(other.parent)
    try:
        assert sidecar.code_version(other) == "unknown"
    finally:
        if old is None:
            os.environ.pop("GIT_CEILING_DIRECTORIES")
        else:
            os.environ["GIT_CEILING_DIRECTORIES"] = old


def test_sidecar_path_naming():
    assert sidecar.sidecar_path(Path("results/lab_drift.csv")) == Path("results/lab_drift.meta.json")


def test_tracked_writes_sidecars_only_for_files_the_script_wrote(repo):
    old = repo / "results" / "old_result.csv"
    old.write_text("a\n1\n")
    os.utime(old, (time.time() - 3600, time.time() - 3600))                    # written long before this run
    sha = head(repo)

    def fake_main(x: int) -> None:
        (repo / "results" / "new_result.csv").write_text("a\n2\n")
        (repo / "docs").mkdir(exist_ok=True)
        (repo / "docs" / "notes.md").write_text("changes the tree AFTER the version was recorded")
        assert x == 7

    rc = sidecar.tracked(fake_main, repo, repo / "scripts" / "fake.py", 7)
    assert rc == 0
    meta = json.loads((repo / "results" / "new_result.meta.json").read_text())
    assert set(meta) == {"code_commit", "generated_at", "script"}
    assert meta["code_commit"] == sha                                          # recorded at the START: clean, not -dirty
    assert meta["script"] == "scripts/fake.py" and meta["generated_at"].endswith("+00:00")
    assert not (repo / "results" / "old_result.meta.json").exists()           # untouched result gets no sidecar


def test_tracked_marks_dirty_tree_and_passes_exit_code(repo):
    (repo / "a.txt").write_text("edited before the run")
    sha = head(repo)

    def failing_main() -> int:
        (repo / "results" / "r.csv").write_text("a\n")
        return 2

    assert sidecar.tracked(failing_main, repo, repo / "scripts" / "s.py") == 2
    assert json.loads((repo / "results" / "r.meta.json").read_text())["code_commit"] == sha + "-dirty"


def test_every_results_writing_script_runs_through_tracked():
    scripts = Path(__file__).resolve().parents[1] / "scripts"
    for name in ("lab_drift", "detector_baseline", "canon_eval", "stats_eval", "rep_timing", "canon_attribution",
                 "pqc_drift", "measure_cert_overhead"):
        text = (scripts / f"{name}.py").read_text(encoding="utf-8")
        assert "sidecar.tracked(main" in text and "from pqdl import sidecar" in text, name
