"""Provenance sidecars for results files.

Every analysis script is run through `tracked(...)`: it records the code version (git HEAD, plus "-dirty" if the working
tree has changes) BEFORE the script runs, and afterwards writes results/<name>.meta.json next to every results CSV the
script wrote (files modified since the script started) with {code_commit, generated_at, script}. The API reads these to
report which code produced a result. Results files without a sidecar are reported as generated before tracking.
"""

from __future__ import annotations

import json
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


def code_version(root: Path) -> str:
    """git HEAD sha, with '-dirty' appended when `git status --porcelain` is not empty; 'unknown' if git fails."""
    try:
        sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, capture_output=True, text=True, timeout=30)
        if sha.returncode != 0 or not sha.stdout.strip():
            return "unknown"
        status = subprocess.run(["git", "status", "--porcelain"], cwd=root, capture_output=True, text=True, timeout=60)
        dirty = status.returncode == 0 and bool(status.stdout.strip())
        return sha.stdout.strip() + ("-dirty" if dirty else "")
    except (OSError, subprocess.SubprocessError):
        return "unknown"


@dataclass(frozen=True)
class Run:
    started: float          # time.time() at the start of the script
    code_commit: str        # code version at the start of the script


def start(root: Path) -> Run:
    return Run(time.time(), code_version(root))


def sidecar_path(results_file: Path) -> Path:
    """results/lab_drift.csv -> results/lab_drift.meta.json"""
    return results_file.with_suffix(".meta.json")


def write_for_outputs(run: Run, script: str, results_dir: Path) -> list[Path]:
    """Write a sidecar for every results CSV modified since `run.started`. Returns the sidecar paths."""
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    written = []
    for csv in sorted(results_dir.glob("*.csv")):
        if csv.stat().st_mtime >= run.started - 1.0:
            meta = {"code_commit": run.code_commit, "generated_at": now, "script": script}
            p = sidecar_path(csv)
            p.write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8", newline="\n")
            written.append(p)
    return written


def tracked(fn: Callable[..., int | None], root: str | Path, script_file: str | Path, *args) -> int:
    """Run an analysis script's main(), then write the sidecars for the results it produced. Returns its exit code."""
    root = Path(root).resolve()
    run = start(root)
    rc = fn(*args)
    try:
        script = Path(script_file).resolve().relative_to(root).as_posix()
    except ValueError:
        script = Path(script_file).name
    write_for_outputs(run, script, root / "results")
    return 0 if rc is None else int(rc)
