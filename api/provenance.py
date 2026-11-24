"""Provenance block attached to every response. Reads files only; never runs a command."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from api.config import ApiConfig

UNKNOWN_RESULTS_COMMIT = "unknown (generated before tracking)"
MIXED_RESULTS_COMMIT = "mixed (see results_files)"


def read_git_head(root: Path) -> str:
    """Commit sha of HEAD, read straight from .git (no subprocess). 'unknown' if it cannot be read."""
    try:
        head = (root / ".git" / "HEAD").read_text(encoding="utf-8").strip()
        if not head.startswith("ref:"):
            return head
        ref = head.split(" ", 1)[1].strip()
        ref_file = root / ".git" / ref
        if ref_file.exists():
            return ref_file.read_text(encoding="utf-8").strip()
        for line in (root / ".git" / "packed-refs").read_text(encoding="utf-8").splitlines():
            if line.endswith(" " + ref):
                return line.split(" ", 1)[0]
    except OSError:
        pass
    return "unknown"


def read_sidecar(results_file: Path) -> dict | None:
    """results/<name>.meta.json written by the analysis script, or None if absent or unreadable."""
    p = results_file.with_suffix(".meta.json")
    try:
        meta = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(meta, dict) or not {"code_commit", "generated_at", "script"} <= set(meta):
        return None
    return {k: meta[k] for k in ("code_commit", "generated_at", "script")}


def _display(path: Path, cfg: ApiConfig) -> str:
    try:
        return path.resolve().relative_to(cfg.root).as_posix()
    except ValueError:
        return path.name


def results_commit(sidecars: dict[str, dict | None]) -> str:
    """One commit if every source file has a sidecar with the same commit; UNKNOWN if none has one; otherwise MIXED."""
    commits = [m["code_commit"] if m else None for m in sidecars.values()]
    if not commits or all(c is None for c in commits):
        return UNKNOWN_RESULTS_COMMIT
    if None not in commits and len(set(commits)) == 1:
        return commits[0]
    return MIXED_RESULTS_COMMIT


def provenance(cfg: ApiConfig, source_files: list[Path]) -> dict:
    """data_source, synthetic, results_code_commit (from the sidecars), served_by_commit (repository HEAD when the request
    is served), results_files (sidecar of each source file or null), generated_at (newest sidecar time, else newest file
    modification time) and source_files."""
    side = {_display(p, cfg): read_sidecar(p) for p in source_files}
    stamps = []
    for p in source_files:
        m = read_sidecar(p)
        if m:
            stamps.append(datetime.fromisoformat(m["generated_at"]))
        elif p.exists():
            stamps.append(datetime.fromtimestamp(p.stat().st_mtime, tz=timezone.utc))
    return {"data_source": "SYNTHETIC_TEST_FIXTURE" if cfg.synthetic else "lab_captures",
            "synthetic": bool(cfg.synthetic),
            "results_code_commit": results_commit(side) if source_files else UNKNOWN_RESULTS_COMMIT,
            "served_by_commit": read_git_head(cfg.root),
            "results_files": dict(sorted(side.items())),
            "generated_at": max(stamps).isoformat(timespec="seconds") if stamps else None,
            "source_files": sorted(side)}
