"""Provenance block attached to every response. Reads files only; never runs a command."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from api.config import ApiConfig


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


def _display(path: Path, cfg: ApiConfig) -> str:
    try:
        return path.resolve().relative_to(cfg.root).as_posix()
    except ValueError:
        return path.name


def provenance(cfg: ApiConfig, source_files: list[Path]) -> dict:
    """{data_source, synthetic, code_commit, generated_at, source_files}. generated_at = newest modification time of the
    source files (when the stored results were produced), UTC ISO-8601."""
    mtimes = [p.stat().st_mtime for p in source_files if p.exists()]
    stamp = datetime.fromtimestamp(max(mtimes), tz=timezone.utc).isoformat(timespec="seconds") if mtimes else None
    return {"data_source": "SYNTHETIC_TEST_FIXTURE" if cfg.synthetic else "lab_captures",
            "synthetic": bool(cfg.synthetic),
            "code_commit": read_git_head(cfg.root),
            "generated_at": stamp,
            "source_files": sorted(_display(p, cfg) for p in source_files)}
