"""Generate docs/results_summary.md from the stored results files, with the provenance of each.

Run from the repo root:  .venv/Scripts/python scripts/make_results_summary.py
Every number in the output is read or computed from results/*.csv and data/flows/lab_flows.csv; nothing is typed. A section
whose input file is missing says so instead of being skipped silently. Each table names its source files and what the
provenance sidecar (results/<name>.meta.json) says about them ("unknown (generated before tracking)" when there is none).
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

from pqdl import sidecar

ROOT = Path(__file__).resolve().parents[1]
UNKNOWN = "unknown (generated before tracking)"
CLASSICAL = "X25519|ecdsa_p256|leaf_int"          # the reference profile of the lab matrix (pqdl.canon.CLASSICAL_CONTEXT)
NON_CLASSICAL_NOTE = "median over the non-classical profiles of the main run"


def md_table(df: pd.DataFrame, digits: int = 3) -> str:
    cols = list(df.columns)
    out = ["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
    for r in df.itertuples(index=False):
        out.append("| " + " | ".join(f"{v:.{digits}f}" if isinstance(v, float) else str(v) for v in r) + " |")
    return "\n".join(out)


def provenance_of(path: Path, root: Path) -> dict:
    """Sidecar of a results file (or UNKNOWN) plus its modification time."""
    meta = None
    try:
        meta = json.loads(path.with_suffix(".meta.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        pass
    mtime = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc).isoformat(timespec="seconds") if path.exists() else None
    try:
        rel = path.resolve().relative_to(root).as_posix()
    except ValueError:
        rel = path.name
    return {"file": rel, "exists": path.exists(), "code_commit": (meta or {}).get("code_commit", UNKNOWN),
            "script": (meta or {}).get("script", "n/a"), "generated_at": (meta or {}).get("generated_at", mtime or "n/a")}


def source_line(files: list[Path], root: Path) -> str:
    parts = []
    for f in files:
        p = provenance_of(f, root)
        parts.append(f"`{p['file']}` (commit: {p['code_commit']})")
    return "Source: " + "; ".join(parts) + "."


def read(path: Path) -> pd.DataFrame | None:
    return pd.read_csv(path) if path.exists() else None


def missing(name: str) -> str:
    return f"_Not available: `{name}` is missing. Run the script that produces it (see README.md)._\n"


# ------------------------------------------------------------------ sections
def sec_provenance(results: Path, flows: Path, root: Path) -> str:
    files = sorted(results.glob("*.csv")) + ([flows] if flows.exists() else [])
    rows = [provenance_of(f, root) for f in files]
    df = pd.DataFrame(rows)[["file", "code_commit", "script", "generated_at"]]
    return ("## Provenance of the results files\n\n" + md_table(df) + "\n\n"
            "`code_commit` comes from the sidecar written by the analysis script. Files produced before sidecars existed are "
            f"reported as \"{UNKNOWN}\"; `generated_at` then falls back to the file's modification time.\n")


def sec_handshake(flows_path: Path, root: Path) -> str:
    f = read(flows_path)
    if f is None:
        return "## Observed handshake bytes per profile\n\n" + missing(flows_path.name)
    f = f.assign(profile=f["kem"] + "|" + f["auth"] + "|" + f["chain"])
    t = (f.groupby("profile").agg(flows=("profile", "size"), server_to_client_B=("hs_s2c_bytes", "median"),
                                  client_to_server_B=("hs_c2s_bytes", "median")).reset_index().sort_values("server_to_client_B"))
    return ("## Observed handshake bytes per profile (main run)\n\n" + md_table(t, 1) + "\n\n"
            + "Median of the per-connection handshake-phase payload bytes (`hs_s2c_bytes`, `hs_c2s_bytes`) over all workloads. "
            + source_line([flows_path], root) + "\n")


def method_medians(base: pd.DataFrame, canon: pd.DataFrame | None) -> pd.DataFrame:
    df = pd.concat([base] + ([canon] if canon is not None else []), ignore_index=True)
    d = df[(df["dataset"] == "main") & (df["profile"] != CLASSICAL) & df["metric"].isin(["fpr", "tpr_all", "auroc"])]
    t = d.groupby(["detector", "method", "metric"])["value"].median().unstack("metric").reset_index()
    return t.reindex(columns=["detector", "method", "fpr", "tpr_all", "auroc"])


def sec_detectors(results: Path, root: Path) -> str:
    base, canon = read(results / "detector_baseline.csv"), read(results / "canon_eval.csv")
    if base is None:
        return "## Detector results\n\n" + missing("detector_baseline.csv")
    keep = ["naive", "naive_app", "pooled", "oracle", "canon_a_true", "canon_a2_true", "canon_b_k100_true", "canon_bs_k120_true"]
    t = method_medians(base, canon)
    t = t[t["method"].isin(keep)].sort_values(["detector", "method"])
    cls = base[(base["dataset"] == "main") & (base["profile"] == CLASSICAL) & (base["method"] == "naive") & (base["metric"] == "fpr")]
    files = [results / "detector_baseline.csv"] + ([results / "canon_eval.csv"] if canon is not None else [])
    s = ("## Detector results (main run test blocks)\n\n"
         f"FPR, TPR (all attacks) and AUROC, {NON_CLASSICAL_NOTE}. The attacks are scripted attack-like workloads, so TPR is not "
         "informative about real attacks; read the FPR column first.\n\n" + md_table(t) + "\n\n")
    if len(cls):
        s += ("Classical in-domain check (naive detector on the classical profile, design point = threshold quantile): "
              + ", ".join(f"{r.detector} {r.value:.3f}" for r in cls.itertuples()) + ".\n\n")
    return s + source_line(files, root) + "\n"


def sec_replication(results: Path, root: Path) -> str:
    out = ["## Replicate confirmation (4 replicated profiles)\n"]
    files = []
    for name, label in (("detector_baseline_confirmation.csv", "baseline"), ("canon_confirmation.csv", "CANON")):
        d = read(results / name)
        if d is None:
            out.append(f"- {label}: " + missing(name).strip())
            continue
        d = d[d["metric"].isin(["fpr", "tpr_all", "auroc"])] if "metric" in d.columns else d
        out.append(f"- {label}: main-run and replicate confidence intervals overlap in {int(d['ci_overlap'].sum())} of {len(d)} "
                   f"cells; largest absolute difference {d['abs_diff'].max():.3f}.")
        files.append(results / name)
    return "\n".join(out) + "\n\n" + (source_line(files, root) + "\n" if files else "")


def sec_context(results: Path, root: Path) -> str:
    d = read(results / "canon_context_accuracy.csv")
    if d is None:
        return "## Context estimator\n\n" + missing("canon_context_accuracy.csv")
    t = d.groupby("dataset").apply(lambda g: float((g["recall"] * g["n"]).sum() / g["n"].sum()), include_groups=False)
    return ("## Context estimator (c-hat)\n\n" + ", ".join(f"accuracy on the {k} test blocks: {v:.3f}" for k, v in t.items())
            + ". The labelled contexts are exact only because the lab is deterministic.\n\n"
            + source_line([results / "canon_context_accuracy.csv"], root) + "\n")


def sec_timing(results: Path, root: Path) -> str:
    d = read(results / "rep_timing.csv")
    if d is None:
        return "## Replicate timing analysis\n\n" + missing("rep_timing.csv")
    t = (d.assign(sig=d["perm_p_holm"] < 0.05).groupby("workload")
         .agg(features=("feature", "size"), significant=("sig", "sum"), median_icc=("icc", "median")).reset_index())
    return ("## Replicate timing analysis (pcap level)\n\n" + md_table(t) + "\n\n"
            "`significant` = features whose profile effect has a Holm-adjusted permutation p below 0.05 (pcap medians as the unit). "
            + source_line([results / "rep_timing.csv"], root) + "\n")


def sec_claims(results: Path, root: Path) -> str:
    d = read(results / "stats_claims.csv")
    if d is None:
        return "## Claims table\n\n" + missing("stats_claims.csv")
    counts = d["status"].value_counts().to_dict()
    return ("## Claims table (statuses)\n\n" + ", ".join(f"{k}: {v}" for k, v in sorted(counts.items())) + ".\n\n"
            + md_table(d[["claim", "status", "detail"]]) + "\n\nThe full table with the tests and evidence files is in `docs/stats_notes.md`. "
            + source_line([results / "stats_claims.csv"], root) + "\n")


def build(results: Path, flows: Path, root: Path, generated_by: str) -> str:
    head = ("# Results summary (generated)\n\n"
            f"Generated by `scripts/make_results_summary.py` at commit {generated_by}. Every number is read or computed from the "
            "files named under each table; none is typed. Real lab captures, single machine, scripted workloads, one cipher suite "
            "(see the limitations in `README.md`). Do not quote a number from here without its source line.\n\n")
    body = [sec_provenance(results, flows, root), sec_handshake(flows, root), sec_detectors(results, root), sec_replication(results, root),
            sec_context(results, root), sec_timing(results, root), sec_claims(results, root)]
    return head + "\n".join(body)


def main() -> int:
    text = build(ROOT / "results", ROOT / "data" / "flows" / "lab_flows.csv", ROOT, sidecar.code_version(ROOT))
    out = ROOT / "docs" / "results_summary.md"
    out.write_text(text, encoding="utf-8", newline="\n")
    print(f"wrote {out.relative_to(ROOT)} ({len(text.splitlines())} lines)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
