"""H1 / H3 / H4 drift analyses on the lab flows. Writes results/lab_drift.csv and docs/lab_drift_notes.md.

Reads data/flows/lab_flows.csv only (source = pq_lab); produced by scripts/pcaps_to_flows.py after the capture
run is complete. Fixed seed. Prints the H3, H1 and H4 tables. Run from the repo root:
    .venv/Scripts/python scripts/lab_drift.py
"""

from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd

from pqdl import sidecar
from pqdl.lab_drift import LabDriftResult, run_lab_drift

ROOT = Path(__file__).resolve().parents[1]
FLOWS = ROOT / "data" / "flows" / "lab_flows.csv"
MANIFEST = ROOT / "data" / "pcaps" / "manifest.csv"
OUT_CSV = ROOT / "results" / "lab_drift.csv"
OUT_MD = ROOT / "docs" / "lab_drift_notes.md"
SUMMARY_COLUMNS = ["feature", "eta2_all_groups", "noise95_eta2", "max_psi", "noise95_max_psi", "max_mmd2"]


def show(title: str, frame: pd.DataFrame) -> None:
    print(f"\n=== {title}\n{frame.to_string(index=False)}")


def print_h3(res: LabDriftResult) -> None:
    results = res.results
    for workload, g in res.h3_summary.groupby("workload", sort=True):
        flagged = g[g["not_invariant"]].sort_values("eta2_all_groups", ascending=False)
        mmd = (results[(results["test"] == "H3_app_invariance") & (results["workload"] == workload)]
               .drop_duplicates("compared_group")["mmd2"])
        print(f"\n--- H3 {workload}: {len(flagged)} of {len(g)} app features exceed their noise floor "
              f"({int(g['eta2_above_noise'].sum())} by eta2, {int(g['psi_above_noise'].sum())} by PSI); "
              f"MMD^2 of each profile vs reference on all app features: min {mmd.min():.4f} / median {mmd.median():.4f} "
              f"/ max {mmd.max():.4f}")
        if len(flagged):
            print(flagged[SUMMARY_COLUMNS + ["eta2_above_noise", "psi_above_noise"]].round(4).to_string(index=False))


def print_h1(res: LabDriftResult) -> None:
    wide = res.h1.pivot_table(index=["workload", "feature", "deterministic", "max_within_cell_std"], columns="term",
                              values="partial_eta2", sort=False).reset_index()
    wide.columns.name = None
    show("H1 two-way (kem, auth, interaction) partial eta^2, chain = leaf_int; informative (non-deterministic) first",
         wide.sort_values(["deterministic", "feature", "workload"]).round(4))


def print_h4(res: LabDriftResult) -> None:
    for workload, g in res.h4_summary.groupby("workload", sort=True):
        show(f"H4 whole-connection flow features, {workload}",
             g[SUMMARY_COLUMNS + ["eta2_above_noise", "psi_above_noise", "not_invariant"]].round(4))


def main() -> None:
    flows = pd.read_csv(FLOWS)
    if set(flows["source"]) != {"pq_lab"}:
        raise SystemExit(f"{FLOWS} must contain only source = pq_lab, found {sorted(flows['source'].unique())}")
    result = run_lab_drift(flows, n_noise=200, max_n=2000, seed=0, manifest=pd.read_csv(MANIFEST))
    OUT_CSV.parent.mkdir(exist_ok=True)
    result.results.to_csv(OUT_CSV, index=False)
    OUT_MD.write_text(result.notes, encoding="utf-8")
    print(f"wrote {OUT_CSV} ({len(result.results)} rows) and {OUT_MD}")
    print_h3(result)
    print_h1(result)
    print_h4(result)


if __name__ == "__main__":
    sys.exit(sidecar.tracked(main, ROOT, __file__))
