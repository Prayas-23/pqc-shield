"""Compute drift effect sizes on the REAL CIC-PQC_OAV normal rows; write results/pqc_drift.csv.

Run from the repo root:  .venv/Scripts/python scripts/pqc_drift.py
Fixed seed, so the output is reproducible. (results/*.csv is git-ignored.)
"""

from __future__ import annotations

import sys
from pathlib import Path

from pqdl import sidecar
from pqdl.drift import pqc_contrast_table
from pqdl.features import PQC_DRIFT_FEATURES
from pqdl.loaders import SOURCE_PQC, assert_single_source, load_pqc_oav

OUT = Path(__file__).resolve().parents[1] / "results" / "pqc_drift.csv"
N_PERM = 200
MAX_N = 2000
SEED = 0


def main() -> None:
    pqc, _ = load_pqc_oav()
    assert_single_source(pqc)
    normal = pqc[pqc["label_raw"] == "Normal"]
    table = pqc_contrast_table(normal, PQC_DRIFT_FEATURES, n_perm=N_PERM, max_n=MAX_N, seed=SEED)
    assert set(table["source"]) == {SOURCE_PQC}
    OUT.parent.mkdir(exist_ok=True)
    table.to_csv(OUT, index=False)
    print(f"wrote {OUT} ({len(table)} rows; n_perm={N_PERM}, max_n={MAX_N}, seed={SEED})")


if __name__ == "__main__":
    sys.exit(sidecar.tracked(main, Path(__file__).resolve().parents[1], __file__))
