"""Measure the per-certificate overhead of the lab's own certificates (EXPLORATORY, post-hoc; used only by CANON-A2).

Run from the repo root:  .venv/Scripts/python scripts/measure_cert_overhead.py
Needs Docker and the lab image. A throwaway PKI is generated inside a container by lab/gen_certs.sh (never leaves the
container); the DER size of the leaf and the intermediate certificate is read for every auth. Per auth:
    o_cert = mean over {leaf, intermediate} of (DER size - public key - signature),
with public key and signature taken from the size model's SIZES table (so the model's own sizes are kept and only the
framing overhead is measured). ECDSA signature DER lengths vary by a few bytes between PKIs; ML-DSA sizes are exact.
Writes results/cert_overhead.csv.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pandas as pd

from pqdl.canon import AUTH_MAP, measured_o_cert
from pqdl.profiles import SIZES

ROOT = Path(__file__).resolve().parents[1]
IMAGE = "pqdl-lab:openssl-3.5.9"


def find_docker() -> str:
    import shutil
    found = shutil.which("docker")
    if found:
        return found
    cand = Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "DockerDesktop" / "resources" / "bin" / "docker.exe"
    if cand.exists():
        return str(cand)
    raise SystemExit("Docker not found: cannot measure the lab certificates")


def parse_sizes(text: str) -> pd.DataFrame:
    rows = [line.strip().split(",") for line in text.splitlines() if line.count(",") == 2]
    return pd.DataFrame(rows, columns=["auth", "leaf_der", "int_der"]).astype({"leaf_der": int, "int_der": int})


def overhead_table(sizes: pd.DataFrame) -> pd.DataFrame:
    """Add pk, sig and o_cert (mean of leaf and intermediate framing) per auth."""
    out = sizes.copy()
    pk_sig = [SIZES["auth"][AUTH_MAP[a]] for a in out["auth"]]
    out["pk"], out["sig"] = [p for p, _ in pk_sig], [s for _, s in pk_sig]
    out["o_cert_leaf"] = out["leaf_der"] - out["pk"] - out["sig"]
    out["o_cert_int"] = out["int_der"] - out["pk"] - out["sig"]
    out["o_cert"] = [measured_o_cert(a, l, i) for a, l, i in zip(out["auth"], out["leaf_der"], out["int_der"])]
    return out


def main() -> int:
    env = {**os.environ, "MSYS_NO_PATHCONV": "1"}
    cmd = [find_docker(), "run", "--rm", "-v", f"{ROOT / 'lab'}:/hostlab:ro", IMAGE, "bash", "/hostlab/measure_cert_sizes.sh"]
    res = subprocess.run(cmd, capture_output=True, text=True, timeout=600, env=env)
    if res.returncode != 0:
        print(res.stdout, res.stderr, file=sys.stderr)
        return 1
    table = overhead_table(parse_sizes(res.stdout.replace("\r", "")))
    (ROOT / "results").mkdir(exist_ok=True)
    table.to_csv(ROOT / "results" / "cert_overhead.csv", index=False)
    print(table.to_string(index=False))
    print("model default o_cert: 40")
    return 0


if __name__ == "__main__":
    sys.exit(main())
