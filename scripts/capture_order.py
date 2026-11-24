"""Print the replicate capture order, one line per capture: run_order kem auth chain replicate workload.

Used by lab/run_matrix.sh --rep. Run from the repo root:  .venv/Scripts/python scripts/capture_order.py --seed 20261124
"""

from __future__ import annotations

import sys

from pqdl.labplan import replicate_order


def main(argv: list[str]) -> None:
    sys.stdout.reconfigure(newline=chr(10))   # plain LF even on Windows: the shell must not see a trailing CR
    seed = int(argv[argv.index("--seed") + 1]) if "--seed" in argv else 0
    for run_order, kem, auth, chain, replicate, workload in replicate_order(seed):
        print(run_order, kem, auth, chain, replicate, workload)


if __name__ == "__main__":
    main(sys.argv[1:])
