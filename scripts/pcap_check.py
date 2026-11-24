"""Print "observed_connections=N max_payload=M" for one pcap (used by lab/run_matrix.sh).

Run from the repo root:  .venv/Scripts/python scripts/pcap_check.py data/pcaps/<file>.pcap
"""

from __future__ import annotations

import sys

from pqdl.pcap import capture_checks


def main(argv: list[str]) -> None:
    connections, max_payload = capture_checks(argv[0])
    print(f"observed_connections={connections} max_payload={max_payload}")


if __name__ == "__main__":
    main(sys.argv[1:])
