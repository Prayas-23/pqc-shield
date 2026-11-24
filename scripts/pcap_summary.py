"""Print a header-level summary of the pcaps listed in data/pcaps/manifest.csv (or of given files).

Run from the repo root:  .venv/Scripts/python scripts/pcap_summary.py [file.pcap ...]
Uses scapy on our own captures; looks at packet headers and sizes only.
"""

from __future__ import annotations

import csv
import sys
from pathlib import Path

from pqdl.pcap import summarise_pcap

PCAPS = Path(__file__).resolve().parents[1] / "data" / "pcaps"


def main(argv: list[str]) -> None:
    files = [Path(a) for a in argv] or [PCAPS / r["pcap_file"] for r in csv.DictReader((PCAPS / "manifest.csv").open())]
    print(f"{'pcap':52} {'pkts':>6} {'tcp':>6} {'payload B':>10} {'c->s B':>9} {'s->c B':>9} "
          f"{'data pkts':>9} {'tiny c->s':>9} {'conns':>6} {'max pl':>7}")
    for f in files:
        s = summarise_pcap(f)
        print(f"{f.name:52} {s.packets:>6} {s.tcp_packets:>6} {s.tcp_payload_bytes:>10} {s.client_to_server_bytes:>9} "
              f"{s.server_to_client_bytes:>9} {s.payload_packets:>9} {s.tiny_client_packets:>9} {s.connections:>6} {s.max_payload:>7}")
    print("\npkts = all packets in the file (includes ARP/ICMPv6 noise); the rest counts TCP on port 4433 only.")
    print("tiny c->s = client->server packets with 1..60 payload bytes; conns = SYN packets to the server.")


if __name__ == "__main__":
    main(sys.argv[1:])
