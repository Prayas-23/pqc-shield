"""summarise_pcap on a hand-built capture (SYNTHETIC packets written by the test itself)."""

from pathlib import Path

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import ARP, Ether
from scapy.utils import wrpcap

from pqdl.pcap import summarise_pcap

C, S = "10.0.0.2", "10.0.0.3"


def tcp(src: str, dst: str, sport: int, dport: int, flags: str, payload: bytes = b""):
    return Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags) / payload


def test_summarise_hand_built_pcap(tmp_path: Path) -> None:
    packets = [
        tcp(C, S, 40000, 4433, "S"),                      # connection 1: SYN
        tcp(S, C, 4433, 40000, "SA"),                     # SYN-ACK (not a new connection)
        tcp(C, S, 40000, 4433, "A"),                      # ACK, no payload
        tcp(C, S, 40000, 4433, "PA", b"x" * 100),         # 100 bytes client -> server
        tcp(S, C, 4433, 40000, "PA", b"y" * 1000),        # 1000 bytes server -> client
        tcp(C, S, 40001, 4433, "S"),                      # connection 2: SYN
        tcp(C, S, 40001, 4433, "PA", b"a"),               # tiny (1 byte)
        tcp(C, S, 40001, 4433, "PA", b"b" * 60),          # tiny (60 bytes = tiny_max)
        tcp(C, S, 40001, 4433, "PA", b"c" * 61),          # not tiny (61 bytes)
        tcp(C, S, 50000, 8080, "S", b""),                 # other port: ignored
        Ether() / ARP(),                                  # non-TCP: counted only in `packets`
    ]
    path = tmp_path / "synthetic.pcap"
    wrpcap(str(path), packets)
    s = summarise_pcap(path, server_port=4433, tiny_max=60)
    assert s.packets == 11
    assert s.tcp_packets == 9
    assert s.connections == 2
    assert s.client_to_server_bytes == 100 + 1 + 60 + 61
    assert s.server_to_client_bytes == 1000
    assert s.tcp_payload_bytes == 1222
    assert s.payload_packets == 5
    assert s.tiny_client_packets == 2
    assert s.max_payload == 1000
