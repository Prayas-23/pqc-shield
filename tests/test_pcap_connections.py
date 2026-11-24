"""extract_connections / TLS record parsing on hand-built SYNTHETIC captures (written by the tests themselves).

Covered, with expected values computed by hand (see the fixture docstring):
  (a) a TLS record split across several TCP segments, (b) a reused source port (two connections on one
  4-tuple), (c) a retransmitted data segment, plus a retransmitted SYN and out-of-order segments.
"""

from __future__ import annotations

import math
from pathlib import Path

import pytest
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw
from scapy.utils import wrpcap

from pqdl.pcap import capture_checks, extract_connections, parse_server_hello, parse_smoke_output, parse_tls_records


def rec(rec_type: int, payload_len: int) -> bytes:
    """A fake TLS record: 5-byte header + payload_len zero bytes."""
    return bytes([rec_type, 3, 3]) + payload_len.to_bytes(2, "big") + bytes(payload_len)


def server_hello(group: int, cipher: int) -> bytes:
    """A real-looking ServerHello record (67 bytes): supported_versions + key_share(group) extensions."""
    exts = (bytes.fromhex("002b00020304") + bytes.fromhex("0033") + (8).to_bytes(2, "big")
            + group.to_bytes(2, "big") + (4).to_bytes(2, "big") + bytes(4))
    body = (bytes.fromhex("0303") + bytes(32) + b"\x00" + cipher.to_bytes(2, "big") + b"\x00"
            + len(exts).to_bytes(2, "big") + exts)
    handshake = b"\x02" + len(body).to_bytes(3, "big") + body
    return bytes([22, 3, 3]) + len(handshake).to_bytes(2, "big") + handshake


def pkt(t: float, src: str, sport: int, dst: str, dport: int, flags: str, seq: int, ack: int = 0, load: bytes = b""):
    p = Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack)
    p = p / Raw(load=load) if load else p
    p.time = t
    return p


def synthetic_two_connections(tmp_path: Path) -> Path:
    """SYNTHETIC. Two connections from the SAME client ip:port to the server (port reuse).

    Connection 1 (ISN client 1000, server 5000), group 0x11ec, cipher 0x1302:
      client stream: ClientHello 100 B | CCS 6 B + Finished 58 B (one segment) | request record 45 B
      server stream: ServerHello 67 B + CCS 6 B + one 3005-byte record = 3078 B, sent as three segments
                     [0,1000) [1000,2000) [2000,3078) so the big record spans all three; segment 2 is
                     retransmitted; then a 505-byte response record after the client Finished.
    Connection 2 (ISN client 70000, server 90000), group 0x001d, cipher 0x1301:
      client: ClientHello 100 B | CCS + Finished 64 B ; server: SH 67 + CCS 6 + 105-byte record = 178 B.
    """
    c, s = "10.0.0.2", "10.0.0.3"
    ch, ccs_fin, req = rec(22, 95), rec(20, 1) + rec(23, 53), rec(23, 40)
    flight = server_hello(0x11EC, 0x1302) + rec(20, 1) + rec(23, 3000)
    assert (len(ch), len(ccs_fin), len(req), len(flight)) == (100, 64, 45, 3078)
    resp = rec(23, 500)
    pk = [
        pkt(0.0000, c, 40000, s, 4433, "S", 1000),
        pkt(0.0005, c, 40000, s, 4433, "S", 1000),                              # retransmitted SYN: same connection
        pkt(0.0010, s, 4433, c, 40000, "SA", 5000, 1001),
        pkt(0.0020, c, 40000, s, 4433, "A", 1001, 5001),
        pkt(0.0030, c, 40000, s, 4433, "PA", 1001, 5001, ch),
        pkt(0.0040, s, 4433, c, 40000, "A", 5001, 1101, flight[:1000]),
        pkt(0.0050, s, 4433, c, 40000, "A", 6001, 1101, flight[1000:2000]),
        pkt(0.0060, s, 4433, c, 40000, "A", 6001, 1101, flight[1000:2000]),      # retransmission of segment 2
        pkt(0.0070, s, 4433, c, 40000, "PA", 7001, 1101, flight[2000:]),
        pkt(0.0100, c, 40000, s, 4433, "PA", 1101, 8079, ccs_fin),              # client CCS + Finished
        pkt(0.0110, c, 40000, s, 4433, "PA", 1165, 8079, req),                  # request (application phase)
        pkt(0.0210, s, 4433, c, 40000, "PA", 8079, 1210, resp),                 # response
        pkt(0.0220, c, 40000, s, 4433, "FA", 1210, 8584),
        pkt(0.0230, s, 4433, c, 40000, "FA", 8584, 1211),
        pkt(0.0240, c, 40000, s, 4433, "A", 1211, 8585),
        # ---- port reuse: a brand-new connection on the same 4-tuple
        pkt(1.0000, c, 40000, s, 4433, "S", 70000),
        pkt(1.0010, s, 4433, c, 40000, "SA", 90000, 70001),
        pkt(1.0020, c, 40000, s, 4433, "A", 70001, 90001),
        pkt(1.0030, c, 40000, s, 4433, "PA", 70001, 90001, rec(22, 95)),
        pkt(1.0040, s, 4433, c, 40000, "PA", 90001, 70101, server_hello(0x001D, 0x1301) + rec(20, 1) + rec(23, 100)),
        pkt(1.0100, c, 40000, s, 4433, "PA", 70101, 90179, rec(20, 1) + rec(23, 53)),
        pkt(1.0200, c, 40000, s, 4433, "FA", 70165, 90179),
        pkt(1.0210, s, 4433, c, 40000, "A", 90179, 70166),
        Ether() / ARP(),                                                         # non-TCP noise
    ]
    path = tmp_path / "synthetic_conns.pcap"
    wrpcap(str(path), pk)
    return path


def test_parse_tls_records_and_partial_tail() -> None:
    stream = rec(22, 10) + rec(20, 1) + rec(23, 20)
    assert [(r.type, r.start, r.length, r.end) for r in parse_tls_records(stream)] == [
        (22, 0, 10, 15), (20, 15, 1, 21), (23, 21, 20, 46)]
    assert len(parse_tls_records(stream[:-1])) == 2          # last record incomplete -> dropped
    assert parse_tls_records(b"\x16\x03") == []


def test_parse_smoke_output() -> None:
    text = (
        "auth         kem              | negotiated group peer sigalg              certs  rd/wr bytes | result\n"
        "mldsa65      mlkem768         | MLKEM768         mldsa65                      2   15976/1418 | PASS\n"
        "slhdsa128s   X25519           | -                -                            -          -/- | FAIL\n"
    )
    assert parse_smoke_output(text) == {("mlkem768", "mldsa65"): (15976, 1418, "PASS")}   # the "-/-" FAIL row has no counts


def test_parse_server_hello() -> None:
    info = parse_server_hello(server_hello(0x11EC, 0x1302) + rec(20, 1))
    assert (info.group_id, info.cipher_suite) == (0x11EC, 0x1302)
    assert parse_server_hello(rec(23, 10)).group_id is None       # first record is not a handshake record
    assert parse_server_hello(b"").cipher_suite is None


def test_port_reuse_gives_two_connections_and_retransmitted_syn_does_not(tmp_path: Path) -> None:
    rows = extract_connections(synthetic_two_connections(tmp_path))
    assert len(rows) == 2
    assert rows[0]["client_port"] == rows[1]["client_port"] == 40000
    assert [r["sh_group_id"] for r in rows] == [0x11EC, 0x001D]
    assert [r["sh_cipher_suite"] for r in rows] == [0x1302, 0x1301]


def test_connection_1_features_hand_computed(tmp_path: Path) -> None:
    r = extract_connections(synthetic_two_connections(tmp_path))[0]
    # handshake: client 100 + 64 = 164 B in 2 segments; server 3078 B in 3 segments (the retransmitted
    # middle segment is ignored); records: client CH, CCS, Finished = 3; server SH, CCS, 3005-B record = 3
    assert (r["hs_c2s_bytes"], r["hs_s2c_bytes"]) == (164, 3078)
    assert (r["hs_c2s_pkts"], r["hs_s2c_pkts"], r["hs_records"]) == (2, 3, 6)
    assert r["retransmitted_pkts"] == 1
    assert r["hs_duration"] == pytest.approx(0.0100)              # SYN at 0.000 -> client Finished at 0.010
    # application phase: one 45-B request, one 505-B response
    assert (r["app_c2s_bytes"], r["app_s2c_bytes"], r["app_c2s_pkts"], r["app_s2c_pkts"]) == (45, 505, 1, 1)
    assert r["app_pkt_len_mean"] == pytest.approx(275.0)          # (45 + 505) / 2
    assert r["app_pkt_len_std"] == pytest.approx(230.0)           # population std of {45, 505}
    assert r["app_pkt_len_max"] == 505
    assert r["app_iat_mean"] == pytest.approx(0.010) and r["app_iat_max"] == pytest.approx(0.010)
    assert r["app_iat_std"] == pytest.approx(0.0, abs=1e-9)
    assert r["app_duration"] == pytest.approx(0.010)
    assert r["app_tiny_client_pkts"] == 1                          # the 45-byte request
    assert (r["app_c2s_size_1"], r["app_s2c_size_1"]) == (45, 505)
    assert math.isnan(r["app_c2s_size_2"]) and math.isnan(r["app_s2c_size_10"])
    assert r["total_bytes"] == 164 + 3078 + 45 + 505 == 3792
    assert r["total_pkts"] == 7
    assert r["flow_duration"] == pytest.approx(0.0240)
    assert r["closed"] is True and r["handshake_complete"] is True


def test_connection_2_after_port_reuse_has_no_application_phase(tmp_path: Path) -> None:
    r = extract_connections(synthetic_two_connections(tmp_path))[1]
    assert (r["hs_c2s_bytes"], r["hs_s2c_bytes"]) == (164, 178)   # sequence numbers restart: not merged with conn 1
    assert (r["hs_c2s_pkts"], r["hs_s2c_pkts"], r["hs_records"]) == (2, 1, 6)
    assert (r["app_c2s_bytes"], r["app_s2c_bytes"], r["app_c2s_pkts"], r["app_s2c_pkts"]) == (0, 0, 0, 0)
    assert math.isnan(r["app_pkt_len_mean"]) and math.isnan(r["app_iat_mean"])
    assert r["app_duration"] == 0.0 and r["app_tiny_client_pkts"] == 0
    assert r["hs_duration"] == pytest.approx(0.0100)
    assert r["flow_duration"] == pytest.approx(0.0210)
    assert r["retransmitted_pkts"] == 0


def test_out_of_order_segments_are_reassembled(tmp_path: Path) -> None:
    """SYNTHETIC: the later server segment arrives BEFORE the earlier one; the record spans both."""
    c, s = "10.0.0.2", "10.0.0.3"
    flight = server_hello(0x0201, 0x1302) + rec(20, 1) + rec(23, 200)       # 67 + 6 + 205 = 278
    pk = [
        pkt(0.00, c, 41000, s, 4433, "S", 10), pkt(0.01, s, 4433, c, 41000, "SA", 20, 11),
        pkt(0.02, c, 41000, s, 4433, "PA", 11, 21, rec(22, 95)),
        pkt(0.03, s, 4433, c, 41000, "A", 21 + 100, 111, flight[100:]),      # later part first
        pkt(0.04, s, 4433, c, 41000, "A", 21, 111, flight[:100]),
        pkt(0.05, c, 41000, s, 4433, "PA", 111, 299, rec(23, 53)),
    ]
    path = tmp_path / "synthetic_ooo.pcap"
    wrpcap(str(path), pk)
    r = extract_connections(path)[0]
    assert r["sh_group_id"] == 0x0201
    assert r["hs_s2c_bytes"] == 278 and r["hs_s2c_pkts"] == 2 and r["retransmitted_pkts"] == 0


def test_capture_checks_counts_connections_and_largest_payload(tmp_path: Path) -> None:
    # SYNTHETIC capture from the fixture: 2 connections; the largest single payload is the 1078-byte last
    # server segment of connection 1 (the retransmitted 1000-byte segment is smaller).
    assert capture_checks(synthetic_two_connections(tmp_path)) == (2, 1078)


def test_whole_connection_flow_features_hand_computed(tmp_path: Path) -> None:
    """CICFlowMeter-like view over ALL packets of the connection (zero-payload packets and retransmissions included)."""
    import statistics

    rows = extract_connections(synthetic_two_connections(tmp_path))
    # Connection 1, in capture order: (time, client->server?, payload bytes)
    pkts = [(0.0000, True, 0), (0.0005, True, 0), (0.0010, False, 0), (0.0020, True, 0), (0.0030, True, 100),
            (0.0040, False, 1000), (0.0050, False, 1000), (0.0060, False, 1000), (0.0070, False, 1078),
            (0.0100, True, 64), (0.0110, True, 45), (0.0210, False, 505), (0.0220, True, 0), (0.0230, False, 0),
            (0.0240, True, 0)]
    r = rows[0]
    assert (r["flow_c2s_pkts"], r["flow_s2c_pkts"]) == (8, 7)              # 15 packets: 8 client, 7 server
    assert (r["flow_c2s_bytes"], r["flow_s2c_bytes"]) == (100 + 64 + 45, 1000 + 1000 + 1000 + 1078 + 505)
    lens = [n for _, _, n in pkts]
    assert r["flow_pkt_len_mean"] == pytest.approx(statistics.fmean(lens))
    assert r["flow_pkt_len_std"] == pytest.approx(statistics.pstdev(lens))      # population std
    assert r["flow_pkt_len_max"] == 1078
    gaps = [b[0] - a[0] for a, b in zip(pkts, pkts[1:])]
    assert r["flow_iat_mean"] == pytest.approx(statistics.fmean(gaps))
    assert r["flow_iat_std"] == pytest.approx(statistics.pstdev(gaps), abs=1e-9)
    assert r["flow_iat_max"] == pytest.approx(0.010)                           # request -> response gap
    # Connection 2 (after port reuse): SYN, ACK, ClientHello, server flight, CCS+Finished, FIN | SYN-ACK, ACK
    r2 = rows[1]
    assert (r2["flow_c2s_pkts"], r2["flow_s2c_pkts"]) == (5, 3)
    assert (r2["flow_c2s_bytes"], r2["flow_s2c_bytes"]) == (164, 178)
    lens2 = [0, 0, 0, 100, 178, 64, 0, 0]
    assert r2["flow_pkt_len_mean"] == pytest.approx(statistics.fmean(lens2))   # 342 / 8 = 42.75
    assert r2["flow_pkt_len_max"] == 178


def test_context_features_first12_data_packet_sizes(tmp_path: Path) -> None:
    """SYNTHETIC fixture: payload sizes of the first 12 data packets per direction (zero-payload packets skipped), 0-padded."""
    rows = extract_connections(synthetic_two_connections(tmp_path))
    c2s = [rows[0][f"flow_first12_c2s_size_{i}"] for i in range(1, 13)]
    s2c = [rows[0][f"flow_first12_s2c_size_{i}"] for i in range(1, 13)]
    assert c2s == [100, 64, 45] + [0] * 9
    assert s2c == [1000, 1000, 1000, 1078, 505] + [0] * 7                 # the retransmitted 1000 is a packet on the wire
    r2 = rows[1]
    assert [r2[f"flow_first12_c2s_size_{i}"] for i in (1, 2, 3)] == [100, 64, 0]
    assert [r2[f"flow_first12_s2c_size_{i}"] for i in (1, 2)] == [178, 0]
