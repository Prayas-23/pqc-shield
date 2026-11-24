"""PCAP reading and per-connection flow features.

Reads packet captures we generated ourselves between local containers (via scapy, streaming). Defensive
only: offline analysis of our own captures; no scanning of external hosts and no decryption of traffic.
Only TCP headers, sizes, timing and the cleartext TLS record headers / ServerHello are looked at.

- summarise_pcap:      quick packet and payload counts for a capture
- extract_connections: one feature row per TCP connection (see docs/pcap_method.md for the method)

Method in one paragraph: a connection starts at a client SYN (SYN without ACK) and ends at the next SYN on
the same 4-tuple (or end of file), so reused source ports never merge connections. Each direction is
reassembled by TCP sequence number (duplicates ignored). The reassembled stream is cut into TLS records.
The handshake phase runs from the SYN to the end of the client's FIRST ApplicationData record (type 23),
which in TLS 1.3 is the client Finished; everything after that is the application phase.
"""

from __future__ import annotations

import bisect
import math
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from scapy.layers.inet import IP, TCP
from scapy.utils import PcapReader

SYN, ACK, FIN, RST = 0x02, 0x10, 0x01, 0x04
TLS_CCS, TLS_ALERT, TLS_HANDSHAKE, TLS_APPDATA = 20, 21, 22, 23
TINY_MAX = 60
N_FIRST = 10

# TLS supported-groups ids seen in the ServerHello key_share. VERIFY against the IANA registry / RFCs:
# x25519 = 0x001d (RFC 8446); MLKEM768 = 0x0201 and X25519MLKEM768 = 0x11ec (IETF TLS ML-KEM drafts).
GROUP_NAMES: dict[int, str] = {0x001D: "X25519", 0x0201: "MLKEM768", 0x0202: "MLKEM1024", 0x11EC: "X25519MLKEM768"}
KEM_GROUP_IDS: dict[str, int] = {"X25519": 0x001D, "mlkem768": 0x0201, "X25519MLKEM768": 0x11EC}


# ------------------------------------------------------------------------ summary (unchanged API)
@dataclass(frozen=True)
class PcapSummary:
    """Header-level summary of one capture, restricted to TCP on `server_port` unless noted."""

    path: str
    packets: int                    # all packets in the file (incl. ARP/ICMPv6 noise)
    tcp_packets: int                # TCP packets to/from server_port
    tcp_payload_bytes: int          # total TCP payload bytes, both directions
    client_to_server_bytes: int
    server_to_client_bytes: int
    payload_packets: int            # TCP packets with a non-empty payload
    tiny_client_packets: int        # client->server packets with 1..tiny_max payload bytes
    connections: int                # SYN (without ACK) packets to server_port
    max_payload: int                # largest single TCP payload seen
    tiny_max: int


def summarise_pcap(path: str | Path, server_port: int = 4433, tiny_max: int = TINY_MAX) -> PcapSummary:
    """Count packets and TCP payload bytes in a pcap, relative to the lab server's TCP port."""
    total = tcp = c2s = s2c = payload_pkts = tiny = conns = biggest = 0
    with PcapReader(str(path)) as reader:
        for pkt in reader:
            total += 1
            if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
                continue
            seg = pkt[TCP]
            if server_port not in (seg.sport, seg.dport):
                continue
            tcp += 1
            size = len(seg.payload)
            to_server = seg.dport == server_port
            if to_server and (int(seg.flags) & (SYN | ACK)) == SYN:
                conns += 1
            if size:
                payload_pkts += 1
                biggest = max(biggest, size)
                if to_server:
                    c2s += size
                    tiny += size <= tiny_max
                else:
                    s2c += size
    return PcapSummary(str(path), total, tcp, c2s + s2c, c2s, s2c, payload_pkts, tiny, conns, biggest, tiny_max)


# ----------------------------------------------------------------------------- TLS records
@dataclass(frozen=True)
class TlsRecord:
    """One complete TLS record in a reassembled stream: `start` is its first byte (header), `length` its payload."""

    type: int
    start: int
    length: int

    @property
    def end(self) -> int:
        return self.start + 5 + self.length


def parse_tls_records(stream: bytes) -> list[TlsRecord]:
    """Split a reassembled TCP stream into complete TLS records (a trailing partial record is dropped)."""
    records, pos = [], 0
    while pos + 5 <= len(stream):
        length = int.from_bytes(stream[pos + 3:pos + 5], "big")
        if pos + 5 + length > len(stream):
            break
        records.append(TlsRecord(stream[pos], pos, length))
        pos += 5 + length
    return records


@dataclass(frozen=True)
class ServerHelloInfo:
    """Fields read from the cleartext ServerHello (None if absent or not parseable)."""

    group_id: int | None
    cipher_suite: int | None


def parse_server_hello(stream: bytes) -> ServerHelloInfo:
    """Selected key_share group id and cipher suite from the first handshake record of the server stream."""
    none = ServerHelloInfo(None, None)
    recs = parse_tls_records(stream)
    if not recs or recs[0].type != TLS_HANDSHAKE:
        return none
    body = stream[recs[0].start + 5:recs[0].end]
    if len(body) < 4 or body[0] != 2:               # handshake type 2 = ServerHello
        return none
    p = 4 + 2 + 32                                   # handshake header, legacy_version, random
    try:
        p += 1 + body[p]                             # legacy_session_id_echo
        cipher = int.from_bytes(body[p:p + 2], "big")
        p += 2 + 1                                   # cipher suite, compression method
        end = p + 2 + int.from_bytes(body[p:p + 2], "big")
        p += 2
        while p + 4 <= end:
            ext_type, ext_len = int.from_bytes(body[p:p + 2], "big"), int.from_bytes(body[p + 2:p + 4], "big")
            if ext_type == 0x0033 and ext_len >= 2:   # key_share: selected_group first
                return ServerHelloInfo(int.from_bytes(body[p + 4:p + 6], "big"), cipher)
            p += 4 + ext_len
        return ServerHelloInfo(None, cipher)
    except IndexError:
        return none


# ----------------------------------------------------------------------- TCP reassembly
@dataclass(frozen=True)
class _Seg:
    start: int      # offset in the reassembled stream
    length: int
    idx: int        # packet index in the capture (monotone with time; breaks timestamp ties)
    time: float


@dataclass
class _Direction:
    """One direction of a connection, reassembled by sequence number; duplicates are ignored."""

    isn: int | None = None
    next_off: int = 0
    data: bytearray = field(default_factory=bytearray)
    pending: dict[int, tuple[bytes, int, float]] = field(default_factory=dict)
    segs: list[_Seg] = field(default_factory=list)
    dups: int = 0

    def add(self, seq: int, payload: bytes, idx: int, t: float) -> None:
        if self.isn is None:
            return
        rel = (seq - self.isn - 1) & 0xFFFFFFFF      # the SYN consumes one sequence number
        if rel >= 1 << 31:                            # before the ISN: stale
            self.dups += 1
            return
        end = rel + len(payload)
        if end <= self.next_off:                      # pure retransmission
            self.dups += 1
        elif rel > self.next_off:                     # out of order: hold until the gap is filled
            if rel in self.pending:
                self.dups += 1
            else:
                self.pending[rel] = (payload, idx, t)
        else:
            self._append(payload[self.next_off - rel:], idx, t)
            self._drain()

    def _append(self, payload: bytes, idx: int, t: float) -> None:
        self.segs.append(_Seg(self.next_off, len(payload), idx, t))
        self.data += payload
        self.next_off += len(payload)

    def _drain(self) -> None:
        while self.pending:
            start = min(self.pending)
            if start > self.next_off:
                return
            payload, idx, t = self.pending.pop(start)
            if start + len(payload) > self.next_off:
                self._append(payload[self.next_off - start:], idx, t)
            else:
                self.dups += 1


@dataclass
class _Conn:
    client_ip: str
    client_port: int
    first_idx: int
    first_time: float
    last_time: float
    client: _Direction = field(default_factory=_Direction)
    server: _Direction = field(default_factory=_Direction)
    closed: bool = False
    max_payload: int = 0          # largest single TCP payload seen (raw packets, incl. retransmissions)
    pkts: list[tuple[float, bool, int]] = field(default_factory=list)   # every TCP packet: (time, to_server, payload bytes)


def _seg_at(segs: list[_Seg], offset: int) -> _Seg:
    """The segment whose bytes contain stream offset `offset`."""
    return segs[bisect.bisect_right([s.start for s in segs], offset) - 1]


# ------------------------------------------------------------------------------ features
def _stats(values: list[float]) -> tuple[float, float, float]:
    """(mean, population std, max) of a list; NaN each if empty."""
    if not values:
        return math.nan, math.nan, math.nan
    mean = sum(values) / len(values)
    return mean, math.sqrt(sum((v - mean) ** 2 for v in values) / len(values)), max(values)


def _first_sizes(prefix: str, sizes: list[int]) -> dict[str, float]:
    return {f"{prefix}_{i + 1}": (sizes[i] if i < len(sizes) else math.nan) for i in range(N_FIRST)}


def _client_split(conn: _Conn, boundary: int | None) -> tuple[list[int], list[tuple[int, float, int]]]:
    """Client segments -> (handshake payload sizes, application tuples (idx, time, size)).

    A segment that straddles the boundary contributes its handshake part to the first list and its
    application part to the second (so it counts as a packet in both phases).
    """
    hs: list[int] = []
    app: list[tuple[int, float, int]] = []
    for s in conn.client.segs:
        end = s.start + s.length
        if boundary is None or s.start < boundary:
            hs.append(min(end, boundary if boundary is not None else end) - s.start)
        if boundary is not None and end > boundary:
            app.append((s.idx, s.time, end - max(s.start, boundary)))
    return hs, app


def _phase_features(conn: _Conn) -> dict[str, Any]:
    c_recs, s_recs = parse_tls_records(bytes(conn.client.data)), parse_tls_records(bytes(conn.server.data))
    first_app = next((r for r in c_recs if r.type == TLS_APPDATA), None)
    boundary = first_app.end if first_app else None
    cut = _seg_at(conn.client.segs, boundary - 1) if boundary else None
    c_hs, c_app = _client_split(conn, boundary)
    s_hs = [s for s in conn.server.segs if cut is None or s.idx < cut.idx]
    s_app = [(s.idx, s.time, s.length) for s in conn.server.segs if cut is not None and s.idx >= cut.idx]
    hs_c2s, hs_s2c = sum(c_hs), sum(s.length for s in s_hs)
    app = sorted([(i, t, n, "c") for i, t, n in c_app] + [(i, t, n, "s") for i, t, n in s_app])
    times, sizes = [a[1] for a in app], [float(a[2]) for a in app]
    iats = [b - a for a, b in zip(times, times[1:])]
    size_mean, size_std, size_max = _stats(sizes)
    iat_mean, iat_std, iat_max = _stats(iats)
    c_sizes = [n for _, _, n, d in app if d == "c"]
    s_sizes = [n for _, _, n, d in app if d == "s"]
    return {
        "handshake_complete": cut is not None,
        "hs_c2s_bytes": hs_c2s, "hs_s2c_bytes": hs_s2c, "hs_c2s_pkts": len(c_hs), "hs_s2c_pkts": len(s_hs),
        "hs_duration": (cut.time if cut else conn.last_time) - conn.first_time,
        "hs_records": sum(r.end <= hs_c2s for r in c_recs) + sum(r.end <= hs_s2c for r in s_recs),
        "app_c2s_bytes": sum(c_sizes), "app_s2c_bytes": sum(s_sizes),
        "app_c2s_pkts": len(c_sizes), "app_s2c_pkts": len(s_sizes),
        "app_pkt_len_mean": size_mean, "app_pkt_len_std": size_std, "app_pkt_len_max": size_max,
        "app_iat_mean": iat_mean, "app_iat_std": iat_std, "app_iat_max": iat_max,
        "app_duration": (times[-1] - times[0]) if times else 0.0,
        "app_tiny_client_pkts": sum(1 <= n <= TINY_MAX for n in c_sizes),
        **_first_sizes("app_c2s_size", c_sizes), **_first_sizes("app_s2c_size", s_sizes),
        "total_bytes": len(conn.client.data) + len(conn.server.data),
        "total_pkts": len(conn.client.segs) + len(conn.server.segs),
        "flow_duration": conn.last_time - conn.first_time,
    }


def _flow_features(conn: _Conn) -> dict[str, Any]:
    """CICFlowMeter-like whole-connection view: ALL TCP packets of the connection (SYN, ACKs and FINs included,
    retransmissions included), both directions, in capture order. Length = TCP payload bytes (0 for pure ACKs);
    IAT = gap between consecutive packets of the connection. Std is the population std (ddof = 0)."""
    c2s = [n for _, to_server, n in conn.pkts if to_server]
    s2c = [n for _, to_server, n in conn.pkts if not to_server]
    lens = [float(n) for _, _, n in conn.pkts]
    times = [t for t, _, _ in conn.pkts]
    len_mean, len_std, len_max = _stats(lens)
    iat_mean, iat_std, iat_max = _stats([b - a for a, b in zip(times, times[1:])])
    return {
        "flow_c2s_bytes": sum(c2s), "flow_s2c_bytes": sum(s2c), "flow_c2s_pkts": len(c2s), "flow_s2c_pkts": len(s2c),
        "flow_pkt_len_mean": len_mean, "flow_pkt_len_std": len_std, "flow_pkt_len_max": len_max,
        "flow_iat_mean": iat_mean, "flow_iat_std": iat_std, "flow_iat_max": iat_max,
    }


def _connection_row(conn: _Conn) -> dict[str, Any]:
    hello = parse_server_hello(bytes(conn.server.data))
    return {
        "client_port": conn.client_port, "start_time": conn.first_time, "closed": conn.closed,
        "sh_group_id": hello.group_id, "sh_group_name": GROUP_NAMES.get(hello.group_id) if hello.group_id is not None else None,
        "sh_cipher_suite": hello.cipher_suite,
        **_phase_features(conn),
        **_flow_features(conn),
        "retransmitted_pkts": conn.client.dups + conn.server.dups,
    }


# --------------------------------------------------------------------------------- driver
def _split_connections(path: str | Path, server_port: int) -> list[_Conn]:
    active: dict[tuple[str, int, str], _Conn] = {}
    finished: list[_Conn] = []
    with PcapReader(str(path)) as reader:
        for idx, pkt in enumerate(reader):
            if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
                continue
            seg, ip = pkt[TCP], pkt[IP]
            if server_port not in (seg.sport, seg.dport):
                continue
            to_server, flags, t = seg.dport == server_port, int(seg.flags), float(pkt.time)
            key = (ip.src, seg.sport, ip.dst) if to_server else (ip.dst, seg.dport, ip.src)
            if to_server and flags & SYN and not flags & ACK:
                cur = active.get(key)
                if cur is not None and cur.client.isn == seg.seq:   # retransmitted SYN: same connection
                    cur.last_time = t
                    cur.pkts.append((t, True, 0))
                    continue
                if cur is not None:
                    finished.append(cur)
                new = _Conn(key[0], key[1], idx, t, t)
                new.client.isn = seg.seq
                new.pkts.append((t, True, 0))
                active[key] = new
                continue
            cur = active.get(key)
            if cur is None:                                         # no SYN seen for this tuple: ignore
                continue
            cur.last_time = t
            if not to_server and flags & SYN and flags & ACK:
                cur.server.isn = cur.server.isn if cur.server.isn is not None else seg.seq
                cur.pkts.append((t, False, 0))
                continue
            cur.closed = cur.closed or bool(flags & (FIN | RST))
            payload = bytes(seg.payload)
            cur.max_payload = max(cur.max_payload, len(payload))
            cur.pkts.append((t, to_server, len(payload)))
            if payload:
                (cur.client if to_server else cur.server).add(seg.seq, payload, idx, t)
    return sorted(finished + list(active.values()), key=lambda c: c.first_idx)


_SMOKE_ROW = re.compile(r"^(\w+)\s+(\w+)\s+\|\s+(\S+)\s+(\S+)\s+(\d+)\s+(\d+)/(\d+)\s+\|\s+(PASS|FAIL)\s*$", re.M)


def parse_smoke_output(text: str) -> dict[tuple[str, str], tuple[int, int, str]]:
    """Parse lab/smoke_test.sh output: {(kem, auth): (client bytes read, client bytes written, PASS|FAIL)}."""
    return {(m.group(2), m.group(1)): (int(m.group(6)), int(m.group(7)), m.group(8))
            for m in _SMOKE_ROW.finditer(text)}


def extract_connections(path: str | Path, server_port: int = 4433) -> list[dict[str, Any]]:
    """One feature dict per TCP connection to `server_port`, in order of connection start.

    Streaming (scapy PcapReader). Times are seconds, sizes are TCP payload bytes. See docs/pcap_method.md.
    """
    return [_connection_row(c) for c in _split_connections(path, server_port)]


def capture_checks(path: str | Path, server_port: int = 4433) -> tuple[int, int]:
    """(number of TCP connections, largest single TCP payload in any packet) for a capture, in one pass.

    The largest payload tells whether NIC offloads (GRO/GSO/TSO) were off while capturing: with an MTU of
    1500 a wire-sized segment carries at most 1460 payload bytes.
    """
    conns = _split_connections(path, server_port)
    return len(conns), max((c.max_payload for c in conns), default=0)
