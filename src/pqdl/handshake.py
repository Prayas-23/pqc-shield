"""Handshake size and flight modelling.

Analytical model of a TLS 1.3 / QUIC handshake. Units: sizes in bytes, times in
seconds, bandwidth in bytes/second. Nothing here is measured; every output is a
deterministic function of the profile and the overhead/network parameters.

Model:
    B_S = L_SH + L_EE + n_certs*(pk + sig + o_cert) + (sig + o_cv) + L_Fin
    B_C = ClientHello + client Finished
    N_S = ceil(B_S / MSS)
    R(B) = ceil(log2(1 + B / (W0 * MSS)))          (slow-start rounds)
    T_hs = R*RTT + (B_S + B_C)/BW + T_cpu
    QUIC amplification_flag = B_S > 3 * max(ClientHello_bytes, 1200)
    (B_C, which includes client Finished, is used only for T_hs.)
"""

from __future__ import annotations

from typing import Any

from pqdl.profiles import Overheads, Profile, auth_sizes, kem_sizes

DEFAULT_MSS = 1460
# Segment payload size in the lab captures: 1500-byte MTU - 40 (IP+TCP) - 12 (TCP timestamp option) = 1448.
# Use LAB_MSS (pass mss=LAB_MSS) when comparing the model with lab pcaps; DEFAULT_MSS assumes no TCP options.
LAB_MSS = 1448
DEFAULT_W0 = 10
QUIC_MIN_INITIAL = 1200
QUIC_AMPLIFICATION_FACTOR = 3


def _server_parts(profile: Profile, ov: Overheads) -> dict[str, int]:
    """Byte size of each server-flight message, in wire order."""
    _, server_share = kem_sizes(profile)
    pk, sig = auth_sizes(profile)
    return {
        "ServerHello": ov.sh_base + server_share,
        "EncryptedExtensions": ov.l_ee,
        "Certificate chain": profile.n_certs * (pk + sig + ov.o_cert),
        "CertificateVerify": sig + ov.o_cv,
        "server Finished": ov.l_fin,
    }


def server_flight_bytes(profile: Profile, ov: Overheads = Overheads()) -> int:
    """B_S: total bytes the server sends during the handshake."""
    return sum(_server_parts(profile, ov).values())


def client_hello_bytes(profile: Profile, ov: Overheads = Overheads()) -> int:
    """ClientHello size in bytes: ch_base + client key share."""
    client_share, _ = kem_sizes(profile)
    return ov.ch_base + client_share


def client_flight_bytes(profile: Profile, ov: Overheads = Overheads()) -> int:
    """B_C: ClientHello plus client Finished, in bytes (used by handshake_time only)."""
    return client_hello_bytes(profile, ov) + ov.l_fin


def n_packets(nbytes: int, mss: int = DEFAULT_MSS) -> int:
    """ceil(nbytes / mss) using exact integer arithmetic."""
    if nbytes < 0 or mss <= 0:
        raise ValueError("nbytes must be >= 0 and mss > 0")
    return -(-nbytes // mss)


def slow_start_rounds(nbytes: int, mss: int = DEFAULT_MSS, w0: int = DEFAULT_W0) -> int:
    """R(B) = ceil(log2(1 + B / (w0*mss))).

    Computed as the smallest integer R with (2**R - 1) * w0 * mss >= B, which is
    mathematically identical but avoids floating-point error at exact powers of two.
    """
    if nbytes < 0 or mss <= 0 or w0 <= 0:
        raise ValueError("nbytes must be >= 0; mss and w0 must be > 0")
    unit = w0 * mss
    rounds = 0
    while (2**rounds - 1) * unit < nbytes:
        rounds += 1
    return rounds


def handshake_time(
    profile: Profile,
    rtt: float,
    bw: float,
    t_cpu: float = 0.0,
    mss: int = DEFAULT_MSS,
    w0: int = DEFAULT_W0,
    ov: Overheads = Overheads(),
) -> float:
    """T_hs = R*RTT + (B_S + B_C)/BW + T_cpu.

    Units: rtt in seconds, bw in bytes/second, t_cpu in seconds; returns seconds.
    R is computed from the server flight B_S.
    """
    if rtt < 0 or bw <= 0 or t_cpu < 0:
        raise ValueError("rtt and t_cpu must be >= 0; bw must be > 0")
    b_s = server_flight_bytes(profile, ov)
    b_c = client_flight_bytes(profile, ov)
    return slow_start_rounds(b_s, mss, w0) * rtt + (b_s + b_c) / bw + t_cpu


def amplification_flag(profile: Profile, ov: Overheads = Overheads()) -> bool:
    """QUIC anti-amplification check: B_S > 3 * max(ClientHello_bytes, 1200).

    Uses the ClientHello size (the client's first datagram), not B_C, so the client
    Finished is excluded. Always False for non-QUIC transports, where the limit does
    not apply.
    """
    if profile.transport != "QUIC":
        return False
    b_s = server_flight_bytes(profile, ov)
    ch = client_hello_bytes(profile, ov)
    return b_s > QUIC_AMPLIFICATION_FACTOR * max(ch, QUIC_MIN_INITIAL)


def handshake_ladder(
    profile: Profile, mss: int = DEFAULT_MSS, ov: Overheads = Overheads()
) -> list[dict[str, Any]]:
    """Ordered handshake messages as {step, direction, bytes, packets}.

    `packets` is ceil(bytes / mss) for that message alone, so the per-step packet
    counts can sum to more than N_S (the real flight coalesces messages).
    """
    client_share, _ = kem_sizes(profile)
    steps: list[tuple[str, str, int]] = [("ClientHello", "C->S", ov.ch_base + client_share)]
    steps += [(name, "S->C", size) for name, size in _server_parts(profile, ov).items()]
    steps.append(("client Finished", "C->S", ov.l_fin))
    return [
        {"step": step, "direction": direction, "bytes": size, "packets": n_packets(size, mss)}
        for step, direction, size in steps
    ]
