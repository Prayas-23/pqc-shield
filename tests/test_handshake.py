import math

import pytest

from pqdl.handshake import (
    amplification_flag,
    client_flight_bytes,
    client_hello_bytes,
    handshake_ladder,
    handshake_time,
    n_packets,
    server_flight_bytes,
    slow_start_rounds,
)
from pqdl.profiles import Overheads, Profile

CLASSICAL = Profile("X25519", "ECDSA-P256", "TCP")
PQ_SIG = Profile("X25519", "MLDSA44", "TCP")


# --- Values specified by the user (hand-computed) --------------------------------------
def test_classical_profile_user_values() -> None:
    b_s = server_flight_bytes(CLASSICAL)
    assert b_s == 596
    assert n_packets(b_s) == 1
    assert slow_start_rounds(b_s) == 1


def test_mldsa44_server_flight_user_value() -> None:
    assert server_flight_bytes(PQ_SIG) == 10160


def test_mldsa65_user_values() -> None:
    b_s = server_flight_bytes(Profile("X25519", "MLDSA65", "TCP"))
    assert b_s == 14107
    assert n_packets(b_s) == 10
    assert slow_start_rounds(b_s) == 1


def test_slhdsa128s_user_values() -> None:
    b_s = server_flight_bytes(Profile("X25519", "SLHDSA128s", "TCP"))
    assert b_s == 23908
    assert n_packets(b_s) == 17
    assert slow_start_rounds(b_s) == 2


# --- Additional hand-computed values (added by the assistant; please verify) -----------
def test_mldsa44_packets_and_rounds() -> None:
    # ceil(10160 / 1460) = 7 (6*1460 = 8760 < 10160 <= 10220); 1 + 10160/14600 < 2 -> R = 1
    b_s = server_flight_bytes(PQ_SIG)
    assert n_packets(b_s) == 7
    assert slow_start_rounds(b_s) == 1


def test_client_flight_classical() -> None:
    assert client_flight_bytes(CLASSICAL) == 250 + 32 + 36  # 318


def test_client_flight_hybrid_kem() -> None:
    assert client_flight_bytes(Profile("X25519MLKEM768", "ECDSA-P256", "TCP")) == 250 + 1216 + 36


def test_handshake_time_classical() -> None:
    # R=1, B_S+B_C = 596+318 = 914: 1*0.05 + 914/1e6 + 0.001
    t = handshake_time(CLASSICAL, rtt=0.05, bw=1_000_000.0, t_cpu=0.001)
    assert t == pytest.approx(0.051914)


# --- Maths helpers ---------------------------------------------------------------------
@pytest.mark.parametrize(
    ("nbytes", "expected"),
    [(0, 0), (1, 1), (1460, 1), (1461, 2), (2920, 2), (2921, 3)],
)
def test_n_packets(nbytes: int, expected: int) -> None:
    assert n_packets(nbytes) == expected


@pytest.mark.parametrize(
    ("nbytes", "expected"),
    [(0, 0), (1, 1), (14600, 1), (14601, 2), (43800, 2), (43801, 3)],
)
def test_slow_start_rounds_boundaries(nbytes: int, expected: int) -> None:
    assert slow_start_rounds(nbytes) == expected


@pytest.mark.parametrize("nbytes", [1, 596, 10160, 14600, 20000, 50000, 123456])
def test_slow_start_rounds_matches_log2_formula(nbytes: int) -> None:
    assert slow_start_rounds(nbytes) == math.ceil(math.log2(1 + nbytes / (10 * 1460)))


def test_invalid_inputs_raise() -> None:
    with pytest.raises(ValueError):
        n_packets(-1)
    with pytest.raises(ValueError):
        slow_start_rounds(-1)
    with pytest.raises(ValueError):
        handshake_time(CLASSICAL, rtt=0.05, bw=0.0)
    with pytest.raises(ValueError):
        Profile("NOPE", "ECDSA-P256", "TCP")


# --- QUIC amplification ----------------------------------------------------------------
def test_amplification_flag() -> None:
    # 596 > 3*1200 is False; 10160 > 3600 is True
    assert amplification_flag(Profile("X25519", "ECDSA-P256", "QUIC")) is False
    assert amplification_flag(Profile("X25519", "MLDSA44", "QUIC")) is True


def test_amplification_uses_client_hello_not_b_c() -> None:
    # Hybrid KEM: ClientHello = 250 + 1216 = 1466 (> 1200); B_C = 1466 + 36 = 1502.
    # o_cert=1423 tunes B_S = 90+1120 + 30 + 2*(64+64+1423) + (64+8) + 36 = 4450.
    # ClientHello rule: 4450 > 3*1466 = 4398 -> True.  B_C rule would give 4450 > 4506 -> False.
    profile = Profile("X25519MLKEM768", "ECDSA-P256", "QUIC")
    ov = Overheads(o_cert=1423)
    assert client_hello_bytes(profile, ov) == 1466
    assert client_flight_bytes(profile, ov) == 1502
    assert server_flight_bytes(profile, ov) == 4450
    assert 4450 <= 3 * client_flight_bytes(profile, ov)  # the old B_C rule would say False
    assert amplification_flag(profile, ov) is True


def test_amplification_floor_of_1200_applies_to_small_client_hello() -> None:
    # ClientHello = 282 < 1200, so the limit is 3*1200 = 3600. Tune B_S to 3600 / 3601.
    # Classical B_S = 596 + 2*(o_cert-40); o_cert=1542 -> 3600, o_cert=1543 -> 3602.
    profile = Profile("X25519", "ECDSA-P256", "QUIC")
    assert server_flight_bytes(profile, Overheads(o_cert=1542)) == 3600
    assert amplification_flag(profile, Overheads(o_cert=1542)) is False
    assert amplification_flag(profile, Overheads(o_cert=1543)) is True


def test_amplification_flag_false_for_tcp() -> None:
    assert amplification_flag(PQ_SIG) is False


# --- Ladder ----------------------------------------------------------------------------
def test_ladder_order_and_directions() -> None:
    ladder = handshake_ladder(CLASSICAL)
    assert [s["step"] for s in ladder] == [
        "ClientHello",
        "ServerHello",
        "EncryptedExtensions",
        "Certificate chain",
        "CertificateVerify",
        "server Finished",
        "client Finished",
    ]
    assert [s["direction"] for s in ladder] == ["C->S"] + ["S->C"] * 5 + ["C->S"]


@pytest.mark.parametrize("profile", [CLASSICAL, PQ_SIG, Profile("MLKEM768", "SLHDSA128s", "QUIC", 3)])
def test_ladder_bytes_sum_to_flights(profile: Profile) -> None:
    ladder = handshake_ladder(profile)
    server = sum(s["bytes"] for s in ladder if s["direction"] == "S->C")
    client = sum(s["bytes"] for s in ladder if s["direction"] == "C->S")
    assert server == server_flight_bytes(profile)
    assert client == client_flight_bytes(profile)


def test_ladder_packets_are_per_step_ceil() -> None:
    cert = next(s for s in handshake_ladder(PQ_SIG) if s["step"] == "Certificate chain")
    assert cert["bytes"] == 7544
    assert cert["packets"] == 6  # ceil(7544 / 1460)


def test_overheads_are_configurable() -> None:
    ov = Overheads(l_ee=0, o_cert=0, o_cv=0, l_fin=0, sh_base=0, ch_base=0)
    assert server_flight_bytes(CLASSICAL, ov) == 32 + 2 * (64 + 64) + 64
    assert client_flight_bytes(CLASSICAL, ov) == 32


def test_lab_mss_changes_the_packet_count_for_a_16kb_flight() -> None:
    # A 15,976-byte server flight (the size OpenSSL reported for mlkem768 + mldsa65 in the lab).
    # Hand check: 11 * 1448 = 15,928 < 15,976 <= 12 * 1448 = 17,376 -> 12 packets;
    #             10 * 1460 = 14,600 < 15,976 <= 11 * 1460 = 16,060 -> 11 packets with the default MSS.
    from pqdl.handshake import LAB_MSS

    assert LAB_MSS == 1448
    assert n_packets(15976, mss=LAB_MSS) == 12
    assert n_packets(15976) == 11
