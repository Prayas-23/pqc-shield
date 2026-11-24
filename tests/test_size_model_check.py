"""Arithmetic behind scripts/size_model_check.py, on hand-built fixtures (no real data)."""

import math

import pytest

from pqdl.eval import (
    best_n_certs,
    best_n_certs_global,
    model_delta_terms,
    predicted_delta,
    residual,
    residual_pct,
    solve_n_certs,
    total_flight_bytes,
)
from pqdl.handshake import client_flight_bytes, server_flight_bytes
from pqdl.profiles import Profile

REF = Profile("X25519", "ECDSA-P256", "TCP")
P384 = Profile("X25519", "ECDSA-P384", "TCP")


def test_new_sizes_entries_are_usable() -> None:
    for kem, auth in (("MLKEM1024", "MLDSA87"), ("X25519", "RSA3072"), ("X25519", "ECDSA-P384")):
        assert server_flight_bytes(Profile(kem, auth, "TCP")) > 0


def test_model_delta_terms_hand_computed() -> None:
    # P384 vs P256, same kem. B_S = c0 + n*(pk+sig+o_cert) with c0 containing (sig + o_cv):
    #   fixed = sig diff = 96 - 64 = 32;  per_cert = (96+96) - (64+64) = 64.
    # n=2: B_S(P384) = 122+30+2*232+104+36 = 756, B_S(REF) = 596, delta = 160 = 32 + 2*64.
    fixed, per_cert = model_delta_terms(P384, REF, server_flight_bytes)
    assert (fixed, per_cert) == (32.0, 64.0)
    assert server_flight_bytes(Profile("X25519", "ECDSA-P384", "TCP", 2)) - server_flight_bytes(
        Profile("X25519", "ECDSA-P256", "TCP", 2)) == 160 == predicted_delta(fixed, per_cert, 2)


def test_total_delta_adds_client_side_difference() -> None:
    # Same kem on both sides, so the client flight does not change: total delta == server delta.
    assert model_delta_terms(P384, REF, total_flight_bytes) == model_delta_terms(P384, REF, server_flight_bytes)
    # Different kem: client flight differs by the client share difference (1184 - 32 = 1152) at any n.
    ml = Profile("MLKEM768", "ECDSA-P256", "TCP")
    assert client_flight_bytes(ml) - client_flight_bytes(REF) == 1152
    fixed_total, per_cert_total = model_delta_terms(ml, REF, total_flight_bytes)
    fixed_server, per_cert_server = model_delta_terms(ml, REF, server_flight_bytes)
    assert per_cert_total == per_cert_server == 0.0
    assert fixed_total - fixed_server == 1152


def test_residual_and_percent() -> None:
    assert residual(160.0, 150.0) == 10.0
    assert residual_pct(160.0, 150.0) == pytest.approx(100 * 10 / 160)
    assert residual(-20.0, -10.0) == -10.0
    assert residual_pct(-20.0, -10.0) == pytest.approx(50.0)  # (-20 - -10) / -20 * 100
    assert math.isnan(residual_pct(0.0, 5.0))


def test_solve_n_certs_recovers_known_n() -> None:
    # observed delta built from n = 2: 32 + 2*64 = 160  ->  n = (160 - 32) / 64 = 2
    assert solve_n_certs(160.0, 32.0, 64.0) == pytest.approx(2.0)
    assert solve_n_certs(160.0 + 32.0, 32.0, 64.0) == pytest.approx(2.5)  # not forced to an integer
    assert math.isnan(solve_n_certs(10.0, 5.0, 0.0))  # per-cert term 0: n not identifiable


def test_best_n_certs_picks_smallest_residual() -> None:
    assert best_n_certs(160.0, 32.0, 64.0) == 2
    assert best_n_certs(160.0 + 20.0, 32.0, 64.0) == 2  # noisy but closest to n = 2
    assert best_n_certs(224.0, 32.0, 64.0, candidates=(1, 2, 3)) == 3
    assert best_n_certs(0.0, 0.0, 0.0) == 1  # tie -> smaller n


def test_best_n_certs_global_uses_all_cells() -> None:
    fixed, per_cert = [32.0, 10.0, 5.0], [64.0, 20.0, 8.0]
    observed = [predicted_delta(f, p, 3) for f, p in zip(fixed, per_cert)]
    assert best_n_certs_global(observed, fixed, per_cert) == 3
    assert best_n_certs_global([predicted_delta(f, p, 1) for f, p in zip(fixed, per_cert)], fixed, per_cert) == 1
