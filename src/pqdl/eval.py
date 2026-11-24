"""Evaluation.

Compares model predictions with observations and (later) computes detector metrics before and
after drift and before and after CANON, with confidence intervals and fixed seeds, writing
re-runnable results under results/.

Currently: arithmetic for checking the handshake size model against observed size differences.
All functions are pure; nothing here is measured or hard-coded.
"""

from __future__ import annotations

import math
from dataclasses import replace
from typing import Callable, Sequence

from pqdl.handshake import client_flight_bytes, server_flight_bytes
from pqdl.profiles import Profile


def residual(observed: float, predicted: float) -> float:
    """observed - predicted."""
    return observed - predicted


def residual_pct(observed: float, predicted: float) -> float:
    """100 * (observed - predicted) / observed; NaN if observed == 0."""
    return 100.0 * (observed - predicted) / observed if observed != 0 else math.nan


def predicted_delta(fixed: float, per_cert: float, n_certs: float) -> float:
    """Model delta for a given certificate count: fixed + n_certs * per_cert."""
    return fixed + n_certs * per_cert


def solve_n_certs(observed_delta: float, fixed: float, per_cert: float) -> float:
    """The (real-valued) n_certs for which the model delta equals the observed delta.

    Solves observed = fixed + n * per_cert. NaN if per_cert == 0 (n is then not identifiable).
    """
    return (observed_delta - fixed) / per_cert if per_cert != 0 else math.nan


def best_n_certs(observed_delta: float, fixed: float, per_cert: float,
                 candidates: Sequence[int] = (1, 2, 3)) -> int:
    """Candidate n_certs with the smallest absolute residual for one cell (ties: the smaller n)."""
    return min(candidates, key=lambda n: (abs(residual(observed_delta, predicted_delta(fixed, per_cert, n))), n))


def best_n_certs_global(observed: Sequence[float], fixed: Sequence[float], per_cert: Sequence[float],
                        candidates: Sequence[int] = (1, 2, 3)) -> int:
    """One candidate n_certs shared by all cells, minimising the sum of squared residuals."""
    def sse(n: int) -> float:
        return sum(residual(o, predicted_delta(f, p, n)) ** 2 for o, f, p in zip(observed, fixed, per_cert))
    return min(candidates, key=lambda n: (sse(n), n))


def model_delta_terms(profile: Profile, reference: Profile, size_fn: Callable[[Profile], int]) -> tuple[float, float]:
    """Split the model's size difference (profile - reference) into (fixed, per_cert).

    The model is linear in n_certs, so delta(n) = fixed + n * per_cert with fixed = delta(0) and
    per_cert = delta(1) - delta(0). Both profiles use the same n_certs. `size_fn` is e.g.
    server_flight_bytes, or server plus client flight bytes (see total_flight_bytes).
    """
    def delta(n: int) -> int:
        return size_fn(replace(profile, n_certs=n)) - size_fn(replace(reference, n_certs=n))
    d0, d1 = delta(0), delta(1)
    return float(d0), float(d1 - d0)


def total_flight_bytes(profile: Profile) -> int:
    """B_S + B_C from the handshake model."""
    return server_flight_bytes(profile) + client_flight_bytes(profile)
