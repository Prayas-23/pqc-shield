"""CANON v0: correction of handshake-induced drift for detectors that cannot isolate the handshake.

Design: docs/canon_design.md (frozen before any CANON result). CANON sees only V_FLOW features plus the early-packet
CONTEXT_FEATURES; the context features go to the context estimator only, never to a detector.

* context = profile "kem|auth|chain" (18 classes); estimated by a RandomForest on CONTEXT_FEATURES (c-hat).
* CANON-A: subtract the handshake byte / packet-count DIFFERENCE predicted by pqdl.handshake (mss = LAB_MSS) from the
  driver feature groups. No PQ data enters the correction.
* CANON-B: per-context additive location shift fitted on k benign calibration flows, plus a per-context split-conformal
  threshold tau_c = ceil((n+1)(1-alpha))-th smallest calibration score (+inf if that rank exceeds n).
"""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

from pqdl.features import CONTEXT_FEATURES
from pqdl.handshake import LAB_MSS, client_flight_bytes, n_packets, server_flight_bytes
from pqdl.profiles import Profile

CLASSICAL_CONTEXT = "X25519|ecdsa_p256|leaf_int"
ALPHA = 0.05
KEM_MAP = {"X25519": "X25519", "mlkem768": "MLKEM768", "X25519MLKEM768": "X25519MLKEM768"}
AUTH_MAP = {"ecdsa_p256": "ECDSA-P256", "mldsa44": "MLDSA44", "mldsa65": "MLDSA65", "mldsa87": "MLDSA87"}
CHAIN_CERTS = {"leaf": 1, "leaf_int": 2}

# Feature groups of V_FLOW used by the attribution protocol and the corrections.
GROUPS: dict[str, tuple[str, ...]] = {
    "bytes": ("flow_c2s_bytes", "flow_s2c_bytes"),
    "pkts": ("flow_c2s_pkts", "flow_s2c_pkts"),
    "pktlen": ("flow_pkt_len_mean", "flow_pkt_len_std", "flow_pkt_len_max"),
    "time": ("flow_iat_mean", "flow_iat_std", "flow_iat_max", "flow_duration"),
}


def group_features(groups: Sequence[str]) -> list[str]:
    """All V_FLOW feature names of the given groups, in group order."""
    unknown = [g for g in groups if g not in GROUPS]
    if unknown:
        raise ValueError(f"unknown feature groups {unknown}")
    return [f for g in groups for f in GROUPS[g]]


# --------------------------------------------------------------------------- CANON-A
def context_profile(context: str) -> Profile:
    """Map a lab context string 'kem|auth|chain' to a size-model Profile (TCP)."""
    kem, auth, chain = context.split("|")
    return Profile(KEM_MAP[kem], AUTH_MAP[auth], "TCP", CHAIN_CERTS[chain])


@dataclass(frozen=True)
class HandshakeDelta:
    """Model-predicted handshake difference of a context relative to the reference context (bytes / packets)."""
    s2c_bytes: int
    c2s_bytes: int
    s2c_pkts: int
    c2s_pkts: int


def handshake_delta(context: str, reference: str = CLASSICAL_CONTEXT, mss: int = LAB_MSS) -> HandshakeDelta:
    """Differences only: B_S, B_C and their packet counts at `mss`, context minus reference."""
    p, r = context_profile(context), context_profile(reference)
    bs_p, bs_r = server_flight_bytes(p), server_flight_bytes(r)
    bc_p, bc_r = client_flight_bytes(p), client_flight_bytes(r)
    return HandshakeDelta(bs_p - bs_r, bc_p - bc_r, n_packets(bs_p, mss) - n_packets(bs_r, mss),
                          n_packets(bc_p, mss) - n_packets(bc_r, mss))


def correct_a(flows: pd.DataFrame, contexts: Sequence[str], groups: Sequence[str]) -> pd.DataFrame:
    """CANON-A: return a copy of the V_FLOW columns of `flows` corrected for the handshake difference of each flow's
    context. `groups` lists the corrected groups: 'bytes', 'pkts' and/or 'pktlen' (mean only, recomputed). 'time'
    is never corrected (no validated model). Counts are floored at 0."""
    if "time" in groups:
        raise ValueError("CANON-A has no timing model; 'time' cannot be corrected")
    out = flows.copy()
    ctx = np.asarray(contexts, dtype=object)
    if len(ctx) != len(out):
        raise ValueError("one context per flow required")
    deltas = {c: handshake_delta(c) for c in set(ctx)}
    col = lambda f: np.array([getattr(deltas[c], f) for c in ctx], dtype=float)   # noqa: E731
    if "bytes" in groups:
        out["flow_s2c_bytes"] = np.maximum(out["flow_s2c_bytes"].to_numpy(float) - col("s2c_bytes"), 0.0)
        out["flow_c2s_bytes"] = np.maximum(out["flow_c2s_bytes"].to_numpy(float) - col("c2s_bytes"), 0.0)
    if "pkts" in groups:
        out["flow_s2c_pkts"] = np.maximum(out["flow_s2c_pkts"].to_numpy(float) - col("s2c_pkts"), 0.0)
        out["flow_c2s_pkts"] = np.maximum(out["flow_c2s_pkts"].to_numpy(float) - col("c2s_pkts"), 0.0)
    if "pktlen" in groups:
        tot_b = out["flow_c2s_bytes"].to_numpy(float) + out["flow_s2c_bytes"].to_numpy(float)
        tot_p = out["flow_c2s_pkts"].to_numpy(float) + out["flow_s2c_pkts"].to_numpy(float)
        mean = np.divide(tot_b, tot_p, out=out["flow_pkt_len_mean"].to_numpy(float).copy(), where=tot_p > 0)
        out["flow_pkt_len_mean"] = mean
    return out


# --------------------------------------------------------------------------- context estimator
def fit_context_estimator(train: pd.DataFrame, seed: int = 0) -> RandomForestClassifier:
    """RandomForest (300 trees) on CONTEXT_FEATURES predicting the profile string. Training blocks only."""
    if "block" in train.columns and not (train["block"] == "train").all():
        raise ValueError("the context estimator may only be trained on the train block")
    y = train["kem"] + "|" + train["auth"] + "|" + train["chain"]
    X = np.nan_to_num(train[list(CONTEXT_FEATURES)].to_numpy(float), nan=0.0)
    return RandomForestClassifier(n_estimators=300, random_state=seed, n_jobs=1).fit(X, y)


def predict_context(model: RandomForestClassifier, df: pd.DataFrame) -> np.ndarray:
    return model.predict(np.nan_to_num(df[list(CONTEXT_FEATURES)].to_numpy(float), nan=0.0))


def confusion(true: Sequence[str], pred: Sequence[str], labels: Sequence[str]) -> pd.DataFrame:
    """Confusion matrix (rows true, columns predicted) over `labels`, plus nothing else."""
    t, p = pd.Categorical(list(true), categories=list(labels)), pd.Categorical(list(pred), categories=list(labels))
    return pd.crosstab(t, p, dropna=False).rename_axis(index="true", columns="predicted")


# --------------------------------------------------------------------------- CANON-B
def conformal_rank(n: int, alpha: float = ALPHA) -> int:
    """ceil((n + 1)(1 - alpha)); computed with a small tolerance so exact products do not round up."""
    return int(math.ceil((n + 1) * (1.0 - alpha) - 1e-9))


def conformal_threshold(scores: np.ndarray, alpha: float = ALPHA) -> float:
    """The conformal_rank-th smallest score; +inf when the rank exceeds the number of calibration scores."""
    s = np.sort(np.asarray(scores, dtype=float))
    r = conformal_rank(len(s), alpha)
    return float(s[r - 1]) if 1 <= r <= len(s) else float("inf")


def location_shift(calibration: pd.DataFrame, reference: pd.DataFrame, cols: Sequence[str]) -> np.ndarray:
    """g_j(c): median of each column over the calibration flows minus its median over the classical reference flows."""
    return calibration[list(cols)].median().to_numpy(float) - reference[list(cols)].median().to_numpy(float)


def residualise(flows: pd.DataFrame, contexts: Sequence[str], shifts: Mapping[str, np.ndarray],
                cols: Sequence[str]) -> pd.DataFrame:
    """CANON-B: subtract each flow's context shift from the `cols` columns (other columns untouched)."""
    out = flows.copy()
    ctx = np.asarray(contexts, dtype=object)
    missing = set(ctx) - set(shifts)
    if missing:
        raise KeyError(f"no calibration shift for contexts {sorted(missing)}")
    sub = out[list(cols)].to_numpy(float) - np.stack([shifts[c] for c in ctx])
    out[list(cols)] = sub
    return out


def calibration_draw(benign_val: pd.DataFrame, k: int, seed: int) -> pd.DataFrame:
    """k benign validation flows of one context: first k of a seeded permutation (so draws are nested in k)."""
    if (benign_val["attack"]).any():
        raise ValueError("calibration flows must be benign")
    if k > len(benign_val):
        raise ValueError(f"need {k} calibration flows, only {len(benign_val)} available")
    order = np.random.default_rng(seed).permutation(len(benign_val))
    return benign_val.iloc[order[:k]]
