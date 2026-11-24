"""SYNTHETIC fixture for the API tests: a tiny results folder and a tiny lab-flows file. Nothing here is a real result.

Every file name and every `source` column says SYNTHETIC. The numbers are invented round values chosen so that the tests
can check arithmetic (e.g. the pqmix formula); they must never be quoted anywhere.
"""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd

from api.config import ApiConfig
from pqdl import detectors as dt

P0 = "X25519|ecdsa_p256|leaf_int"          # classical reference profile
P1 = "mlkem768|mldsa65|leaf_int"
N_PER = {"benign_web": 300, "benign_api": 300, "handshake_flood": 200, "slow_send": 50}
FPR = {(P0, "any"): 0.02, (P1, "naive"): 0.90, (P1, "naive_app"): 0.03, (P1, "canon_b_k100_true"): 0.04,
       (P1, "canon_bs_k120_true"): 0.05, (P1, "any"): 0.10}
HS = {P0: (1441, 274), P1: (15976, 1418)}


def synthetic_fpr(profile: str, method: str) -> float:
    return FPR.get((profile, method), FPR[(profile, "any")])


def make_flows(seed: int = 0) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    rows, t = [], 1_000_000.0
    for profile in (P0, P1):
        kem, auth, chain = profile.split("|")
        for wl, n in N_PER.items():
            attack = wl in dt.ATTACK_WORKLOADS
            vals = rng.normal(30.0 if attack else 10.0, 1.0, size=(n, len(dt.V_FLOW)))
            if profile == P1:
                for c in ("flow_c2s_bytes", "flow_s2c_bytes"):
                    vals[:, list(dt.V_FLOW).index(c)] += 50.0
            for i in range(n):
                t += 0.01
                row = {"source": "SYNTHETIC", "kem": kem, "auth": auth, "chain": chain, "workload": wl,
                       "label": "attack" if attack else "benign", "pcap_file": f"SYNTHETIC_{kem}_{wl}.pcap",
                       "conn_index": i, "start_time": t, "hs_s2c_bytes": HS[profile][0] + int(rng.integers(0, 3)),
                       "hs_c2s_bytes": HS[profile][1]}
                row.update(dict(zip(dt.V_FLOW, vals[i])))
                rows.append(row)
    df = pd.DataFrame(rows)
    for c in dt.V_APP:
        if c not in df.columns:
            df[c] = rng.normal(5.0, 1.0, size=len(df)) + np.where(df["label"] == "attack", 20.0, 0.0)
    return df


def _result_rows(methods: list[str]) -> pd.DataFrame:
    rows = []
    for profile in (P0, P1):
        kem, auth, chain = profile.split("|")
        for det in dt.DETECTORS:
            for m in methods:
                for metric, base in (("fpr", synthetic_fpr(profile, m)), ("tpr_all", 0.95), ("auroc", 0.99)):
                    rows.append({"dataset": "main", "profile": profile, "kem": kem, "auth": auth, "chain": chain,
                                 "detector": det, "method": m, "view": "V_FLOW", "metric": metric, "value": base,
                                 "seed_sd": 0.001, "ci_lo": base - 0.01, "ci_hi": base + 0.01, "n_benign": 240,
                                 "n_attack": 100, "source": "SYNTHETIC"})
    return pd.DataFrame(rows)


def build(tmp_path: Path, eager_train: bool = False) -> ApiConfig:
    root = tmp_path / "SYNTHETIC_project"
    results = root / "SYNTHETIC_results"
    results.mkdir(parents=True)
    _result_rows(["naive", "naive_app", "oracle", "pooled"]).to_csv(results / "detector_baseline.csv", index=False)
    _result_rows(["canon_a_true", "canon_b_k100_true", "canon_bs_k120_true"]).to_csv(results / "canon_eval.csv", index=False)
    drift = pd.DataFrame([
        {"test": "H1_handshake_two_way", "workload": "benign_web", "feature": "hs_s2c_bytes", "ref_group": "", "compared_group": "",
         "term": "kem", "design": "two_way", "eta2": 0.9, "partial_eta2": 0.95, "psi": None, "mmd2": None, "mmd2_p_value": None,
         "noise95_eta2": 0.01, "noise95_max_psi": None, "n_ref": None, "n_group": None, "deterministic": True, "note": "SYNTHETIC"},
        {"test": "H3_app_invariance", "workload": "benign_web", "feature": "app_c2s_bytes", "ref_group": P0, "compared_group": P1,
         "term": None, "design": None, "eta2": 0.0, "partial_eta2": None, "psi": 0.0, "mmd2": 0.004, "mmd2_p_value": None,
         "noise95_eta2": 0.005, "noise95_max_psi": 0.05, "n_ref": 300, "n_group": 300, "deterministic": None, "note": "SYNTHETIC"},
        {"test": "H4_flow_features", "workload": "slow_send", "feature": "flow_s2c_bytes", "ref_group": P0, "compared_group": P1,
         "term": None, "design": None, "eta2": 0.5, "partial_eta2": None, "psi": 2.0, "mmd2": 0.3, "mmd2_p_value": 0.001,
         "noise95_eta2": 0.01, "noise95_max_psi": 0.2, "n_ref": 50, "n_group": 50, "deterministic": None, "note": "SYNTHETIC"},
    ])
    drift.to_csv(results / "lab_drift.csv", index=False)
    pd.DataFrame([{"detector": "rf", "profile": P1, "method": "naive", "n_capture_sets": 4, "mean_fpr": 0.88,
                   "sd_across_pcaps": 0.02, "min": 0.85, "max": 0.91, "main_fpr": 0.9, "flow_ci_lo": 0.89, "flow_ci_hi": 0.91,
                   "flow_se": 0.005, "sd_over_flow_se": 4.0, "flow_ci_understates": True}]).to_csv(results / "stats_pcap_level.csv", index=False)
    pd.DataFrame([{"auth": "ecdsa_p256", "o_cert": 405.0}, {"auth": "mldsa65", "o_cert": 392.0}]).to_csv(results / "cert_overhead.csv", index=False)
    flows_path = root / "SYNTHETIC_lab_flows.csv"
    make_flows().to_csv(flows_path, index=False)
    return ApiConfig(results_dir=results, flows_path=flows_path, root=root, synthetic=True, eager_train=eager_train)
