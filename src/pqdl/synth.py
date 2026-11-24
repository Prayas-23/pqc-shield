"""SYNTHETIC data for unit tests only, never for reported results.

Small, seeded, clearly labelled SYNTHETIC tables so maths functions can be tested.
Every generated row carries source="SYNTHETIC".
"""

from __future__ import annotations

from typing import Mapping, Sequence

import numpy as np
import pandas as pd

SYNTHETIC_SOURCE = "SYNTHETIC"


def synthetic_groups(
    group_means: Mapping[str, Sequence[float]], n_per_group: int = 200, seed: int = 0,
    group_col: str = "group",
) -> pd.DataFrame:
    """SYNTHETIC frame: features f0, f1, ... ~ Normal(mean_of_group, 1); one block per group.

    `group_means` maps group name -> per-feature means (all the same length).
    """
    rng = np.random.default_rng(seed)
    frames = []
    for name, means in group_means.items():
        data = {f"f{i}": rng.normal(m, 1.0, n_per_group) for i, m in enumerate(means)}
        frames.append(pd.DataFrame({group_col: name, **data}))
    out = pd.concat(frames, ignore_index=True)
    out["source"] = SYNTHETIC_SOURCE
    return out


def synthetic_pqc_cells(
    cells: Sequence[tuple[str, str]], kem_effect: Mapping[str, float], auth_effect: Mapping[str, float],
    n_per_cell: int = 30, seed: int = 0,
) -> pd.DataFrame:
    """SYNTHETIC stand-in for CIC-PQC_OAV normal rows: one block of rows per (kem, auth) cell.

    Feature f0 = kem_effect[kem] + Normal(0, 1); feature f1 = auth_effect[auth] + Normal(0, 1).
    Columns: kem_scenario, auth_scenario, label_raw ('Normal'), f0, f1, source ('SYNTHETIC').
    """
    rng = np.random.default_rng(seed)
    frames = []
    for kem, auth in cells:
        frames.append(pd.DataFrame({
            "kem_scenario": kem, "auth_scenario": auth, "label_raw": "Normal",
            "f0": kem_effect[kem] + rng.normal(0.0, 1.0, n_per_cell),
            "f1": auth_effect[auth] + rng.normal(0.0, 1.0, n_per_cell),
        }))
    out = pd.concat(frames, ignore_index=True)
    out["source"] = SYNTHETIC_SOURCE
    return out


LAB_SYNTH_KEMS = ("X25519", "mlkem768", "X25519MLKEM768")
LAB_SYNTH_AUTHS = ("ecdsa_p256", "mldsa44", "mldsa65", "mldsa87")


def synthetic_lab_flows(n_per_cell: int = 12, seed: int = 0,
                        workloads: Sequence[str] = ("benign_web", "handshake_flood")) -> pd.DataFrame:
    """SYNTHETIC stand-in for data/flows/lab_flows.csv with PLANTED effects, for testing lab_drift only.

    Planted: hs_*_bytes/pkts/records are exact functions of the profile (deterministic); hs_duration depends on
    auth (plus noise); app_s2c_bytes depends on the KEM (a deliberate violation of application-phase invariance);
    every other app_* feature is identically distributed for all profiles. flow_s2c_bytes = hs + app bytes.
    Profiles: 3 KEM x 4 auth with chain leaf_int, plus chain leaf for two of them. Every row has source SYNTHETIC.
    """
    rng = np.random.default_rng(seed)
    profiles = [(k, a, "leaf_int") for k in LAB_SYNTH_KEMS for a in LAB_SYNTH_AUTHS]
    profiles += [("X25519", "ecdsa_p256", "leaf"), ("mlkem768", "mldsa65", "leaf")]
    frames = []
    for workload in workloads:
        for kem, auth, chain in profiles:
            ki, ai = LAB_SYNTH_KEMS.index(kem), LAB_SYNTH_AUTHS.index(auth)
            n = n_per_cell
            hs_s2c = 1500.0 + 800.0 * ki + 3000.0 * ai + (600.0 if chain == "leaf_int" else 0.0)
            hs_duration = 0.002 + 0.0003 * ai + rng.normal(0.0, 0.0002, n)
            app_c2s, app_s2c = rng.normal(70, 5, n), rng.normal(10000, 500, n) + 4000.0 * ki
            app_duration = np.abs(rng.normal(0.01, 0.002, n))
            data: dict[str, object] = {
                "source": SYNTHETIC_SOURCE, "kem": kem, "auth": auth, "chain": chain, "workload": workload,
                "label": "benign" if workload.startswith("benign") else "attack",
                "pcap_file": f"SYNTHETIC_{kem}_{auth}_{chain}_{workload}.pcap", "capture_offload_ok": True,
                "hs_c2s_bytes": 1000.0 + 400.0 * ki, "hs_s2c_bytes": hs_s2c, "hs_c2s_pkts": 2.0 + ki,
                "hs_s2c_pkts": float(np.ceil(hs_s2c / 1448.0)), "hs_duration": hs_duration, "hs_records": 9.0,
                "app_c2s_bytes": app_c2s, "app_s2c_bytes": app_s2c, "app_c2s_pkts": rng.normal(20, 2, n),
                "app_s2c_pkts": rng.normal(20, 2, n), "app_pkt_len_mean": rng.normal(500, 30, n),
                "app_pkt_len_std": rng.normal(200, 20, n), "app_pkt_len_max": rng.normal(1448, 10, n),
                "app_iat_mean": np.abs(rng.normal(0.001, 0.0002, n)), "app_iat_std": np.abs(rng.normal(0.001, 0.0002, n)),
                "app_iat_max": np.abs(rng.normal(0.004, 0.001, n)), "app_duration": app_duration,
                "app_tiny_client_pkts": rng.normal(2, 0.5, n),
                "flow_c2s_bytes": 1000.0 + 400.0 * ki + app_c2s, "flow_s2c_bytes": hs_s2c + app_s2c,
                "flow_c2s_pkts": rng.normal(25, 3, n), "flow_s2c_pkts": rng.normal(30, 3, n),
                "flow_pkt_len_mean": rng.normal(400, 30, n), "flow_pkt_len_std": rng.normal(500, 30, n),
                "flow_pkt_len_max": rng.normal(1448, 10, n), "flow_iat_mean": np.abs(rng.normal(0.0005, 0.0001, n)),
                "flow_iat_std": np.abs(rng.normal(0.001, 0.0002, n)), "flow_iat_max": np.abs(rng.normal(0.003, 0.0005, n)),
                "flow_duration": hs_duration + app_duration,
            }
            for k in range(1, 11):               # first-ten packet sizes: only the first two exist
                data[f"app_c2s_size_{k}"] = rng.normal(500, 20, n) if k <= 2 else np.nan
                data[f"app_s2c_size_{k}"] = rng.normal(1448, 5, n) if k <= 2 else np.nan
            frames.append(pd.DataFrame(data))
    return pd.concat(frames, ignore_index=True)
