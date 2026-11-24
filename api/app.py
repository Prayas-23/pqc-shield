"""FastAPI application factory. READ-ONLY: GET routes and one replay WebSocket over stored results.

Nothing here recomputes a research result on request, captures traffic, runs a shell command or writes a file.
Every JSON response carries a `provenance` block.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from typing import Literal

import pandas as pd
from fastapi import FastAPI, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

import pqdl
from api.config import ApiConfig
from api.provenance import provenance
from api.replay import REPLAY_NOTICE, STREAM_METHODS, ReplayModels
from api.store import DataStore, MissingData, records
from pqdl import canon
from pqdl import detectors as dt
from pqdl.handshake import LAB_MSS, client_flight_bytes, handshake_ladder, server_flight_bytes
from pqdl.profiles import Overheads

Detector = Literal["rf", "ae", "iforest"]
CAVEATS = [
    "Single machine: all captures come from one laptop running Docker.",
    "Local network: no real RTT, loss or congestion; timing features are lab timings.",
    "Scripted workloads: the 'attacks' (handshake_flood, slow_send) are scripted attack-like workloads, not real attacks.",
    "One cipher suite (TLS_AES_256_GCM_SHA384); profiles differ only in key exchange, signature algorithm and chain length.",
    "The 18 profiles are 18 'doses', not independent samples; splits are time-blocked inside one pcap per profile and workload.",
    "IsolationForest misses handshake floods even in-domain; treat its results as a weak baseline.",
]
# detector_baseline.csv / canon_eval.csv method name -> label used in results/stats_pcap_level.csv
PCAP_LEVEL_LABEL = {"naive": "naive", "naive_app": "V_APP", "pooled": "pooled", "oracle": "oracle", "canon_a_true": "CANON-A",
                    "canon_a2_true": "CANON-A2 (exploratory)", "canon_b_k100_true": "CANON-B v0 k=100",
                    "canon_bs_k120_true": "CANON-B split k=120"}
# pqmix: label -> method name in the results files
MIX_METHODS = {"naive": "naive", "V_APP": "naive_app", "CANON-B split k=120": "canon_bs_k120_true",
               "CANON-B v0 k=100": "canon_b_k100_true"}
PQMIX_FORMULA = ("FPR_mix(pi) = pi * FPR_profile + (1 - pi) * FPR_classical, using the MEASURED test-block FPR of the method "
                 "on the chosen PQ profile and on the classical profile. A weighted average of two measurements, "
                 "not a simulation; the CIs of the two components are given, none is invented for the mix.")
BASE_CSV, CANON_CSV, PCAP_CSV, DRIFT_CSV = "detector_baseline.csv", "canon_eval.csv", "stats_pcap_level.csv", "lab_drift.csv"
CERT_CSV = "cert_overhead.csv"
CI_LEVEL = 0.95        # level of the flow-bootstrap intervals in the results files (detectors.summarise: 2.5 % and 97.5 % quantiles)


def create_app(cfg: ApiConfig | None = None) -> FastAPI:
    cfg = cfg or ApiConfig()
    store = DataStore(cfg)
    holder: dict[str, ReplayModels] = {}

    def models() -> ReplayModels:
        if "m" not in holder:
            holder["m"] = ReplayModels(store.flows())
        return holder["m"]

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        if cfg.eager_train:                                   # train the replay detectors once, at startup
            await asyncio.to_thread(lambda: models().warm())
        yield

    app = FastAPI(title="PQ-DRIFTLAB API (read-only)", version=pqdl.__version__, lifespan=lifespan)
    app.add_middleware(CORSMiddleware, allow_origins=[cfg.allowed_origin], allow_methods=["GET"], allow_headers=["*"])

    @app.exception_handler(MissingData)
    async def _missing(_: Request, exc: MissingData) -> JSONResponse:
        return JSONResponse(status_code=503, content={"detail": str(exc), "provenance": provenance(cfg, [])})

    def out(payload: dict, files: list) -> dict:
        return {"provenance": provenance(cfg, files), **payload}

    # ------------------------------------------------------------------ /api/meta
    @app.get("/api/meta")
    def meta() -> dict:
        base, can = store.csv(BASE_CSV), store.csv(CANON_CSV)
        return out({"version": pqdl.__version__, "served_by_commit": provenance(cfg, [])["served_by_commit"],
                    "profiles": store.profile_strings(),
                    "methods": {"baseline": sorted(base["method"].unique()), "canon": sorted(can["method"].unique()),
                                "stream": list(STREAM_METHODS)},
                    "detectors": list(dt.DETECTORS), "caveats": CAVEATS,
                    "classical_profile": canon.CLASSICAL_CONTEXT, "design_fpr": dt.DESIGN_FPR, "ci_level": CI_LEVEL},
                   [store.path(BASE_CSV), store.path(CANON_CSV), cfg.flows_path])

    # ------------------------------------------------------------------ /api/ladder
    @app.get("/api/ladder")
    def ladder(kem: str, auth: str, chain: str, cert_overhead: Literal["default", "measured"] = "default") -> dict:
        ctx = f"{kem}|{auth}|{chain}"
        try:
            prof = canon.context_profile(ctx)
        except KeyError:
            raise HTTPException(404, f"unknown profile {ctx}") from None
        obs = store.observed_handshake(kem, auth, chain)
        if obs is None:
            raise HTTPException(404, f"no lab flows for profile {ctx}")
        files = [cfg.flows_path]
        ov = Overheads()
        if cert_overhead == "measured":                      # per-certificate overhead measured on the lab's own certificates
            table = store.csv(CERT_CSV).set_index("auth")
            if auth not in table.index:
                raise HTTPException(404, f"no measured certificate overhead for auth {auth}")
            ov = Overheads(o_cert=int(round(float(table.loc[auth, "o_cert"]))))
            files.append(store.path(CERT_CSV))
        model_s, model_c = server_flight_bytes(prof, ov), client_flight_bytes(prof, ov)

        def diff(o: float, m: int) -> dict:
            return {"observed": o, "model": m, "difference": o - m,
                    "difference_pct_of_observed": 100.0 * (o - m) / o if o else None}

        return out({"profile": ctx, "mss": LAB_MSS,
                    "model": {"ladder": handshake_ladder(prof, mss=LAB_MSS, ov=ov), "B_S": model_s, "B_C": model_c,
                              "cert_overhead": cert_overhead, "o_cert_bytes": ov.o_cert,
                              "note": ("size model with the per-certificate overhead measured on the lab's own certificates"
                                       if cert_overhead == "measured" else
                                       "size model with default overheads (VERIFY); not tuned to the lab")},
                    "observed": obs,
                    "comparison": {"server_to_client_bytes": diff(obs["hs_s2c_bytes_median"], model_s),
                                   "client_to_server_bytes": diff(obs["hs_c2s_bytes_median"], model_c)}},
                   files)

    # ------------------------------------------------------------------ /api/drift
    @app.get("/api/drift")
    def drift(workload: str | None = None, view: Literal["hs", "app", "flow"] | None = None,
              limit: int = Query(500, ge=1, le=5000), offset: int = Query(0, ge=0)) -> dict:
        d = store.csv(DRIFT_CSV).copy()
        d["view"] = d["feature"].str.split("_").str[0]
        if workload:
            d = d[d["workload"] == workload]
        if view:
            d = d[d["view"] == view]
        cols = [c for c in ("test", "workload", "view", "feature", "ref_group", "compared_group", "term", "design", "eta2",
                            "partial_eta2", "psi", "mmd2", "mmd2_p_value", "noise95_eta2", "noise95_max_psi", "n_ref",
                            "n_group", "deterministic", "note") if c in d.columns]
        return out({"filters": {"workload": workload, "view": view}, "n_rows": int(len(d)), "offset": offset,
                    "limit": limit, "rows": records(d[cols].iloc[offset:offset + limit]),
                    "note": "noise95_* = 95th percentile of the permutation noise floor (shuffled profile labels)"},
                   [store.path(DRIFT_CSV)])

    # ------------------------------------------------------------------ /api/detectors
    @app.get("/api/detectors")
    def detectors(detector: Detector | None = None, method: str | None = None, profile: str | None = None,
                  dataset: str = "main", metric: str | None = None, limit: int = Query(2000, ge=1, le=10000)) -> dict:
        base, can = store.csv(BASE_CSV), store.csv(CANON_CSV)
        df = pd.concat([base, can], ignore_index=True)
        df = df[df["dataset"] == dataset]
        for col, val in (("detector", detector), ("method", method), ("profile", profile), ("metric", metric)):
            if val:
                df = df[df[col] == val]
        files = [store.path(BASE_CSV), store.path(CANON_CSV)]
        pcap = None
        try:
            pcap = store.csv(PCAP_CSV)
            files.append(store.path(PCAP_CSV))
        except MissingData:
            pass
        rows = []
        for (ds, det, meth, prof), g in df.groupby(["dataset", "detector", "method", "profile"], sort=True):
            rec = {"dataset": ds, "detector": det, "method": meth, "profile": prof,
                   "n_benign": int(g["n_benign"].iloc[0]), "n_attack": int(g["n_attack"].iloc[0]),
                   "metrics": {r.metric: {"value": r.value, "ci_lo": r.ci_lo, "ci_hi": r.ci_hi, "seed_sd": r.seed_sd}
                               for r in g.itertuples()},
                   "pcap_level": None}
            label = PCAP_LEVEL_LABEL.get(meth)
            if pcap is not None and ds == "main" and label:
                m = pcap[(pcap["detector"] == det) & (pcap["profile"] == prof) & (pcap["method"] == label)]
                if len(m):
                    r = m.iloc[0]
                    rec["pcap_level"] = {"n_capture_sets": int(r["n_capture_sets"]), "mean_fpr": float(r["mean_fpr"]),
                                         "sd_across_pcaps": float(r["sd_across_pcaps"]), "min": float(r["min"]),
                                         "max": float(r["max"]), "flow_ci_understates": bool(r["flow_ci_understates"]),
                                         "note": "FPR per capture set (main run + replicates) of benign test flows"}
            rows.append(rec)
        return out({"filters": {"detector": detector, "method": method, "profile": profile, "dataset": dataset,
                                "metric": metric},
                    "n_records": len(rows), "records": _clean(rows[:limit])}, files)

    # ------------------------------------------------------------------ /api/pqmix
    @app.get("/api/pqmix")
    def pqmix(pi: float = Query(..., ge=0.0, le=1.0), detector: Detector = Query(...), profile: str = Query(...)) -> dict:
        base, can = store.csv(BASE_CSV), store.csv(CANON_CSV)
        df = pd.concat([base, can], ignore_index=True)
        df = df[(df["dataset"] == "main") & (df["detector"] == detector) & (df["metric"] == "fpr")]
        if profile not in set(df["profile"]):
            raise HTTPException(404, f"unknown profile {profile}")
        rows = {}
        for label, meth in MIX_METHODS.items():
            g = df[df["method"] == meth].set_index("profile")
            if profile not in g.index or canon.CLASSICAL_CONTEXT not in g.index:
                continue
            p, c = g.loc[profile], g.loc[canon.CLASSICAL_CONTEXT]
            rows[label] = {"method_name": meth, "fpr_profile": float(p["value"]),
                           "fpr_profile_ci": [float(p["ci_lo"]), float(p["ci_hi"])],
                           "fpr_classical": float(c["value"]),
                           "fpr_classical_ci": [float(c["ci_lo"]), float(c["ci_hi"])],
                           "fpr_mix": pi * float(p["value"]) + (1 - pi) * float(c["value"])}
        return out({"pi": pi, "detector": detector, "profile": profile, "classical_profile": canon.CLASSICAL_CONTEXT,
                    "formula": PQMIX_FORMULA, "simulation": False, "methods": rows},
                   [store.path(BASE_CSV), store.path(CANON_CSV)])

    # ------------------------------------------------------------------ WS /api/stream
    @app.websocket("/api/stream")
    async def stream(ws: WebSocket, detector: str, method: str, profile: str = "mlkem768|mldsa65|leaf_int",
                     speed: float = 50.0, limit: int = 2000) -> None:
        if detector not in dt.DETECTORS or method not in STREAM_METHODS or not (0 < speed <= 5000) or not (1 <= limit <= 5000):
            await ws.close(code=1008, reason="detector in rf/ae/iforest, method in naive/naive_app/canon_a/canon_b, 0 < speed <= 5000")
            return
        try:
            scored = await asyncio.to_thread(lambda: models().replay(detector, method, profile, limit))
        except (ValueError, MissingData) as exc:
            await ws.close(code=1008, reason=str(exc)[:120])
            return
        await ws.accept()
        prov = provenance(cfg, [cfg.flows_path])
        g = scored.flows
        t0 = float(g["start_time"].iloc[0])
        try:
            await ws.send_json({"type": "hello", "replay": True, "notice": REPLAY_NOTICE, "detector": detector,
                                "method": method, "profile": profile, "speed_flows_per_s": speed, "n_flows": len(g),
                                "provenance": prov})
            n_alert = n_benign_alert = n_attack_alert = 0
            for i, (row, score, thr) in enumerate(zip(g.itertuples(), scored.scores, scored.thresholds)):
                alert = bool(score > thr)
                n_alert += alert
                n_benign_alert += alert and not row.attack
                n_attack_alert += alert and bool(row.attack)
                await ws.send_json({"type": "flow", "replay": True, "index": i,
                                    "recorded_offset_s": float(row.start_time) - t0, "workload": row.workload,
                                    "label": "attack" if row.attack else "benign", "score": float(score),
                                    "threshold": float(thr), "alert": alert, "flow_s2c_bytes": float(row.flow_s2c_bytes),
                                    "flow_c2s_bytes": float(row.flow_c2s_bytes)})
                await asyncio.sleep(1.0 / speed)
            await ws.send_json({"type": "done", "replay": True, "n_flows": len(g), "alerts": int(n_alert),
                                "alerts_on_benign": int(n_benign_alert), "alerts_on_attack": int(n_attack_alert),
                                "notice": REPLAY_NOTICE})
            await ws.close()
        except WebSocketDisconnect:
            return

    return app


def _clean(obj):
    """Recursively replace NaN/inf floats by None so the JSON is valid."""
    import math
    if isinstance(obj, dict):
        return {k: _clean(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_clean(v) for v in obj]
    if isinstance(obj, float) and not math.isfinite(obj):
        return None
    return obj
