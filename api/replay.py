"""Replay of RECORDED lab flows through detectors trained once on the classical training block.

This is a REPLAY of stored captures (the test blocks of data/flows/lab_flows.csv), never live traffic. Detectors are
trained once (model seed 11) and cached; scoring a flow here uses the same functions as the offline evaluation.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass

import numpy as np
import pandas as pd

from pqdl import canon
from pqdl import detectors as dt

MODEL_SEED = 11
CAL_SEED = 20261127                       # same calibration seed as scripts/canon_eval.py
STREAM_METHODS = ("naive", "naive_app", "canon_a", "canon_b")
CLASSICAL = canon.CLASSICAL_CONTEXT
REPLAY_NOTICE = ("REPLAY of recorded lab captures (test blocks of data/flows/lab_flows.csv), not live traffic. "
                 "Scripted attack-like workloads, one machine, local network.")


@dataclass
class Scored:
    flows: pd.DataFrame
    scores: np.ndarray
    thresholds: np.ndarray


class ReplayModels:
    def __init__(self, flows: pd.DataFrame) -> None:
        self.df = dt.time_block_split(dt.add_labels(flows))
        self._domains: dict[tuple[str, str], dt.Domain] = {}
        self._bank: dict | None = None
        self._lock = threading.RLock()

    def _classical(self, block: str) -> pd.DataFrame:
        g = self.df[(self.df["block"] == block) & (self.df["profile"] == CLASSICAL)]
        if g.empty:
            raise ValueError(f"the classical profile {CLASSICAL} has no {block} block in the flows file")
        return g

    def domain(self, det: str, view: str) -> dt.Domain:
        with self._lock:
            key = (det, view)
            if key not in self._domains:
                self._domains[key] = dt.fit_domain(det, dt.VIEWS[view], self._classical("train"), self._classical("val"), (MODEL_SEED,))
            return self._domains[key]

    def warm(self) -> None:
        """Train everything once (called at startup)."""
        for det in dt.DETECTORS:
            for view in dt.VIEWS:
                self.domain(det, view)
        self.bank()

    def bank(self) -> dict:
        """CANON-B (split) calibration bank: per-context shifts and the benign validation flows' threshold halves."""
        with self._lock:
            if self._bank is None:
                ref = self._classical("train")
                ref = ref[~ref["attack"]]
                shifts, thr_flows = {}, {}
                for i, c in enumerate(sorted(self.df["profile"].unique())):
                    val = self.df[(self.df["block"] == "val") & (self.df["profile"] == c) & ~self.df["attack"]]
                    k = len(val) - len(val) % 2
                    if k < 2:
                        continue
                    fit, thr = canon.split_calibration(canon.calibration_draw(val, min(k, 120), CAL_SEED + i))
                    shifts[c] = canon.location_shift(fit, ref, canon.group_features(["bytes"]))
                    thr_flows[c] = thr
                self._bank = {"shifts": shifts, "thr_flows": thr_flows, "taus": {}}
            return self._bank

    def _tau(self, det: str, ctx: str) -> float:
        bank = self.bank()
        with self._lock:
            if (det, ctx) not in bank["taus"]:
                cols = canon.group_features(["bytes"])
                res = canon.residualise(bank["thr_flows"][ctx], [ctx] * len(bank["thr_flows"][ctx]), bank["shifts"], cols)
                sc = self.domain(det, "V_FLOW").score(dt.design_matrix(res, dt.V_FLOW))[0]
                bank["taus"][(det, ctx)] = canon.conformal_threshold(sc)
            return bank["taus"][(det, ctx)]

    def replay(self, det: str, method: str, profile: str, limit: int) -> Scored:
        """Test-block flows of `profile` in recorded start-time order with a score and threshold per flow."""
        if method not in STREAM_METHODS:
            raise ValueError(f"method must be one of {STREAM_METHODS}")
        g = self.df[(self.df["block"] == "test") & (self.df["profile"] == profile)].sort_values("start_time").head(limit)
        if g.empty:
            raise ValueError(f"no test-block flows for profile {profile}")
        ctx = np.array([profile] * len(g), dtype=object)
        if method == "naive":
            d = self.domain(det, "V_FLOW")
            return Scored(g, d.score(dt.design_matrix(g, dt.V_FLOW))[0], np.full(len(g), d.thresholds[0]))
        if method == "naive_app":
            d = self.domain(det, "V_APP")
            return Scored(g, d.score(dt.design_matrix(g, dt.V_APP))[0], np.full(len(g), d.thresholds[0]))
        d = self.domain(det, "V_FLOW")
        if method == "canon_a":
            fixed = canon.correct_a(g, ctx, ["bytes"])
            return Scored(g, d.score(dt.design_matrix(fixed, dt.V_FLOW))[0], np.full(len(g), d.thresholds[0]))
        bank = self.bank()
        if profile not in bank["shifts"]:
            raise ValueError(f"no calibration flows for profile {profile}")
        fixed = canon.residualise(g, ctx, bank["shifts"], canon.group_features(["bytes"]))
        return Scored(g, d.score(dt.design_matrix(fixed, dt.V_FLOW))[0], np.full(len(g), self._tau(det, profile)))
