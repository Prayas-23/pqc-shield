"""Cached, read-only access to the stored CSVs. Nothing here recomputes a research result."""

from __future__ import annotations

import threading
from pathlib import Path

import numpy as np
import pandas as pd

from api.config import ApiConfig


class MissingData(Exception):
    """A stored results file is not there (the pipeline scripts have not been run)."""


def records(df: pd.DataFrame) -> list[dict]:
    """DataFrame -> JSON-safe list of dicts (NaN/inf -> None, numpy scalars -> python)."""
    out = []
    for row in df.to_dict(orient="records"):
        out.append({k: (None if (isinstance(v, float) and not np.isfinite(v)) or v is pd.NA else
                        (v.item() if isinstance(v, np.generic) else v)) for k, v in row.items()})
    return out


class DataStore:
    def __init__(self, cfg: ApiConfig) -> None:
        self.cfg = cfg
        self._cache: dict[Path, pd.DataFrame] = {}
        self._obs: dict[tuple[str, str, str], dict | None] = {}
        self._lock = threading.Lock()

    def path(self, name: str) -> Path:
        return self.cfg.results_dir / name

    def _read(self, path: Path) -> pd.DataFrame:
        with self._lock:
            if path not in self._cache:
                if not path.exists():
                    raise MissingData(f"{path.name} not found; run the pipeline script that produces it")
                self._cache[path] = pd.read_csv(path)
            return self._cache[path]

    def csv(self, name: str) -> pd.DataFrame:
        return self._read(self.path(name))

    def flows(self) -> pd.DataFrame:
        return self._read(self.cfg.flows_path)

    # --- derived descriptive lookups (cheap, cached once)
    def profile_strings(self) -> list[str]:
        f = self.flows()
        return sorted((f["kem"] + "|" + f["auth"] + "|" + f["chain"]).unique())

    def observed_handshake(self, kem: str, auth: str, chain: str) -> dict | None:
        """Median OBSERVED hs_s2c_bytes / hs_c2s_bytes of the profile's lab flows (descriptive, cached)."""
        key = (kem, auth, chain)
        with self._lock:
            if key in self._obs:
                return self._obs[key]
        f = self.flows()
        g = f[(f["kem"] == kem) & (f["auth"] == auth) & (f["chain"] == chain)]
        out = None if g.empty else {"n_flows": int(len(g)), "hs_s2c_bytes_median": float(g["hs_s2c_bytes"].median()),
                                    "hs_c2s_bytes_median": float(g["hs_c2s_bytes"].median())}
        with self._lock:
            self._obs[key] = out
        return out
