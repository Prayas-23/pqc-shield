"""API configuration: where the stored results and lab flows live. Paths are only ever READ."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class ApiConfig:
    results_dir: Path = ROOT / "results"
    flows_path: Path = ROOT / "data" / "flows" / "lab_flows.csv"
    root: Path = ROOT
    synthetic: bool = False        # True only for the SYNTHETIC test fixture; every response then says synthetic: true
    eager_train: bool = True       # train the replay detectors once at startup (lifespan); False = lazily on first use
    allowed_origin: str = "http://localhost:5173"
    host: str = "127.0.0.1"
