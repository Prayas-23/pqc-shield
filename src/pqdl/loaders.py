"""Dataset loaders.

Loads CIC-PQC_OAV and CIC-IDS2017 from manually downloaded files under data/, maps each
to a DataFrame tagged with a `source` column, and returns a data-quality report dict
alongside it. The two datasets are NEVER merged (AGENTS.md rule 6); use
`assert_single_source` in every train/test helper.

Schemas were inspected from the real files; see docs/data_schema.md
(regenerate with scripts/inspect_data.py).

Parsed results are cached as pickles under <data_dir>/cache/ (pickle, not parquet, so no
extra dependency is needed). The cache key covers file names, sizes, mtimes, loader
parameters and LOADER_VERSION, so a changed file or parameter rebuilds the cache.
Only load caches that this code wrote itself.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from collections import Counter
from pathlib import Path
from typing import Any, Callable, Literal

import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)

LOADER_VERSION = 1
SOURCE_PQC = "cic_pqc_oav"
SOURCE_IDS = "cic_ids2017"
DATA_DIR = Path(__file__).resolve().parents[2] / "data"
WARN_LABEL_LOSS_FRACTION = 0.10

Dedupe = Literal["none", "within_file", "global"]
DEDUPE_MODES: tuple[str, ...] = ("none", "within_file", "global")
Report = dict[str, Any]

PQC_FILES = ("ml_features_and_labels.csv", "scenario_manifest.csv", "raw_sessions.jsonl")
FWD_HDR = "Fwd Header Length"
FWD_HDR_TWIN = "Fwd Header Length.1"  # pandas' name for the header's second copy
FWD_HDR_RENAMED = "Fwd Header Length_dup2"
# Characters that stand in for the en/em dash in CIC-IDS2017 labels, depending on how
# the file was decoded ("Web Attack – XSS" as cp1252, U+FFFD, or a raw 0x96 byte).
_LABEL_DASHES = ("–", "—", "−", "�", "\x96")
_SCENARIO_RE = re.compile(r"^normal_(?P<kem>[A-Za-z0-9]+)_(?P<auth>.+)_cert$")


class MixedSourceError(ValueError):
    """Raised when a frame holds more than one dataset source (or none)."""


def assert_single_source(df: pd.DataFrame) -> None:
    """Raise MixedSourceError unless every row of `df` has the same, non-null `source`."""
    if "source" not in df.columns:
        raise MixedSourceError("frame has no 'source' column")
    if df["source"].isna().any():
        raise MixedSourceError("frame has rows with a null 'source'")
    sources = sorted(str(s) for s in df["source"].unique())
    if len(sources) > 1:
        raise MixedSourceError(f"frame mixes sources {sources}; datasets must not be merged")


# --------------------------------------------------------------------------- shared helpers
def read_csv_text(path: Path) -> tuple[pd.DataFrame, str]:
    """Read a CSV trying utf-8, then cp1252, then latin-1. Return (frame, encoding used)."""
    for enc in ("utf-8", "cp1252", "latin-1"):
        try:
            return pd.read_csv(path, encoding=enc, low_memory=False), enc
        except UnicodeDecodeError:
            continue
    raise ValueError(f"could not decode {path} as utf-8, cp1252 or latin-1")


def strip_column_names(df: pd.DataFrame) -> pd.DataFrame:
    """Return `df` with leading/trailing whitespace removed from column names.

    Raises ValueError if stripping makes two column names identical.
    """
    out = df.copy()
    out.columns = [str(c).strip() for c in out.columns]
    dupes = sorted({c for c in out.columns if list(out.columns).count(c) > 1})
    if dupes:
        raise ValueError(f"duplicate column names after stripping whitespace: {dupes}")
    return out


def normalise_label(value: Any) -> Any:
    """Strip whitespace, collapse runs of spaces and replace odd dash characters by '-'."""
    if not isinstance(value, str):
        return value
    for dash in _LABEL_DASHES:
        value = value.replace(dash, "-")
    return re.sub(r"\s+", " ", value).strip()


def normalise_label_series(labels: pd.Series) -> pd.Series:
    """Apply `normalise_label` to a Series (computed once per distinct value)."""
    mapping = {v: normalise_label(v) for v in labels.dropna().unique()}
    return labels.map(mapping)


def drop_all_nan_rows(df: pd.DataFrame) -> tuple[pd.DataFrame, int]:
    """Drop rows where every column is NaN. Return (frame, number dropped)."""
    empty = df.isna().all(axis=1)
    return df.loc[~empty].reset_index(drop=True), int(empty.sum())


def replace_infs(df: pd.DataFrame) -> tuple[pd.DataFrame, dict[str, int]]:
    """Replace +/-inf with NaN in numeric columns. Return (frame, {column: count})."""
    out = df.copy()
    counts: dict[str, int] = {}
    for col in out.select_dtypes(include=[np.number]).columns:
        n = int(np.isinf(out[col].to_numpy(dtype=float)).sum())
        if n:
            counts[col] = n
            out[col] = out[col].replace([np.inf, -np.inf], np.nan)
    return out, counts


def numeric_to_float64(df: pd.DataFrame) -> pd.DataFrame:
    """Cast numeric (non-bool) columns to float64 so dtypes agree across files."""
    out = df.copy()
    for col in out.columns:
        if pd.api.types.is_numeric_dtype(out[col]) and out[col].dtype != bool:
            out[col] = out[col].astype("float64")
    return out


def row_keys(df: pd.DataFrame) -> pd.DataFrame:
    """128-bit row fingerprint (two independent 64-bit hashes) for exact-duplicate detection.

    Collision probability for ~3e6 rows is about 1e-26, far below any practical concern.
    Used instead of DataFrame.duplicated() on the concatenation to keep peak memory low.
    """
    return pd.DataFrame({
        "a": pd.util.hash_pandas_object(df, index=False, hash_key="0123456789123456").to_numpy(),
        "b": pd.util.hash_pandas_object(df, index=False, hash_key="fedcba9876543210").to_numpy(),
    })


def duplicate_masks(keys: list[pd.DataFrame], mode: str) -> list[np.ndarray]:
    """Boolean 'remove this row' mask per frame. The first occurrence is always kept."""
    if mode == "none":
        return [np.zeros(len(k), dtype=bool) for k in keys]
    if mode == "within_file":
        return [k.duplicated().to_numpy() for k in keys]
    if mode == "global":
        dup = pd.concat(keys, ignore_index=True).duplicated().to_numpy()
        bounds = np.cumsum([len(k) for k in keys])[:-1]
        return list(np.split(dup, bounds))
    raise ValueError(f"dedupe must be one of {DEDUPE_MODES}, got {mode!r}")


def label_counts(labels: pd.Series) -> Counter[str]:
    """Count labels as strings (NaN becomes '<NaN>')."""
    return Counter({("<NaN>" if pd.isna(k) else str(k)): int(v)
                    for k, v in labels.value_counts(dropna=False).items()})


def nonzero_nan_counts(df: pd.DataFrame) -> dict[str, int]:
    """NaN count per column, only for columns that have any."""
    counts = df.isna().sum()
    return {str(c): int(n) for c, n in counts.items() if n}


# ----------------------------------------------------------------------------- caching
def _fingerprint(paths: list[Path], params: dict[str, Any]) -> str:
    h = hashlib.sha256(f"v{LOADER_VERSION}|{json.dumps(params, sort_keys=True)}".encode())
    for p in sorted(paths):
        st = p.stat()
        h.update(f"|{p.name}:{st.st_size}:{st.st_mtime_ns}".encode())
    return h.hexdigest()


def _read_cache(path: Path, fingerprint: str) -> tuple[pd.DataFrame, Report] | None:
    if not path.exists():
        return None
    try:
        cached_fp, df, report = pd.read_pickle(path)
    except Exception:  # noqa: BLE001 - any unreadable/stale pickle just means "rebuild"
        logger.warning("cache %s unreadable; rebuilding", path)
        return None
    return (df, report) if cached_fp == fingerprint else None


def _cached(
    root: Path,
    name: str,
    files: list[Path],
    params: dict[str, Any],
    use_cache: bool,
    build: Callable[[], tuple[pd.DataFrame, Report]],
) -> tuple[pd.DataFrame, Report]:
    cache_path = root / "cache" / name
    fingerprint = _fingerprint(files, params)
    if use_cache:
        hit = _read_cache(cache_path, fingerprint)
        if hit is not None:
            logger.info("loaded %s from cache %s", name, cache_path)
            _log_report(hit[1])
            return hit
    df, report = build()
    _log_report(report)
    if use_cache:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        pd.to_pickle((fingerprint, df, report), cache_path)
    return df, report


def _log_report(report: Report) -> None:
    logger.info("data-quality report [%s]:\n%s", report["source"], json.dumps(report, indent=2, default=str))
    for warning in report.get("warnings", []):
        logger.warning("DATA QUALITY WARNING [%s]: %s", report["source"], warning)


# ------------------------------------------------------------------------ CIC-IDS2017
def resolve_fwd_header_twin(
    frames: list[pd.DataFrame], names: list[str]
) -> tuple[list[pd.DataFrame], Report]:
    """Drop the second 'Fwd Header Length' column only if it equals the first in every file.

    If any file differs, the second column is kept but renamed to FWD_HDR_RENAMED.
    """
    present = [FWD_HDR in f.columns and FWD_HDR_TWIN in f.columns for f in frames]
    identical = [bool(p and f[FWD_HDR].equals(f[FWD_HDR_TWIN])) for p, f in zip(present, frames)]
    info: Report = {
        "files_with_duplicate_header": int(sum(present)),
        "files_identical": int(sum(identical)),
        "differing_files": [n for n, p, i in zip(names, present, identical) if p and not i],
    }
    drop = bool(sum(present)) and all(i for p, i in zip(present, identical) if p)
    info["second_column_dropped"] = drop
    out = []
    for f, p in zip(frames, present):
        if p:
            f = f.drop(columns=[FWD_HDR_TWIN]) if drop else f.rename(columns={FWD_HDR_TWIN: FWD_HDR_RENAMED})
        out.append(f)
    return out, info


def _ids_label_accounting(
    labels: list[pd.Series], masks: list[np.ndarray]
) -> tuple[dict[str, dict[str, float]], list[str]]:
    before: Counter[str] = Counter()
    removed: Counter[str] = Counter()
    for lab, mask in zip(labels, masks):
        before.update(label_counts(lab))
        removed.update(label_counts(lab[mask]))
    table: dict[str, dict[str, float]] = {}
    warnings: list[str] = []
    for label, n_before in sorted(before.items()):
        n_removed = int(removed.get(label, 0))
        frac = n_removed / n_before if n_before else 0.0
        table[label] = {"before": int(n_before), "removed": n_removed,
                        "after": int(n_before) - n_removed, "fraction_removed": round(frac, 6)}
        if frac > WARN_LABEL_LOSS_FRACTION:
            warnings.append(
                f"label {label!r} lost {n_removed} of {n_before} rows ({frac:.1%}) to de-duplication "
                f"(> {WARN_LABEL_LOSS_FRACTION:.0%})")
    return table, warnings


def _prepare_ids_frame(df: pd.DataFrame) -> tuple[pd.DataFrame, int, dict[str, int]]:
    """All-NaN drop, label normalisation, inf->NaN, float64 cast for one daily file."""
    df, n_blank = drop_all_nan_rows(df)
    if "Label" not in df.columns:
        raise KeyError("expected a 'Label' column after stripping column names")
    df["Label"] = normalise_label_series(df["Label"])
    df, infs = replace_infs(df)
    return numeric_to_float64(df), n_blank, infs


def _build_ids(folder: Path, dedupe: str) -> tuple[pd.DataFrame, Report]:
    paths = sorted(folder.glob("*.csv"))
    if not paths:
        raise FileNotFoundError(f"no CSV files in {folder}")
    names = [p.name for p in paths]
    loaded = [read_csv_text(p) for p in paths]
    frames, twin_info = resolve_fwd_header_twin([strip_column_names(df) for df, _ in loaded], names)
    files: dict[str, Report] = {n: {"rows_read": len(f), "encoding": enc}
                                for n, f, (_, enc) in zip(names, frames, loaded)}
    inf_total: Counter[str] = Counter()
    prepared: list[pd.DataFrame] = []
    for name, frame in zip(names, frames):
        frame, n_blank, infs = _prepare_ids_frame(frame)
        files[name]["all_nan_rows_dropped"] = n_blank
        inf_total.update(infs)
        prepared.append(frame)
    del frames, loaded
    masks = duplicate_masks([row_keys(f) for f in prepared], dedupe)
    by_label, warnings = _ids_label_accounting([f["Label"] for f in prepared], masks)
    kept = []
    for name, frame, mask in zip(names, prepared, masks):
        files[name]["duplicates_removed"] = int(mask.sum())
        out = frame.loc[~mask].reset_index(drop=True)
        out["source"] = SOURCE_IDS
        out["source_file"] = name
        out["day"] = name.split("-")[0]
        kept.append(out)
    del prepared
    df = pd.concat(kept, ignore_index=True)
    df["label_binary"] = (df["Label"] != "BENIGN").astype("Int8").where(df["Label"].notna())
    return df, _ids_report(df, files, twin_info, dict(inf_total), by_label, warnings, dedupe)


def _ids_report(
    df: pd.DataFrame, files: dict[str, Report], twin: Report, infs: dict[str, int],
    by_label: dict[str, dict[str, float]], warnings: list[str], dedupe: str,
) -> Report:
    read = sum(f["rows_read"] for f in files.values())
    blank = sum(f["all_nan_rows_dropped"] for f in files.values())
    dups = sum(f["duplicates_removed"] for f in files.values())
    odd = sorted({str(v) for v in df["Label"].dropna().unique() if not str(v).isascii()})
    if odd:
        warnings.append(f"labels still contain non-ASCII characters after normalisation: {odd}")
    return {
        "source": SOURCE_IDS, "dedupe": dedupe, "files": files,
        "rows_read": read,
        "rows_dropped": {"all_nan_rows": blank, "duplicate_rows": dups},
        "rows_out": len(df),
        "removed_by_label": by_label,
        "fwd_header_length": twin,
        "inf_replaced_with_nan": infs,
        "nan_counts": nonzero_nan_counts(df),
        "warnings": warnings,
    }


def load_cic_ids2017(
    data_dir: Path | None = None, dedupe: Dedupe = "global", use_cache: bool = True
) -> tuple[pd.DataFrame, Report]:
    """Load the daily CIC-IDS2017 CSVs as one frame with source='cic_ids2017'.

    Steps: strip column names; handle the duplicated 'Fwd Header Length' column; drop
    all-NaN rows (own report line); normalise labels; +/-inf -> NaN; de-duplicate per
    `dedupe` ('none' | 'within_file' | 'global', applied to the feature columns);
    add label_binary (0 = BENIGN, 1 = attack), source_file and day.
    """
    if dedupe not in DEDUPE_MODES:
        raise ValueError(f"dedupe must be one of {DEDUPE_MODES}, got {dedupe!r}")
    root = Path(data_dir) if data_dir is not None else DATA_DIR
    folder = root / "cic_ids2017"
    files = sorted(folder.glob("*.csv"))
    return _cached(root, f"cic_ids2017_{dedupe}.pkl", files, {"dedupe": dedupe}, use_cache,
                   lambda: _build_ids(folder, dedupe))


# ------------------------------------------------------------------------- CIC-PQC_OAV
def read_observed_kem(path: Path) -> dict[str, Any]:
    """Map '<taxonomy>\\<ID>' -> raw e1_alg_suite string from raw_sessions.jsonl."""
    observed: dict[str, Any] = {}
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                rec = json.loads(line)
                if rec["scenario_id"] in observed:
                    raise ValueError(f"duplicate scenario_id in {path.name}: {rec['scenario_id']!r}")
                observed[rec["scenario_id"]] = rec.get("e1_alg_suite")
    return observed


def parse_scenario_kem_auth(scenario_ids: pd.Series) -> pd.DataFrame:
    """kem_scenario / auth_scenario from 'normal_<kem>_<auth>_cert' ids; NaN for all others."""
    parts = scenario_ids.astype("object").str.extract(_SCENARIO_RE)
    return parts.rename(columns={"kem": "kem_scenario", "auth": "auth_scenario"})


def _pqc_join(ml: pd.DataFrame, man: pd.DataFrame) -> pd.DataFrame:
    ml = ml.rename(columns={"label": "label_ml"}).assign(_key=lambda d: d["ID"].astype(str) + ".pcap")
    man = man.rename(columns={"ID": "manifest_id"})
    out = ml.merge(man, left_on="_key", right_on="manifest_id", how="left", validate="one_to_one")
    return out.drop(columns="_key")


def _pqc_labels(df: pd.DataFrame) -> tuple[pd.DataFrame, Report]:
    df = df.rename(columns={"anomaly_label": "label_raw"})
    mapped = df["label_raw"].map({"Normal": 0, "Anomaly": 1})
    df["label_binary"] = mapped.astype("Int8")
    both = df["label_binary"].notna()
    disagree = both & (df["label_binary"].astype("float") != df["label_ml"].astype("float"))
    return df, {
        "rows_without_manifest_match": int(df["manifest_id"].isna().sum()),
        "unmapped_label_raw_values": sorted(map(str, df.loc[df["label_raw"].notna() & ~both, "label_raw"].unique())),
        "label_binary_vs_ml_label_disagreements": int(disagree.sum()),
    }


def _pqc_kem_auth(df: pd.DataFrame, observed: dict[str, Any]) -> tuple[pd.DataFrame, Report]:
    df = pd.concat([df, parse_scenario_kem_auth(df["scenario_id"])], axis=1)
    key = df["taxonomy"].astype(str) + "\\" + df["ID"].astype(str)
    df["kem_observed"] = key.map(observed)  # raw e1_alg_suite string; NaN if the session is missing
    normal = df["label_raw"] == "Normal"
    scen, obs = df["kem_scenario"], df["kem_observed"]
    usable = scen.notna() & obs.notna() & (obs != "N/A")
    bad = usable & (scen.str.lower() != obs.astype("object").str.lower())
    pairs = Counter(f"{s} -> {o}" for s, o in zip(scen[bad], obs[bad]))
    return df, {
        "normal_rows": int(normal.sum()),
        "normal_rows_without_scenario_kem_auth": int((normal & scen.isna()).sum()),
        "non_normal_rows_with_scenario_kem_auth": int((~normal & scen.notna()).sum()),
        "rows_without_observed_session": int(obs.isna().sum()),
        "kem_scenario_nan": int(scen.isna().sum()),
        "auth_scenario_nan": int(df["auth_scenario"].isna().sum()),
        "scenario_vs_observed_kem": {
            "compared_rows": int(usable.sum()),
            "observed_unavailable_rows": int((scen.notna() & ~usable).sum()),
            "disagreements": int(bad.sum()),
            "disagreement_pairs": dict(pairs),
        },
    }


def _build_pqc(folder: Path) -> tuple[pd.DataFrame, Report]:
    ml, _ = read_csv_text(folder / PQC_FILES[0])
    man, _ = read_csv_text(folder / PQC_FILES[1])
    observed = read_observed_kem(folder / PQC_FILES[2])
    read = {PQC_FILES[0]: len(ml), PQC_FILES[1]: len(man), PQC_FILES[2]: len(observed)}
    ml, blank_ml = drop_all_nan_rows(ml)
    man, blank_man = drop_all_nan_rows(man)
    df, label_info = _pqc_labels(_pqc_join(ml, man))
    df, kem_info = _pqc_kem_auth(df, observed)
    df.insert(0, "source", SOURCE_PQC)
    report: Report = {
        "source": SOURCE_PQC, "rows_read": read,
        "rows_dropped": {"all_nan_rows_ml": blank_ml, "all_nan_rows_manifest": blank_man},
        "rows_out": len(df), "labels": label_info, "kem_auth": kem_info,
        "nan_counts": nonzero_nan_counts(df), "warnings": [],
    }
    if label_info["label_binary_vs_ml_label_disagreements"]:
        report["warnings"].append("manifest anomaly_label disagrees with ml label on some rows")
    return df, report


def load_pqc_oav(data_dir: Path | None = None, use_cache: bool = True) -> tuple[pd.DataFrame, Report]:
    """Load CIC-PQC_OAV as one frame with source='cic_pqc_oav'.

    ml_features_and_labels.csv is joined one-to-one to scenario_manifest.csv on ID + '.pcap'.
    Added columns: label_raw (manifest anomaly_label), label_binary (0 Normal / 1 Anomaly,
    cross-checked against the ml `label`, kept as label_ml), kem_scenario / auth_scenario
    (parsed from scenario_id for 'normal_<kem>_<auth>_cert' rows only, NaN otherwise) and
    kem_observed (raw e1_alg_suite string from raw_sessions.jsonl). Observed values are never
    merged into the scenario columns and Unknown(0x....) codes are kept raw.
    """
    root = Path(data_dir) if data_dir is not None else DATA_DIR
    folder = root / "cic_pqc_oav"
    files = [folder / n for n in PQC_FILES]
    return _cached(root, "cic_pqc_oav.pkl", files, {}, use_cache, lambda: _build_pqc(folder))
