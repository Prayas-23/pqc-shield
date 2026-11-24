"""Inspect the real datasets and write docs/data_schema.md.

Everything in the output is computed from the files on disk; nothing is hand-written.
Run from the repo root:  .venv/Scripts/python scripts/inspect_data.py
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
OUT = ROOT / "docs" / "data_schema.md"

# Label-like columns to tabulate, matched on the whitespace-stripped column name.
LABEL_COLS: dict[str, list[str]] = {
    "ml_features_and_labels.csv": ["label", "split", "taxonomy"],
    "scenario_manifest.csv": ["anomaly_label", "taxonomy_class", "operational_class", "subtype"],
    "ids2017": ["Label"],
}


JSONL_VALUE_KEYS = ["e1_alg_suite", "e3_cert_info.sig_alg", "e8_proto_context", "e9_conn_outcome",
                    "e7_replay_flags", "e1b_tls12_alg_suite.key_exchange"]


def read_csv_any_encoding(path: Path) -> tuple[pd.DataFrame, str]:
    """Read a CSV trying utf-8, then cp1252, then latin-1. Return (frame, encoding used)."""
    for enc in ("utf-8", "cp1252", "latin-1"):
        try:
            return pd.read_csv(path, encoding=enc, low_memory=False), enc
        except UnicodeDecodeError:
            continue
    raise RuntimeError(f"could not decode {path}")


def label_tables(df: pd.DataFrame, wanted: list[str]) -> list[str]:
    lines: list[str] = []
    stripped = {c.strip(): c for c in df.columns}
    for name in wanted:
        if name not in stripped:
            lines.append(f"- label column `{name}` NOT FOUND")
            continue
        vc = df[stripped[name]].value_counts(dropna=False)
        lines.append(f"\nLabel values for `{name}` ({len(vc)} distinct; repr shown so odd bytes are visible):\n")
        lines.append("| value (repr) | count |\n|---|---|")
        lines += [f"| `{v!r}` | {n} |" for v, n in vc.items()]
    return lines


def column_table(df: pd.DataFrame) -> list[str]:
    num = df.select_dtypes(include=[np.number])
    obj = df.select_dtypes(exclude=[np.number])
    inf_counts = {c: int(np.isinf(num[c].to_numpy(dtype=float)).sum()) for c in num.columns}
    # Object columns may hold the strings "Infinity"/"inf" instead of real floats.
    for c in obj.columns:
        s = obj[c].astype(str).str.strip().str.lower()
        inf_counts[c] = int(s.isin(["inf", "-inf", "infinity", "-infinity"]).sum())
    lines = ["| # | column (repr) | dtype | nulls | inf |", "|---|---|---|---|---|"]
    for i, c in enumerate(df.columns):
        lines.append(f"| {i} | `{c!r}` | {df[c].dtype} | {int(df[c].isna().sum())} | {inf_counts[c]} |")
    return lines


def inspect_csv(path: Path, label_key: str) -> tuple[list[str], int]:
    df, enc = read_csv_any_encoding(path)
    dup = int(df.duplicated().sum())
    rel = path.relative_to(ROOT).as_posix()
    out = [f"\n### `{rel}`\n", f"- rows: **{len(df)}**", f"- columns: {df.shape[1]}",
           f"- encoding that decoded it: `{enc}`", f"- fully duplicated rows: **{dup}**",
           f"- completely empty (all-NaN) rows: **{int(df.isna().all(axis=1).sum())}**"]
    dupcols = [c for c in df.columns if ".1" in str(c)[-2:]]
    if dupcols:
        out.append(f"- pandas-mangled duplicate column names (header had repeats): {dupcols}")
    out += label_tables(df, LABEL_COLS[label_key])
    out += ["\nColumns:\n"] + column_table(df)
    out += ["\nFirst 3 rows (transposed):\n", "```", df.head(3).T.to_string(), "```"]
    return out, len(df)


def flatten(obj: Any, prefix: str = "") -> dict[str, str]:
    flat: dict[str, str] = {}
    for k, v in obj.items():
        key = f"{prefix}{k}"
        if isinstance(v, dict):
            flat.update(flatten(v, key + "."))
        else:
            flat[key] = type(v).__name__
    return flat


def inspect_jsonl(path: Path) -> tuple[list[str], int]:
    rel = path.relative_to(ROOT).as_posix()
    n = 0
    key_counts: Counter[str] = Counter()
    value_counts: dict[str, Counter[str]] = {k: Counter() for k in JSONL_VALUE_KEYS}
    first: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            if not line.strip():
                continue
            rec = json.loads(line)
            n += 1
            if len(first) < 3:
                first.append(rec)
            key_counts.update(flatten(rec).keys())
            for k in JSONL_VALUE_KEYS:
                value_counts[k][str(_get(rec, k))] += 1
    out = [f"\n### `{rel}`\n", f"- non-empty lines (records): **{n}**",
           "\nFirst 3 lines, flattened keys (nested keys joined by `.`) with value type:\n"]
    for i, rec in enumerate(first):
        out.append(f"Line {i + 1}:\n\n```")
        out += [f"{k}: {t}  = {_get(rec, k)!r}" for k, t in flatten(rec).items()]
        out.append("```")
    out += ["\nKey presence across ALL records:\n", "| key | records with key |", "|---|---|"]
    out += [f"| `{k}` | {c} |" for k, c in sorted(key_counts.items())]
    for k, vc in value_counts.items():
        out += [f"\nValue counts for `{k}` ({len(vc)} distinct):\n", "| value (repr) | records |", "|---|---|"]
        out += [f"| `{v!r}` | {c} |" for v, c in vc.most_common()]
    return out, n


def _get(rec: dict[str, Any], dotted: str) -> Any:
    cur: Any = rec
    for part in dotted.split("."):
        cur = cur[part]
    return cur


def join_diagnostics(ml: pd.DataFrame, man: pd.DataFrame) -> list[str]:
    ml_ids, man_ids = ml["ID"].astype(str), man["ID"].astype(str)
    out = ["\n### CIC-PQC_OAV join diagnostics (ml_features_and_labels.ID vs scenario_manifest.ID)\n",
           f"- ml rows: {len(ml)}; unique ml IDs: {ml_ids.nunique()}",
           f"- manifest rows: {len(man)}; unique manifest IDs: {man_ids.nunique()}",
           f"- ml IDs found verbatim in manifest IDs: {int(ml_ids.isin(set(man_ids)).sum())}"]
    with_pcap = ml_ids + ".pcap"
    out.append(f"- ml IDs found in manifest IDs after appending '.pcap': {int(with_pcap.isin(set(man_ids)).sum())}")
    stem = man_ids.str.replace(r"\.pcap$", "", regex=True)
    out.append(f"- manifest IDs with '.pcap' stripped that match an ml ID: {int(stem.isin(set(ml_ids)).sum())}")
    out.append(f"- ml IDs matching nothing even after '.pcap' fix: {int((~with_pcap.isin(set(man_ids))).sum())}")
    merged = ml.assign(_k=with_pcap).merge(man, left_on="_k", right_on="ID", suffixes=("", "_man"))
    out += ["\nCross-tab after join: ml `label` (rows) vs manifest `anomaly_label` (cols):\n", "```",
            pd.crosstab(merged["label"], merged["anomaly_label"]).to_string(), "```"]
    inv = man.groupby(["scenario_id", "taxonomy_class", "operational_class", "anomaly_label"]).size()
    out += [f"\nManifest scenario inventory ({len(inv)} distinct scenario_id x class combinations):\n",
            "| scenario_id | taxonomy_class | operational_class | anomaly_label | rows |", "|---|---|---|---|---|"]
    out += [f"| `{a}` | {b} | {c} | {d} | {n} |" for (a, b, c, d), n in inv.items()]
    onehot = [c for c in ml.columns if c.startswith(("e1_alg_suite_", "e3_sig_alg_"))]
    out += ["\nOne-hot column True-counts in ml_features_and_labels (kem / sig evidence):\n",
            "| column | True rows |", "|---|---|"]
    out += [f"| `{c}` | {int(ml[c].sum())} |" for c in onehot]
    return out


def main() -> None:
    parts: list[str] = [
        "# Data schema (generated)\n",
        "Generated by `scripts/inspect_data.py` from the files in `data/`. Do not edit by hand;",
        "re-run the script. All numbers below are computed from the files.\n",
        "## Row counts (machine-read by `pytest -m realdata`)\n",
        "| path | rows |", "|---|---|",
    ]
    body: list[str] = ["\n## CIC-PQC_OAV\n"]
    counts: list[tuple[str, int]] = []

    pqc = DATA / "cic_pqc_oav"
    ml, _ = read_csv_any_encoding(pqc / "ml_features_and_labels.csv")
    man, _ = read_csv_any_encoding(pqc / "scenario_manifest.csv")
    for name, key in [("ml_features_and_labels.csv", "ml_features_and_labels.csv"),
                      ("scenario_manifest.csv", "scenario_manifest.csv")]:
        lines, n = inspect_csv(pqc / name, key)
        body += lines
        counts.append((f"data/cic_pqc_oav/{name}", n))
    lines, n = inspect_jsonl(pqc / "raw_sessions.jsonl")
    body += lines
    counts.append(("data/cic_pqc_oav/raw_sessions.jsonl", n))
    body += join_diagnostics(ml, man)

    body += ["\n## CIC-IDS2017\n"]
    sigs: dict[str, list[str]] = {}
    for path in sorted((DATA / "cic_ids2017").glob("*.csv")):
        lines, n = inspect_csv(path, "ids2017")
        body += lines
        counts.append((f"data/cic_ids2017/{path.name}", n))
        hdr = pd.read_csv(path, nrows=0, encoding="cp1252").columns
        sigs[path.name] = [c.strip() for c in hdr]
    first_name = next(iter(sigs))
    same = all(v == sigs[first_name] for v in sigs.values())
    body.append(f"\nAll daily files have identical (stripped) column lists: **{same}**")
    if not same:
        for k, v in sigs.items():
            if v != sigs[first_name]:
                body.append(f"- `{k}` differs: extra={sorted(set(v) - set(sigs[first_name]))}, "
                            f"missing={sorted(set(sigs[first_name]) - set(v))}")

    parts += [f"| `{p}` | {n} |" for p, n in counts]
    OUT.parent.mkdir(exist_ok=True)
    OUT.write_text("\n".join(parts + body) + "\n", encoding="utf-8")
    print(f"wrote {OUT}")


if __name__ == "__main__":
    sys.exit(main())
