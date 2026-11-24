"""Audit the feature lists in pqdl.features against the real data; write docs/feature_audit.md.

Everything in the output is computed from the data (via the loaders' default settings).
Run from the repo root:  .venv/Scripts/python scripts/feature_audit.py
"""

from __future__ import annotations

import itertools
import sys
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from pqdl import features as ft
from pqdl.loaders import assert_single_source, load_cic_ids2017, load_pqc_oav, row_keys

OUT = Path(__file__).resolve().parents[1] / "docs" / "feature_audit.md"
PQC_INDICATOR_GROUPS = ("e1_alg_suite", "e8_proto_context", "e9_conn_outcome", "e3_sig_alg",
                        "e1b_tls_version", "e1b_ciphersuite", "e2b_tls_version", "e2b_ciphersuite",
                        "e3_cert_parsed")
MAX_CONFLICT_ROWS_SHOWN = 40


def md_table(headers: list[str], rows: list[list[Any]]) -> list[str]:
    lines = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    return lines + ["| " + " | ".join(str(c) for c in r) + " |" for r in rows]


def fmt(x: Any) -> str:
    if isinstance(x, (bool, np.bool_)):
        return str(bool(x))
    if pd.isna(x):
        return "NaN"
    return f"{float(x):.6g}"


# ------------------------------------------------------------------ heuristic feature kinds
def pqc_kind(name: str, dtype: Any) -> str:
    n = name.lower()
    if "time" in n or "duration" in n:
        return "timing"
    if "bytes" in n or "size" in n or "record_len" in n:
        return "size"
    if "entropy" in n:
        return "entropy (payload randomness)"
    if dtype == bool:
        group = next((g for g in PQC_INDICATOR_GROUPS if name.startswith(g)), "?")
        return f"indicator ({group})"
    return "other"


def ids_kind(name: str) -> str:
    n = name.lower()
    if n.endswith("/s") or "rate" in n:
        return "rate"
    if any(k in n for k in ("iat", "duration", "idle", "active")):
        return "timing"
    if any(k in n for k in ("length", "bytes", "size", "win", "header")):
        return "size"
    if any(k in n for k in ("packets", "count", "flags", "pkt")):
        return "count"
    return "categorical code" if n == "protocol" else "other"


# --------------------------------------------------------------------------- feature tables
def pqc_feature_rows(df: pd.DataFrame) -> list[list[Any]]:
    normal = df[df["label_raw"] == "Normal"]
    rows = []
    for c in ft.PQC_HANDSHAKE_FEATURES:
        s = df[c]
        rows.append([f"`{c}`", s.dtype, int(s.isna().sum()), int(s.nunique()), int(normal[c].nunique()),
                     fmt(s.min()), fmt(s.max()), pqc_kind(c, s.dtype)])
    return rows


def ids_feature_rows(df: pd.DataFrame) -> tuple[list[list[Any]], list[str]]:
    rows, constant = [], []
    for c in ft.IDS_FLOW_FEATURES:
        s = df[c]
        nunique = int(s.nunique())
        if nunique <= 1:
            constant.append(c)
        rows.append([f"`{c}`", int(s.isna().sum()), nunique, fmt(s.min()), fmt(s.max()), ids_kind(c)])
    return rows, constant


# ------------------------------------------------------------------------- label conflicts
def label_conflicts(df: pd.DataFrame, feats: tuple[str, ...], label_col: str) -> dict[str, Any]:
    """Groups of rows with identical feature vectors (NaN == NaN) but more than one label."""
    keys = row_keys(df[list(feats)])
    frame = pd.DataFrame({"a": keys["a"].to_numpy(), "b": keys["b"].to_numpy(),
                          "label": df[label_col].astype(str).to_numpy()})
    distinct = frame.drop_duplicates()
    n_labels = distinct.groupby(["a", "b"]).size()
    conflicting = n_labels[n_labels > 1].index
    if len(conflicting) == 0:
        return {"groups": 0, "rows": 0, "table": [], "total_rows": len(df)}
    conf = frame.set_index(["a", "b"]).loc[conflicting].reset_index()
    sets = conf.drop_duplicates().groupby(["a", "b"])["label"].agg(lambda s: tuple(sorted(s)))
    per_label = conf.groupby(["a", "b", "label"]).size().rename("n").reset_index()
    per_label["set"] = sets.loc[list(zip(per_label["a"], per_label["b"]))].to_numpy()
    table = []
    for label_set, part in per_label.groupby("set"):
        by_label = part.groupby("label")["n"].sum()
        table.append([" vs ".join(label_set), part[["a", "b"]].drop_duplicates().shape[0],
                      int(by_label.sum()), ", ".join(f"{k}: {int(v)}" for k, v in by_label.items())])
    table.sort(key=lambda r: -r[2])
    return {"groups": int(len(conflicting)), "rows": int(per_label["n"].sum()), "table": table,
            "total_rows": len(df)}


def conflict_section(title: str, res: dict[str, Any]) -> list[str]:
    pct = 100 * res["rows"] / res["total_rows"]
    out = [f"\n#### {title}\n",
           f"- feature-identical groups with more than one label: **{res['groups']}**",
           f"- rows inside those groups: **{res['rows']}** of {res['total_rows']} ({pct:.3f}%)"]
    if not res["table"]:
        return out
    shown = res["table"][:MAX_CONFLICT_ROWS_SHOWN]
    out += ["", *md_table(["label set", "groups", "rows", "rows per label"], shown)]
    if len(res["table"]) > len(shown):
        out.append(f"\n(top {len(shown)} of {len(res['table'])} label sets by rows)")
    return out


# ------------------------------------------------------------------------------ cell table
def crossed_subdesigns(table: pd.DataFrame) -> list[tuple[list[str], list[str]]]:
    """Maximal (kem subset, auth subset) blocks with >=2 of each where every cell is non-empty."""
    present = table > 0
    blocks: list[tuple[list[str], list[str]]] = []
    for size in range(2, len(table.index) + 1):
        for kems in itertools.combinations(table.index, size):
            auths = [a for a in table.columns if present.loc[list(kems), a].all()]
            if len(auths) >= 2:
                blocks.append((list(kems), auths))
    return [b for b in blocks
            if not any(b != o and set(b[0]) <= set(o[0]) and set(b[1]) <= set(o[1]) for o in blocks)]


def cell_section(pqc: pd.DataFrame) -> list[str]:
    normal = pqc[pqc["label_raw"] == "Normal"]
    table = pd.crosstab(normal["kem_scenario"], normal["auth_scenario"])
    nonzero = table.to_numpy()[table.to_numpy() > 0]
    crossed = bool((table > 0).all().all())
    balanced = bool(len(set(nonzero.tolist())) == 1)
    rows = [[k, *[int(v) for v in table.loc[k]]] for k in table.index]
    out = [f"\nNormal rows: {len(normal)} (kem_scenario x auth_scenario; 0 = combination absent)\n",
           *md_table(["kem_scenario \\ auth_scenario", *table.columns], rows),
           "", f"- fully crossed (every kem x auth cell non-empty): **{crossed}**",
           f"- empty cells: **{int((table == 0).to_numpy().sum())}** of {table.size}",
           f"- balanced (all non-empty cells have the same count): **{balanced}** "
           f"(counts present: {sorted(set(nonzero.tolist()))})",
           "", "Maximal fully-crossed sub-designs (>=2 kems x >=2 auths, every cell non-empty):", ""]
    blocks = crossed_subdesigns(table)
    out += [f"- kems {k} x auths {a}" for k, a in blocks] or ["- none"]
    return out


# ------------------------------------------------------------------------------------ main
def main() -> None:
    pqc, pqc_rep = load_pqc_oav()
    ids, ids_rep = load_cic_ids2017()
    assert_single_source(pqc)
    assert_single_source(ids)
    ids_rows, ids_const = ids_feature_rows(ids)

    out: list[str] = [
        "# Feature audit (generated)\n",
        f"Generated by `scripts/feature_audit.py` from the real data. Feature-list version: "
        f"`{ft.FEATURES_VERSION}` (`src/pqdl/features.py`). Do not edit by hand; re-run the script.\n",
        f"- CIC-PQC_OAV: {len(pqc)} rows (loader defaults).",
        f"- CIC-IDS2017: {len(ids)} rows after loader defaults (dedupe=`{ids_rep['dedupe']}`, "
        f"{ids_rep['rows_dropped']['all_nan_rows']} all-NaN rows and "
        f"{ids_rep['rows_dropped']['duplicate_rows']} duplicate rows removed).",
        "- The two datasets are audited separately and never combined.",
        "\n## 1. CIC-PQC_OAV: PQC_HANDSHAKE_FEATURES (32)\n",
        "`kind` is a NAME-BASED heuristic (verify by hand). `unique(all)` / `unique(normal)` count distinct "
        "non-NaN values over all rows / over Normal rows only. min/max of booleans are False/True.\n",
        *md_table(["feature", "dtype", "NaN", "unique(all)", "unique(normal)", "min", "max", "kind"],
                  pqc_feature_rows(pqc)),
        "\n## 2. CIC-PQC_OAV: PQC_EXCLUDED\n",
        *md_table(["column", "reason"], [[f"`{k}`", v] for k, v in ft.PQC_EXCLUDED.items()]),
        f"\n## 3. CIC-IDS2017: IDS_FLOW_FEATURES ({len(ft.IDS_FLOW_FEATURES)})\n",
        "`kind` is a NAME-BASED heuristic (verify by hand). Statistics are over the loader output "
        "(+/-inf already replaced by NaN).\n",
        *md_table(["feature", "NaN", "unique", "min", "max", "kind"], ids_rows),
        f"\nConstant features (<=1 distinct non-NaN value), still listed: {ids_const or 'none'}",
        "\n## 4. CIC-IDS2017: IDS_EXCLUDED\n",
        *md_table(["column", "reason"], [[f"`{k}`", v] for k, v in ft.IDS_EXCLUDED.items()]),
        "\n## 5. Label conflicts (identical features, different labels)\n",
        "Rows are grouped by an exact 128-bit hash of the listed feature columns only (NaN counts as "
        "equal to NaN). Each group that carries more than one distinct label is a conflict.",
    ]
    out += conflict_section(f"CIC-IDS2017, IDS_FLOW_FEATURES, label = `Label`", label_conflicts(ids, ft.IDS_FLOW_FEATURES, "Label"))
    out += conflict_section("CIC-PQC_OAV, PQC_HANDSHAKE_FEATURES, label = `label_raw` (Normal/Anomaly)",
                            label_conflicts(pqc, ft.PQC_HANDSHAKE_FEATURES, "label_raw"))
    out += conflict_section("CIC-PQC_OAV, PQC_HANDSHAKE_FEATURES, label = `subtype` (finer; baseline_normal vs each anomaly)",
                            label_conflicts(pqc, ft.PQC_HANDSHAKE_FEATURES, "subtype"))
    out += ["\n## 6. CIC-PQC_OAV cell table (design check)", *cell_section(pqc)]
    OUT.write_text("\n".join(out) + "\n", encoding="utf-8")
    print(f"wrote {OUT}")


if __name__ == "__main__":
    sys.exit(main())
