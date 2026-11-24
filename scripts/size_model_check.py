"""Compare the handshake size model (pqdl.handshake) with observed sizes in CIC-PQC_OAV.

Uses ONLY normal rows of the real dataset, grouped by (kem_scenario, auth_scenario) cell.
Writes docs/size_model_check.md. Nothing is tuned: every constant comes from pqdl.profiles
(marked VERIFY) or pqdl.handshake defaults; the only free parameter is n_certs on the server
side, which is solved for and reported, never fitted to make residuals small.

Run from the repo root:  .venv/Scripts/python scripts/size_model_check.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from pqdl.eval import (
    best_n_certs,
    best_n_certs_global,
    model_delta_terms,
    predicted_delta,
    residual,
    residual_pct,
    solve_n_certs,
    total_flight_bytes,
)
from pqdl.loaders import DATA_DIR, assert_single_source, load_pqc_oav
from pqdl.profiles import Overheads, Profile, SIZES

OUT = Path(__file__).resolve().parents[1] / "docs" / "size_model_check.md"
JSONL = DATA_DIR / "cic_pqc_oav" / "raw_sessions.jsonl"

# Dataset scenario names -> SIZES names. 'rsa' is deliberately absent (size not determinable).
KEM_MAP = {"X25519": "X25519", "mlkem768": "MLKEM768", "mlkem1024": "MLKEM1024"}
AUTH_MAP = {"ecdsa_p256": "ECDSA-P256", "ecdsa_p384": "ECDSA-P384", "mldsa65": "MLDSA65",
            "mldsa87": "MLDSA87", "rsa3072": "RSA3072"}
REF_CELL = ("X25519", "ecdsa_p256")
RECORD_HEADER = 5  # bytes of TLS record header
CANDIDATE_N = (1, 2, 3)
OBS = ["e2_client_size", "e2_client_record_len", "e2_server_record_len", "e2c_total_bytes"]
# JSONL fields that could reveal certificate / key sizes; values meaning "not available".
CERT_FIELDS = [("e3_cert_info", "sig_alg"), ("e3_cert_info", "parsed"), ("e2_struct_ke", "server_size"),
               ("e2b_tls12_struct", "key_length"), ("e2b_tls12_struct", "key_type")]
NOT_AVAILABLE = {"N/A", "UNKNOWN", "False", "None"}


def md_table(headers: list[str], rows: list[list[Any]]) -> list[str]:
    return ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)] + [
        "| " + " | ".join(str(c) for c in r) + " |" for r in rows]


def num(x: float, digits: int = 1) -> str:
    if x is None or (isinstance(x, float) and np.isnan(x)):
        return "NaN"
    return f"{x:.{digits}f}"


def values(s: pd.Series) -> str:
    vals = sorted(s.unique())
    text = [str(int(v)) if float(v).is_integer() else f"{v:g}" for v in vals]
    if len(vals) > 8:
        return f"{len(vals)} distinct, {text[0]}..{text[-1]}"
    return "{" + ", ".join(text) + "}"


def cell_name(kem: str, auth: str) -> str:
    return f"{kem}+{auth}"


def profile_of(kem: str, auth: str) -> Profile:
    return Profile(KEM_MAP[kem], AUTH_MAP[auth], "TCP")


# ----------------------------------------------------------------------- RSA size evidence
def rsa_size_evidence() -> tuple[bool, list[list[Any]]]:
    """Distinct values of every candidate cert/key-size field on normal rows, per auth scenario."""
    seen: dict[tuple[str, str, str], set[str]] = {}
    with JSONL.open(encoding="utf-8") as fh:
        for line in fh:
            rec = json.loads(line)
            name = rec["scenario_id"].split("\\")[-1]
            if not name.startswith("normal_"):
                continue
            auth = name.rsplit("_run", 1)[0].split("_", 2)[2].removesuffix("_cert")
            for group, field in CERT_FIELDS:
                seen.setdefault((auth, group, field), set()).add(str(rec[group][field]))
    rows = [[auth, f"{g}.{f}", sorted(v)] for (auth, g, f), v in sorted(seen.items())]
    informative = any(set(v) - NOT_AVAILABLE for (auth, _, _), v in seen.items() if auth.startswith("rsa"))
    return informative, rows


# --------------------------------------------------------------------------- the three parts
def observed_rows(normal: pd.DataFrame) -> list[list[Any]]:
    rows = []
    for (kem, auth), g in normal.groupby(["kem_scenario", "auth_scenario"]):
        for col in OBS:
            rows.append([cell_name(kem, auth), col, len(g), values(g[col]), num(g[col].mean(), 3)])
    return rows


def client_rows(normal: pd.DataFrame) -> tuple[list[list[Any]], dict[str, bool]]:
    base = Overheads().ch_base + RECORD_HEADER
    rows, exact = [], {"share": True, "header": True}
    for (kem, auth), g in normal.groupby(["kem_scenario", "auth_scenario"]):
        share = SIZES["kem"][KEM_MAP[kem]][0]
        hdr = g["e2_client_record_len"] - g["e2_client_size"]
        r_share = residual(g["e2_client_size"].mean(), share)
        r_hdr = residual(hdr.mean(), base)
        exact["share"] &= bool((g["e2_client_size"] == share).all())
        exact["header"] &= bool((hdr == base).all())
        rows.append([cell_name(kem, auth), len(g), values(g["e2_client_size"]), share, num(r_share, 3),
                     values(hdr), base, num(r_hdr, 3)])
    return rows, exact


def server_cells(normal: pd.DataFrame) -> list[tuple[str, str]]:
    cells = normal.groupby(["kem_scenario", "auth_scenario"]).size().index
    return [c for c in cells if c[1] in AUTH_MAP and c != REF_CELL]


def server_analysis(normal: pd.DataFrame) -> dict[str, Any]:
    means = normal.groupby(["kem_scenario", "auth_scenario"])[["e2_server_record_len", "e2c_total_bytes"]].mean()
    ref_profile = profile_of(*REF_CELL)
    # e2_server_record_len is deliberately not compared: it is probably the length of one record, not
    # the whole server flight (it barely varies across cells; see section 1).
    metrics = {"e2c_total_bytes": ("Delta (B_S + B_C)", total_flight_bytes)}
    detail, solve, per_metric = [], [], {}
    for col, (model_name, fn) in metrics.items():
        obs_l, fixed_l, per_l, n_star = [], [], [], {}
        for cell in server_cells(normal):
            obs = float(means.loc[cell, col] - means.loc[REF_CELL, col])
            fixed, per_cert = model_delta_terms(profile_of(*cell), ref_profile, fn)
            obs_l.append(obs), fixed_l.append(fixed), per_l.append(per_cert)
            for n in CANDIDATE_N:
                pred = predicted_delta(fixed, per_cert, n)
                detail.append([cell_name(*cell), col, model_name, n, num(obs), num(pred),
                               num(residual(obs, pred)), num(residual_pct(obs, pred))])
            n_real = solve_n_certs(obs, fixed, per_cert)
            n_star[cell] = n_real
            solve.append([cell_name(*cell), col, num(obs), num(fixed, 0), num(per_cert, 0), num(n_real, 2),
                          best_n_certs(obs, fixed, per_cert, CANDIDATE_N)])
        per_metric[col] = {"n_star": n_star, "global": best_n_certs_global(obs_l, fixed_l, per_l, CANDIDATE_N)}
    return {"detail": detail, "solve": solve, "per_metric": per_metric}


def consistency_lines(analysis: dict[str, Any]) -> list[str]:
    lines = []
    for col, info in analysis["per_metric"].items():
        stars = {c: v for c, v in info["n_star"].items() if not np.isnan(v)}
        vals = list(stars.values())
        rounded = sorted({int(np.rint(v)) for v in vals})
        lines.append(
            f"- `{col}`: solved n_certs per cell ranges {num(min(vals), 2)} to {num(max(vals), 2)} "
            f"(mean {num(float(np.mean(vals)), 2)}); nearest integers across cells: {rounded}; "
            f"best single n in {list(CANDIDATE_N)} over all cells: {info['global']}.")
    return lines


def verdict_lines(analysis: dict[str, Any]) -> list[str]:
    """Plain computed verdicts per metric, from the sign and rounding of the solved n_certs."""
    lines = []
    for col, info in analysis["per_metric"].items():
        stars = {c: v for c, v in info["n_star"].items() if not np.isnan(v)}
        negative = [c for c, v in stars.items() if v < 0]
        rounded = sorted({int(np.rint(v)) for v in stars.values()})
        lo, hi = num(min(stars.values()), 2), num(max(stars.values()), 2)
        if negative:
            verdict = (f"**does not follow the model**: the solved n_certs is negative in {len(negative)} of "
                       f"{len(stars)} cells (range {lo} to {hi}), which no certificate count can produce, so this "
                       "field cannot be read as the size of the server flight")
        elif len(rounded) == 1:
            verdict = (f"**consistent across cells with n_certs = {rounded[0]}** (solved range {lo} to {hi}); "
                       "differences only, n_certs fitted")
        else:
            verdict = f"**not consistent across cells**: solved n_certs (range {lo} to {hi}) rounds to {rounded}"
        lines.append(f"- Server side, `{col}`: {verdict}.")
    return lines


# ------------------------------------------------------------------------------------- main
def main() -> None:
    pqc, _ = load_pqc_oav()
    assert_single_source(pqc)
    normal = pqc[pqc["label_raw"] == "Normal"]
    informative, evidence = rsa_size_evidence()
    client, exact = client_rows(normal)
    server = server_analysis(normal)
    used = [cell_name(*c) for c in server_cells(normal)]
    excluded = sorted({cell_name(k, a) for k, a in normal.groupby(["kem_scenario", "auth_scenario"]).size().index
                       if a not in AUTH_MAP})

    out = [
        "# Size model check (generated)\n",
        "Generated by `scripts/size_model_check.py` from the real CIC-PQC_OAV **normal** rows "
        f"({len(normal)} rows, {normal.groupby(['kem_scenario', 'auth_scenario']).ngroups} cells). Do not edit by hand; re-run the script.",
        "Model = `pqdl.handshake` with sizes from `pqdl.profiles.SIZES` (all marked VERIFY) and default overheads. "
        f"No constant was tuned. Reference cell for differences: `{cell_name(*REF_CELL)}`.\n",
        "## 1. Observed sizes per cell\n",
        *md_table(["cell", "feature", "n", "distinct values", "mean"], observed_rows(normal)),
        "\n## 2. Which RSA is `auth=rsa`?\n",
        "Distinct values of every cert/key-size field in `raw_sessions.jsonl` for normal rows, per auth scenario:\n",
        *md_table(["auth scenario", "field", "distinct values"], evidence),
        f"\nAny informative (not N/A / UNKNOWN / False) value for `rsa`: **{informative}**. "
        + ("" if informative else "No field reveals a certificate or key size, so the RSA size behind `auth=rsa` "
           "**cannot be determined** and is not guessed. Cells with `auth=rsa` are excluded from the server-side "
           f"comparison: {excluded}. (`rsa3072` is named explicitly and is modelled as RSA-3072.)"),
        "\n## 3. Client side (no free parameters; all cells, since the client flight does not depend on auth)\n",
        f"Model: `e2_client_size` = client key share from SIZES; `e2_client_record_len - e2_client_size` = "
        f"ClientHello base {Overheads().ch_base} + {RECORD_HEADER}-byte record header = {Overheads().ch_base + RECORD_HEADER}. "
        "Residual = observed mean - model.\n",
        *md_table(["cell", "n", "observed client_size", "model client_share", "residual",
                   "observed record_len - client_size", "model", "residual"], client),
        "\n## 4. Server side (one free parameter: n_certs); differences from the reference cell only\n",
        f"Cells used: {used}. Observed delta = mean(cell) - mean({cell_name(*REF_CELL)}). Model delta uses the same "
        "n_certs in the cell and in the reference. Only `e2c_total_bytes` is compared; the model quantity is "
        "B_S + B_C. (`e2_server_record_len` is excluded: it is probably the length of a single record, not the "
        "whole server flight.) Residual = observed - predicted; residual % = residual / observed.\n",
        "### 4a. Observed vs predicted delta for n_certs in {1, 2, 3}\n",
        *md_table(["cell", "feature", "model quantity", "n_certs", "observed delta", "predicted delta", "residual",
                   "residual %"], server["detail"]),
        "\n### 4b. Solving for n_certs per cell\n",
        "Model delta is linear: fixed + n_certs * per_cert. `n_certs (solved)` is the real number that makes the "
        "residual exactly 0; `best integer` is the candidate in {1, 2, 3} with the smallest |residual|.\n",
        *md_table(["cell", "feature", "observed delta", "model fixed", "model per_cert", "n_certs (solved)",
                   "best integer"], server["solve"]),
        "\nConsistency across cells:\n", *consistency_lines(server),
        "\n## 5. What the table supports, and what it does not\n",
        "### Supported by the table (computed)\n",
        f"- Client key share: `e2_client_size` equals the model client share in every row of every cell: **{exact['share']}**.",
        f"- Client record offset: `e2_client_record_len - e2_client_size` equals {Overheads().ch_base + RECORD_HEADER} "
        f"(ClientHello base + record header) in every row of every cell: **{exact['header']}** (residuals in section 3).",
        *verdict_lines(server),
        "- Server side residuals at each n_certs in {1, 2, 3}, in sections 4a and 4b.",
        "\n### Not supported\n",
        "- **Absolute sizes.** The meaning of `e2c_total_bytes` in the dataset is not documented in the files we "
        "have, so only differences between cells are compared, never absolute values. Quote any result here as "
        "\"differences only, n_certs fitted\".",
        "- **`e2_server_record_len`.** Not compared (see section 4); the table in section 1 is the only place it appears.",
        "- **A specific n_certs.** n_certs is the only free parameter, so it absorbs any other model error "
        "(wrong certificate encoding, extra extensions, compression). A solved n_certs that looks plausible does "
        "not confirm the model; consistency across cells is the only evidence, and it is limited to the cells listed.",
        "- **RSA cells.** Cells with `auth=rsa` are not compared (size unknown, see section 2).",
        "- **Standard sizes.** Every number in SIZES is marked VERIFY and has not been checked against the standards.",
        "- **Per-row variation.** The model is deterministic; observed values vary row to row (see section 1), "
        "so deltas of means are compared and the spread is not modelled.",
        "- **Transport effects.** TCP/IP headers, TLS record overhead per fragment, retransmissions and handshake "
        "compression are not modelled; if they differ between cells they appear as residuals.",
        "- **Anything about real networks.** CIC-PQC_OAV is a synthetic container testbed.",
    ]
    OUT.write_text("\n".join(out) + "\n", encoding="utf-8")
    print(f"wrote {OUT}")


if __name__ == "__main__":
    sys.exit(main())
