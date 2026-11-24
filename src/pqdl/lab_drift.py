"""Drift analyses on the lab flows (data/flows/lab_flows.csv, source = pq_lab): H1, H3 and H4.

- H3 (application-phase invariance): for each workload, do the app_* features depend on the crypto profile?
  Effect sizes per feature: eta squared across profiles, PSI of each profile vs the reference profile, and MMD on
  the standardised app features, each beside a permutation noise floor (what randomly permuted profile labels give).
- H1 (what explains handshake drift): two-way analysis (kem, auth, interaction) with partial eta squared for the
  hs_* features on the fully crossed chain=leaf_int flows, with deterministic features flagged.
- H4 (flow-level view): the same effect sizes for the whole-connection features an off-the-shelf detector sees.

Effect sizes are the headline. The noise floors are a yardstick for them, not significance tests. Nothing here is
hard-coded; the notes document is generated from the computed tables.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

import pandas as pd

from pqdl.drift import invariance_table, summarise_invariance, two_way_table
from pqdl.features import FEATURES_VERSION, LAB_APP_FEATURES, LAB_FLOW_FEATURES, LAB_HS_FEATURES
from pqdl.loaders import assert_single_source

REF_PROFILE = "X25519|ecdsa_p256|leaf_int"
SIZE_COLUMNS = tuple(n for n in LAB_APP_FEATURES if "_size_" in n)
EFFECT_COLUMNS = ["eta2", "eta2_all_groups", "partial_eta2", "psi", "mmd2", "noise95_eta2", "noise95_max_psi"]
ID_COLUMNS = ["test", "workload", "feature", "ref_group", "compared_group", "term", "deterministic", "design",
              "psi_mode", "n_ref", "n_group", "mmd_n_ref", "mmd_n_group", "mmd_gamma", "note", "source", "features_version"]

CAVEATS = [
    "**Single lab topology.** One client and one server container on one Docker network, on one laptop. Nothing "
    "here says how the effects look on a real path.",
    "**Local network.** No real RTT, jitter or loss: timing features reflect scheduling on one machine, and "
    "retransmissions essentially do not occur.",
    "**Session tickets are disabled** (`-no_ticket -num_tickets 0`), so no NewSessionTicket records appear after the "
    "handshake. A deployment with tickets would add bytes to the application phase of every profile.",
    "**Pinned groups and signature algorithms.** Each profile pins exactly one KEM group and one signature "
    "algorithm on both sides; real clients offer many and servers choose.",
    "**Benign workloads are scripted** (seeded file requests with fixed sizes and pauses), the two attack-like "
    "workloads are scripted too. They are far from real traffic and from each other, so any detector separates "
    "them easily.",
    "**Same seed for every profile** (1234). Each profile's workload sequence is identical, so differences between "
    "profiles are not caused by different request mixes, but the lab does not average over seeds.",
    "**Packet features are valid only with NIC offloads off** (`capture_offload_ok`); the analysis refuses to run if "
    "any pcap says otherwise.",
    "**Statistical yardstick, not a test.** `noise95_*` is the 95th percentile of the statistic when profile labels "
    "are randomly permuted within a workload; a feature is called 'not invariant' when its effect size exceeds it. "
    "It depends on the sample size per profile (benign 300, flood 200, slow_send 50 flows).",
    "**A profile is one pcap per workload, so profile and pcap are confounded.** Anything that changed between "
    "pcaps (laptop load, scheduling, position in the run) is perfectly mixed with the crypto profile. The permutation "
    "noise floor shuffles flows, not pcaps, so it cannot see pcap-level effects and understates the noise of timing "
    "features. Byte and packet-count features are not affected (they are fixed by the workload and the handshake), "
    "but timing effects (IAT, durations) cannot be attributed to the profile without replicate captures of the same "
    "profile.",
    "**First-ten packet sizes** (`app_*_size_k`): a missing k-th packet is entered as 0 for this analysis. "
    "Other NaN statistics (for example IAT with fewer than two packets) are dropped feature by feature, and rows "
    "with any NaN are dropped from the MMD.",
]


@dataclass(frozen=True)
class LabDriftResult:
    results: pd.DataFrame     # long table written to results/lab_drift.csv
    notes: str                # markdown for docs/lab_drift_notes.md
    h3_summary: pd.DataFrame  # per workload and app feature: effect sizes vs noise floors
    h1: pd.DataFrame          # two-way partial eta squared per workload, hs feature and term
    h4_summary: pd.DataFrame  # per workload and flow feature: effect sizes vs noise floors


def cipher_suite_caveat(flows: pd.DataFrame) -> str:
    """Caveat computed from the data: which ServerHello cipher suite(s) occur."""
    suites = sorted({int(v) for v in flows["sh_cipher_suite"].dropna().unique()}) if "sh_cipher_suite" in flows else []
    names = ", ".join(hex(s) for s in suites) if suites else "unknown"
    one = len(suites) == 1
    return (f"**{'One cipher suite' if one else 'Cipher suites'}** in the data: {names}"
            + (" (every connection uses the same AEAD, so record overhead is identical across profiles; another suite "
               "would change record sizes)." if one else "."))


def timing_flags(flows: pd.DataFrame, manifest: pd.DataFrame) -> pd.DataFrame:
    """benign_web flow_duration per profile with the pcap start time and a MAD flag.

    Flag: |median_p - M| > 3 * MAD, M = median of the per-profile medians, MAD = median absolute deviation of those
    medians across profiles (raw, not scaled). Reported only; no data is dropped.
    """
    web = flows[flows["workload"] == "benign_web"]
    per = web.groupby(["kem", "auth", "chain"]).agg(pcap_file=("pcap_file", "first"), median_s=("flow_duration", "median"),
                                                    p95_s=("flow_duration", lambda s: s.quantile(0.95))).reset_index()
    per = per.merge(manifest[["pcap_file", "start_utc"]], on="pcap_file", how="left")
    center = per["median_s"].median()
    per["abs_dev"] = (per["median_s"] - center).abs()
    mad = per["abs_dev"].median()
    per["dev_in_MADs"] = per["abs_dev"] / mad if mad > 0 else float("nan")
    per["flag"] = per["abs_dev"] > 3 * mad
    return per.sort_values("start_utc")


def timing_caveat(flows: pd.DataFrame, manifest: pd.DataFrame | None) -> str:
    """Caveat computed from the data: benign_web pcaps whose median flow_duration is a timing outlier."""
    if manifest is None:
        return "**Timing outliers were not checked** (no manifest was supplied)."
    flagged = timing_flags(flows, manifest).query("flag")
    if flagged.empty:
        return "**No benign_web pcap is a timing outlier** (median flow_duration within 3 MADs of the other profiles)."
    items = "; ".join(f"`{r.kem}|{r.auth}|{r.chain}` (started {r.start_utc}, median {r.median_s * 1000:.2f} ms, "
                      f"{r.dev_in_MADs:.2f} MADs from the median of profile medians)" for r in flagged.itertuples())
    return (f"**{len(flagged)} benign_web pcap(s) flagged for timing:** {items}. Timing may have been disturbed by "
            "activity on the laptop; cause unknown. No data was dropped, so timing-based features for that profile "
            "(`hs_duration`, `app_duration`, `app_iat_*`, `flow_duration`, `flow_iat_*`) should be read with care.")


def add_profile(flows: pd.DataFrame) -> pd.DataFrame:
    """Add the profile column 'kem|auth|chain'."""
    out = flows.copy()
    out["profile"] = out["kem"].astype(str) + "|" + out["auth"].astype(str) + "|" + out["chain"].astype(str)
    return out


def require_valid_capture(flows: pd.DataFrame) -> None:
    """Raise if any flow comes from a pcap whose NIC offloads were not verified off (packet features unusable)."""
    ok = flows["capture_offload_ok"].astype(str).str.lower() == "true"
    if not ok.all():
        bad = sorted(flows.loc[~ok, "pcap_file"].unique())
        raise ValueError(f"capture_offload_ok is false for {len(bad)} pcap(s), e.g. {bad[:3]}; packet features are invalid")


def fill_absent_sizes(df: pd.DataFrame) -> pd.DataFrame:
    """Enter a missing k-th packet size (NaN) as 0 in the app_*_size_k columns."""
    out = df.copy()
    cols = [c for c in SIZE_COLUMNS if c in out.columns]
    out[cols] = out[cols].fillna(0.0)
    return out


def _tag(frame: pd.DataFrame, test: str, workload: str) -> pd.DataFrame:
    out = frame.copy()
    out.insert(0, "workload", workload)
    out.insert(0, "test", test)
    return out


def invariance_for_workloads(flows: pd.DataFrame, features: Sequence[str], test: str, n_noise: int, max_n: int,
                             seed: int, fill_sizes: bool) -> tuple[pd.DataFrame, pd.DataFrame]:
    """invariance_table + summary for each workload separately, over every profile in `flows`."""
    tables, summaries = [], []
    for workload, df in flows.groupby("workload", sort=True):
        df = fill_absent_sizes(df) if fill_sizes else df
        if REF_PROFILE not in set(df["profile"]):
            raise ValueError(f"reference profile {REF_PROFILE} missing for workload {workload}")
        table = invariance_table(df, "profile", REF_PROFILE, features, n_noise=n_noise, max_n=max_n, seed=seed)
        tables.append(_tag(table, test, workload))
        summaries.append(_tag(summarise_invariance(table), test, workload))
    return pd.concat(tables, ignore_index=True), pd.concat(summaries, ignore_index=True)


def handshake_two_way(flows: pd.DataFrame) -> pd.DataFrame:
    """H1: two-way (kem, auth) analysis of the hs_* features on the crossed leaf_int flows, per workload."""
    crossed = flows[flows["chain"] == "leaf_int"]
    return pd.concat([_tag(two_way_table(df, LAB_HS_FEATURES, "kem", "auth"), "H1_handshake_two_way", w)
                      for w, df in crossed.groupby("workload", sort=True)], ignore_index=True)


# ------------------------------------------------------------------------------ rendering
def _fmt(x: object) -> str:
    if isinstance(x, (bool,)):
        return str(x)
    if isinstance(x, (int,)):
        return str(x)
    try:
        return "NaN" if pd.isna(x) else f"{float(x):.4g}"
    except (TypeError, ValueError):
        return str(x)


def md_table(frame: pd.DataFrame) -> list[str]:
    cols = list(frame.columns)
    rows = ["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
    rows += ["| " + " | ".join(_fmt(v) for v in r) + " |" for r in frame.itertuples(index=False)]
    return rows


def _invariance_section(title: str, summary: pd.DataFrame, intro: str) -> list[str]:
    out = [f"\n## {title}\n", intro]
    for workload, g in summary.groupby("workload", sort=True):
        flagged = g[g["not_invariant"]].sort_values("eta2_all_groups", ascending=False)
        out.append(f"\n### {workload}: {len(flagged)} of {len(g)} features NOT invariant "
                   f"({int(g['eta2_above_noise'].sum())} by eta squared, {int(g['psi_above_noise'].sum())} by PSI)\n")
        if len(flagged):
            cols = ["feature", "eta2_all_groups", "noise95_eta2", "max_psi", "noise95_max_psi", "max_mmd2"]
            out += md_table(flagged[cols])
        invariant = g[~g["not_invariant"]]["feature"].tolist()
        out.append(f"\nInvariant within the noise floor ({len(invariant)}): {', '.join(invariant) if invariant else 'none'}")
    return out


def _h1_section(h1: pd.DataFrame) -> list[str]:
    out = ["\n## H1: what explains handshake drift (kem x auth, chain = leaf_int)\n",
           "Partial eta squared per term. `hs_*_bytes`, `hs_*_pkts` and `hs_records` are usually exact functions of "
           "the profile: zero spread inside a (kem, auth) cell, so there is no residual and their partial eta squared "
           "is trivially 1 for any factor that changes them (and 0 otherwise). The informative rows are the "
           "non-deterministic features (timing)."]
    nondet_bytes = sorted(h1[(~h1["deterministic"]) & h1["feature"].str.endswith("_bytes")]["feature"].unique())
    if nondet_bytes:
        spread = h1[h1["feature"].isin(nondet_bytes)].groupby("feature")["max_within_cell_std"].max()
        out.append("\n**Byte features with a few bytes of spread inside some cells** (listed as non-deterministic on "
                   f"purpose): {', '.join(f'{f} (max within-cell std {v:.3g} B)' for f, v in spread.items())}. "
                   "The cause is the ECDSA cells: ECDSA signatures are variable-length DER (70-72 bytes), so the "
                   "CertificateVerify and the certificates' own signatures change the handshake size by a few bytes "
                   "from connection to connection, and each pcap ran on a freshly generated PKI. ML-DSA signatures "
                   "have fixed length, so those cells have zero spread. The spread is a tiny fraction of the "
                   "between-cell differences, so the partial eta squared of these features stays close to 1: read "
                   "them as near-deterministic, not as timing-like noise.")
    wide = h1.pivot_table(index=["workload", "feature", "deterministic", "max_within_cell_std"], columns="term",
                          values="partial_eta2", sort=False).reset_index()
    wide.columns.name = None
    for det, title in ((True, "Deterministic within a cell (trivial effects)"), (False, "Non-deterministic (informative)")):
        part = wide[wide["deterministic"] == det].drop(columns="deterministic")
        out.append(f"\n### {title}\n")
        out += md_table(part) if len(part) else ["none"]
    return out


def render_notes(h3_summary: pd.DataFrame, h1: pd.DataFrame, h4_summary: pd.DataFrame, n_flows: int, n_profiles: int,
                 data_caveats: Sequence[str] = ()) -> str:
    lines = ["# Lab drift notes (generated)\n",
             f"Generated by `scripts/lab_drift.py` from `data/flows/lab_flows.csv` (source `pq_lab`): {n_flows} flows, "
             f"{n_profiles} profiles (kem | auth | chain). Feature lists: `pqdl.features` version `{FEATURES_VERSION}`. "
             f"Reference profile for PSI and MMD: `{REF_PROFILE}`. Full numbers: `results/lab_drift.csv`.",
             "\n## Caveats\n", *[f"- {c}" for c in [*CAVEATS, *data_caveats]]]
    lines += _invariance_section(
        "H3: application-phase invariance (app_* features vs crypto profile)", h3_summary,
        "For each workload separately. `eta2_all_groups` = share of the feature's variance explained by profile; "
        "`max_psi` = the largest PSI of any profile against the reference; `noise95_*` = the same statistic under "
        "randomly permuted profile labels (95th percentile); `max_mmd2` = largest MMD^2 of any profile vs the "
        "reference on all standardised app features.")
    lines += _h1_section(h1)
    lines += _invariance_section(
        "H4: whole-connection flow features (what an off-the-shelf detector sees)", h4_summary,
        "Same statistics for the CICFlowMeter-like `flow_*` features, per workload, over all profiles.")
    return "\n".join(lines) + "\n"


def run_lab_drift(flows: pd.DataFrame, n_noise: int = 200, max_n: int = 2000, seed: int = 0,
                  manifest: pd.DataFrame | None = None) -> LabDriftResult:
    """Run H3, H1 and H4 on the lab flows and return the long results table plus the generated notes.

    `manifest` (data/pcaps/manifest.csv) is only used to add the timing-outlier caveat (needs each pcap's start time).
    """
    assert_single_source(flows)
    require_valid_capture(flows)
    flows = add_profile(flows)
    h3, h3_sum = invariance_for_workloads(flows, LAB_APP_FEATURES, "H3_app_invariance", n_noise, max_n, seed, True)
    h4, h4_sum = invariance_for_workloads(flows, LAB_FLOW_FEATURES, "H4_flow_features", n_noise, max_n, seed, False)
    h1 = handshake_two_way(flows)
    results = pd.concat([h3, h1, h4], ignore_index=True)
    results["source"] = flows["source"].iloc[0]
    results["features_version"] = FEATURES_VERSION
    ordered = EFFECT_COLUMNS + ID_COLUMNS
    results = results.reindex(columns=ordered + [c for c in results.columns if c not in ordered])
    caveats = [cipher_suite_caveat(flows), timing_caveat(flows, manifest)]
    notes = render_notes(h3_sum, h1, h4_sum, len(flows), flows["profile"].nunique(), caveats)
    return LabDriftResult(results, notes, h3_sum, h1, h4_sum)
