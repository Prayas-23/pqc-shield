"""Turn the lab pcaps listed in data/pcaps/manifest.csv into one row per TCP connection.

Writes data/flows/lab_flows.csv (git-ignored; source = "pq_lab") and prints four validation tables:
  1. connections found vs n_sessions in the manifest
  2. handshake byte counts of the handshake_flood pcaps vs OpenSSL's own read/written counts, taken from
     lab/smoke_test.sh run through docker (computed now, not typed in)
  3. ServerHello key_share group id vs the manifest KEM, for every connection
  4. benign_web application-phase features contain no handshake bytes
Nothing is tuned to make a check pass; mismatches are reported as they are.

Run from the repo root:  .venv/Scripts/python scripts/pcaps_to_flows.py [--no-smoke] [--summary]
                         [--pcaps data/pcaps_mini] [--out data/flows/lab_flows_mini.csv]
--summary prints the four end-of-run tables: (a) flow counts per (kem, auth, chain, workload); (b) distinct
handshake byte values per profile; (c) ServerHello-vs-manifest mismatches; (d) slow_send medians per profile.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pandas as pd

from pqdl.pcap import GROUP_NAMES, KEM_GROUP_IDS, extract_connections, parse_smoke_output

ROOT = Path(__file__).resolve().parents[1]
PCAPS, OUT = ROOT / "data" / "pcaps", ROOT / "data" / "flows" / "lab_flows.csv"
SOURCE = "pq_lab"
IMAGE = "pqdl-lab:openssl-3.5.9"
MANIFEST_COLS = ["kem", "auth", "chain", "workload", "label"]
CAPTURE_COLS = ["intended_sessions", "tcpdump_dropped", "capture_offload_ok", "max_tcp_payload"]
# Validation 4 limit, fixed in advance: TLS adds 22 bytes (5 header + 1 type + 16 tag) per record of up to
# 16 KB, plus the server's close alert (24 B) and the HTTP response header; allow 1% + 100 B over the bytes
# the client logged as received.
BENIGN_OVERHEAD_FRACTION, BENIGN_OVERHEAD_BYTES = 0.01, 100
# Validation 4(a): handshake bytes of each benign connection vs that pcap's own modal value. The observed ECDSA
# DER signature spread is up to 2-3 bytes per pcap; ML-DSA pcaps are expected to show 0. No other tolerance changed.
HS_SPREAD_BYTES = 3


def find_docker() -> str | None:
    found = shutil.which("docker")
    if found:
        return found
    local = os.environ.get("LOCALAPPDATA", "")
    candidate = Path(local) / "Programs" / "DockerDesktop" / "resources" / "bin" / "docker.exe"
    return str(candidate) if candidate.exists() else None


def smoke_reference(kem: str, auth: str, chain: str) -> tuple[int, int] | None:
    """OpenSSL's own (bytes read, bytes written) for this profile, from lab/smoke_test.sh via docker."""
    docker = find_docker()
    if docker is None:
        return None
    out = subprocess.run([docker, "run", "--rm", "-e", f"SMOKE_ONLY={kem}:{auth}", "-e", f"CHAIN={chain}", IMAGE,
                          "/lab/smoke_test.sh"], capture_output=True, text=True, timeout=300).stdout
    ref = parse_smoke_output(out).get((kem, auth))
    return (ref[0], ref[1]) if ref and ref[2] == "PASS" else None


def build_flows(manifest: pd.DataFrame) -> pd.DataFrame:
    frames = []
    for m in manifest.itertuples():
        rows = extract_connections(PCAPS / m.pcap_file)
        df = pd.DataFrame(rows)
        for col in reversed(MANIFEST_COLS):
            df.insert(0, col, getattr(m, col))
        df.insert(0, "source", SOURCE)
        df.insert(len(MANIFEST_COLS) + 1, "pcap_file", m.pcap_file)
        df.insert(len(MANIFEST_COLS) + 2, "conn_index", range(len(df)))
        extra = [c for c in ("replicate_id", "run_order") if c in manifest.columns]   # present in --rep manifests
        for col in reversed(CAPTURE_COLS + extra):
            df.insert(len(MANIFEST_COLS) + 3, col, getattr(m, col))
        frames.append(df)
    return pd.concat(frames, ignore_index=True)


def show(title: str, table: pd.DataFrame) -> None:
    print(f"\n=== {title}\n{table.to_string(index=False)}")


def validation1(flows: pd.DataFrame, manifest: pd.DataFrame) -> bool:
    found = flows.groupby("pcap_file").size()
    t = manifest[["pcap_file", "intended_sessions", "observed_connections"]].copy()
    t["connections_found_now"] = t["pcap_file"].map(found).fillna(0).astype(int)
    t["match"] = (t["intended_sessions"] == t["observed_connections"]) & (t["intended_sessions"] == t["connections_found_now"])
    show("1. connections found vs intended_sessions in the manifest", t)
    return bool(t["match"].all())


def counts(s: pd.Series) -> str:
    return ", ".join(f"{int(k)}x{v}" for k, v in s.value_counts().sort_index().items())


def validation2(flows: pd.DataFrame, use_smoke: bool) -> None:
    rows = []
    for (kem, auth, chain), g in flows[flows["workload"] == "handshake_flood"].groupby(["kem", "auth", "chain"]):
        ref = smoke_reference(kem, auth, chain) if use_smoke else None
        row = {"pcap": g["pcap_file"].iloc[0], "conns": len(g),
               "smoke read/written": f"{ref[0]}/{ref[1]}" if ref else "unavailable",
               "hs_s2c_bytes (value x conns)": counts(g["hs_s2c_bytes"]), "hs_c2s_bytes": counts(g["hs_c2s_bytes"])}
        if ref:
            row["hs_s2c - smoke"] = counts(g["hs_s2c_bytes"] - ref[0])
            row["hs_c2s - smoke"] = counts(g["hs_c2s_bytes"] - ref[1])
        row["leftover app_s2c_bytes"] = counts(g["app_s2c_bytes"])
        row["leftover app_c2s_bytes"] = counts(g["app_c2s_bytes"])
        rows.append(row)
    show("2. handshake_flood: parser handshake bytes vs OpenSSL's own read/written counts (smoke test)", pd.DataFrame(rows))


def validation3(flows: pd.DataFrame) -> bool:
    expected = flows["kem"].map(KEM_GROUP_IDS)
    ok = flows["sh_group_id"] == expected
    t = (flows.assign(ok=ok).groupby("pcap_file")
         .agg(kem=("kem", "first"), expected_id=("kem", lambda s: hex(KEM_GROUP_IDS[s.iloc[0]])), conns=("ok", "size"),
              matches=("ok", "sum"), observed=("sh_group_id", lambda s: ", ".join(f"{hex(int(v))} ({GROUP_NAMES.get(int(v), '?')})" for v in sorted(s.dropna().unique())))
              ).reset_index())
    t["mismatches"] = t["conns"] - t["matches"]
    show("3. ServerHello key_share group id vs the manifest KEM", t)
    return bool((~ok).sum() == 0)


def log_bytes(pcap_file: str) -> list[int]:
    text = (PCAPS / pcap_file.replace(".pcap", ".workload.log")).read_text(errors="replace")
    return [int(b) for b in re.findall(r"status=ok rc=0 bytes_received=(\d+)", text)]


def validation4(flows: pd.DataFrame) -> bool:
    """Check 4 per benign_web pcap.

    (a) every connection's hs_s2c_bytes and hs_c2s_bytes is within HS_SPREAD_BYTES of THAT pcap's own modal value
        (ECDSA signatures are variable-length DER, so a few bytes of spread is expected; ML-DSA must show none);
    (b) hs + app bytes add up to the connection total;
    (c) application-phase server bytes are within 1% + 100 B above what the client logged as received.
    """
    rows, all_ok = [], True
    for pcap, g in flows[flows["workload"] == "benign_web"].groupby("pcap_file"):
        g = g.sort_values("conn_index")
        logged = log_bytes(pcap)
        mode_s2c, mode_c2s = g["hs_s2c_bytes"].mode().iloc[0], g["hs_c2s_bytes"].mode().iloc[0]
        dev_s2c, dev_c2s = int((g["hs_s2c_bytes"] - mode_s2c).abs().max()), int((g["hs_c2s_bytes"] - mode_c2s).abs().max())
        same_hs = dev_s2c <= HS_SPREAD_BYTES and dev_c2s <= HS_SPREAD_BYTES
        identity = bool((g["hs_s2c_bytes"] + g["app_s2c_bytes"] + g["hs_c2s_bytes"] + g["app_c2s_bytes"] == g["total_bytes"]).all())
        n = min(len(g), len(logged))
        over = g["app_s2c_bytes"].to_numpy()[:n] - pd.Series(logged[:n]).to_numpy()
        limit = pd.Series(logged[:n]).to_numpy() * BENIGN_OVERHEAD_FRACTION + BENIGN_OVERHEAD_BYTES
        within = bool(len(g) == len(logged) and ((over >= 0) & (over <= limit)).all())
        all_ok &= within and identity and same_hs
        rows.append({"pcap": pcap, "conns": len(g), "logged sessions": len(logged),
                     "modal hs_s2c": int(mode_s2c), "max |dev| s2c": dev_s2c, "modal hs_c2s": int(mode_c2s),
                     "max |dev| c2s": dev_c2s, f"hs within +/-{HS_SPREAD_BYTES} B of own mode": same_hs,
                     "hs+app == total": identity,
                     "app_s2c - logged bytes (min..max)": f"{int(over.min())}..{int(over.max())}" if n else "-",
                     f"all within {BENIGN_OVERHEAD_FRACTION:.0%}+{BENIGN_OVERHEAD_BYTES} B": within,
                     "app_s2c_bytes (min/median/max)": f"{int(g['app_s2c_bytes'].min())}/{int(g['app_s2c_bytes'].median())}/{int(g['app_s2c_bytes'].max())}"})
    show("4. benign_web: application-phase features contain no handshake bytes", pd.DataFrame(rows))
    return all_ok


def summary_tables(flows: pd.DataFrame, manifest: pd.DataFrame) -> None:
    """End-of-run tables (a)-(e). Reports only; nothing is dropped."""
    key = ["kem", "auth", "chain", "workload"]
    a = flows.groupby(key).agg(flows=("conn_index", "size"), intended_sessions=("intended_sessions", "first")).reset_index()
    a["match"] = a["flows"] == a["intended_sessions"]
    show("(a) flow counts per (kem, auth, chain, workload) next to intended_sessions", a)
    prof = flows.groupby(["kem", "auth", "chain"]).agg(
        distinct_hs_s2c_bytes=("hs_s2c_bytes", "nunique"), distinct_hs_c2s_bytes=("hs_c2s_bytes", "nunique"),
        hs_s2c_values=("hs_s2c_bytes", lambda s: ", ".join(str(int(v)) for v in sorted(s.unique()))),
        hs_c2s_values=("hs_c2s_bytes", lambda s: ", ".join(str(int(v)) for v in sorted(s.unique())))).reset_index()
    show("(b) per profile: distinct hs_s2c_bytes and hs_c2s_bytes values (all workloads)", prof)
    mism = int((flows["sh_group_id"] != flows["kem"].map(KEM_GROUP_IDS)).sum())
    print(f"{chr(10)}=== (c) ServerHello group vs manifest KEM mismatches: {mism} of {len(flows)} connections (must be 0)")
    ciphers = flows.groupby(["sh_cipher_suite", "kem"]).size().rename("connections").reset_index()
    ciphers["sh_cipher_suite"] = ciphers["sh_cipher_suite"].map(lambda v: hex(int(v)) if pd.notna(v) else "none")
    show("(c) ServerHello cipher suite counts (by manifest KEM)", ciphers)
    slow = flows[flows["workload"] == "slow_send"].groupby(["kem", "auth", "chain"]).agg(
        slow_send_flows=("flow_duration", "size"), median_flow_duration_s=("flow_duration", "median"),
        median_app_c2s_pkts=("app_c2s_pkts", "median"), median_app_c2s_bytes=("app_c2s_bytes", "median")).reset_index()
    show("(d) slow_send: median flow_duration and app_c2s_pkts per profile", slow.round(4))
    timing_table(flows, manifest)


def timing_table(flows: pd.DataFrame, manifest: pd.DataFrame) -> None:
    """(e) benign_web flow_duration per profile with the pcap's start time; flag medians far from the rest.

    Flag: |median_p - M| > 3 * MAD, where M is the median of the per-profile medians and MAD the median absolute
    deviation of those medians across profiles (raw, not scaled). Timing may have been disturbed by activity on the
    laptop during the run. Flags are reported; no data is dropped.
    """
    web = flows[flows["workload"] == "benign_web"]
    per = web.groupby(["kem", "auth", "chain"]).agg(
        pcap_file=("pcap_file", "first"), n=("flow_duration", "size"), median_s=("flow_duration", "median"),
        p95_s=("flow_duration", lambda s: s.quantile(0.95))).reset_index()
    per = per.merge(manifest[["pcap_file", "start_utc"]], on="pcap_file", how="left").sort_values("start_utc")
    center = per["median_s"].median()
    mad = (per["median_s"] - center).abs().median()
    per["abs_dev_from_median"] = (per["median_s"] - center).abs()
    per["dev_in_MADs"] = per["abs_dev_from_median"] / mad if mad > 0 else float("nan")
    per["flag_gt_3_MAD"] = per["abs_dev_from_median"] > 3 * mad
    show(f"(e) benign_web flow_duration per profile, in run order (median of per-profile medians M = {center:.6f} s, "
         f"MAD = {mad:.6f} s)", per.drop(columns=["pcap_file"]).round(6))
    flagged = per[per["flag_gt_3_MAD"]]
    print(f"{chr(10)}(e) flagged pcaps (|median - M| > 3 x MAD): {len(flagged)} of {len(per)}"
          + ("" if flagged.empty else " -> " + ", ".join(f"{r.kem}|{r.auth}|{r.chain} @ {r.start_utc}" for r in flagged.itertuples())))


def manifest_checks(flows: pd.DataFrame, manifest: pd.DataFrame) -> None:
    """Totals and the manifest rows that should not exist."""
    print(f"{chr(10)}=== totals: {len(flows)} flows from {len(manifest)} pcaps in {manifest[['kem', 'auth', 'chain']].drop_duplicates().shape[0]} profiles")
    off = manifest[manifest["observed_connections"] != manifest["intended_sessions"]]
    print(f"pcaps with observed_connections != intended_sessions: {len(off)}" + ("" if off.empty else chr(10) + off.to_string(index=False)))
    bad_offload = manifest["capture_offload_ok"].astype(str).str.lower() != "true"
    bad = manifest[bad_offload | (manifest["tcpdump_dropped"] > 0)]
    print(f"manifest rows with capture_offload_ok = false or tcpdump_dropped > 0: {len(bad)}" + ("" if bad.empty else chr(10) + bad.to_string(index=False)))
    print(f"max_tcp_payload over all pcaps: {int(manifest['max_tcp_payload'].max())} (limit 1460)")


def main(argv: list[str]) -> None:
    global PCAPS, OUT
    for flag in ("--pcaps", "--out"):
        if flag in argv:
            value = Path(argv[argv.index(flag) + 1])
            value = value if value.is_absolute() else ROOT / value
            if flag == "--pcaps":
                PCAPS = value
            else:
                OUT = value
    manifest = pd.read_csv(PCAPS / "manifest.csv")
    flows = build_flows(manifest)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    flows.to_csv(OUT, index=False)
    print(f"wrote {OUT}: {len(flows)} connections from {len(manifest)} pcaps, source={SOURCE}")
    v1 = validation1(flows, manifest)
    validation2(flows, use_smoke="--no-smoke" not in argv)
    v3 = validation3(flows)
    v4 = validation4(flows)
    if "--summary" in argv:
        summary_tables(flows, manifest)
        manifest_checks(flows, manifest)
    print(f"\nvalidation 1 (counts match): {v1} | validation 3 (group ids match): {v3} | validation 4 (no handshake bytes in app phase): {v4}")


if __name__ == "__main__":
    main(sys.argv[1:])
