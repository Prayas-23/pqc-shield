"""Replicate-capture timing analysis at the PCAP level -> results/rep_timing*.csv and docs/rep_timing_notes.md.

Run from the repo root:  .venv/Scripts/python scripts/rep_timing.py
Reads data/flows/lab_flows_rep.csv (3 replicates) and data/flows/lab_flows.csv (main run = replicate 0, flagged).
Does not re-run the main-run analysis and does not touch captures.
"""

from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import pandas as pd

from pqdl import rep_timing as rt
from pqdl.labplan import REPLICATE_PROFILES, REPLICATE_WORKLOADS

ROOT = Path(__file__).resolve().parents[1]
SEED, N_PERM, N_BOOT = 20261125, 10_000, 5_000
MAIN = 0                                                    # replicate_id used for the main-run pcaps
REF = ("X25519", "ecdsa_p256")
ALPHA = 0.05


def load_medians() -> pd.DataFrame:
    rep = pd.read_csv(ROOT / "data/flows/lab_flows_rep.csv")
    main = pd.read_csv(ROOT / "data/flows/lab_flows.csv")
    keep = main[(main.chain == "leaf_int")
                & main.set_index(["kem", "auth"]).index.isin(list(REPLICATE_PROFILES))].copy()
    keep["replicate_id"], keep["run_order"] = MAIN, np.nan
    both = pd.concat([rep, keep], ignore_index=True)
    assert set(both["source"]) == {"pq_lab"}
    med = rt.pcap_medians(both)
    med["profile"] = med["kem"] + "|" + med["auth"]
    med["run"] = np.where(med["replicate_id"] == MAIN, "main run", "replicate")
    return med


def matrix(sub: pd.DataFrame, feature: str, reps: list[int]) -> tuple[np.ndarray, np.ndarray, list[str]]:
    """(k profiles x n reps) array of pcap medians, flat values, flat profile codes."""
    profiles = [f"{k}|{a}" for k, a in REPLICATE_PROFILES]
    rows = []
    for p in profiles:
        s = sub[sub.profile == p].set_index("replicate_id")[feature]
        rows.append([s[r] for r in reps])
    arr = np.array(rows, dtype=float)
    return arr, arr.ravel(), profiles


def variance_table(med: pd.DataFrame) -> pd.DataFrame:
    out = []
    for wl in REPLICATE_WORKLOADS:
        sub = med[med.workload == wl]
        for ft in rt.TIMING_FEATURES:
            row: dict = {"workload": wl, "feature": ft}
            for tag, reps in (("all4", [MAIN, 1, 2, 3]), ("rep3", [1, 2, 3])):
                arr, flat, _ = matrix(sub, ft, reps)
                codes = np.repeat(np.arange(arr.shape[0]), arr.shape[1])
                c = rt.variance_components(arr)
                f, p = rt.permutation_f_test(flat, codes, N_PERM, SEED)
                if tag == "all4":
                    lo, hi = rt.bootstrap_icc(arr, N_BOOT, SEED)
                    row.update(n_pcaps=arr.size, var_between=c.var_between, var_within=c.var_within, icc=c.icc,
                               icc_ci_lo=lo, icc_ci_hi=hi, f_ratio=f, perm_p=p)
                else:
                    row.update(icc_rep3=c.icc, f_ratio_rep3=f, perm_p_rep3=p)
            out.append(row)
    df = pd.DataFrame(out)
    df["perm_p_holm"] = df.groupby("workload")["perm_p"].transform(lambda s: rt.holm(s.to_numpy()))
    df["perm_p_rep3_holm"] = df.groupby("workload")["perm_p_rep3"].transform(lambda s: rt.holm(s.to_numpy()))
    return df


def range_table(med: pd.DataFrame) -> pd.DataFrame:
    out = []
    for wl in REPLICATE_WORKLOADS:
        for ft in rt.TIMING_FEATURES:
            for k, a in REPLICATE_PROFILES:
                s = med[(med.workload == wl) & (med.kem == k) & (med.auth == a)].set_index("replicate_id")[ft]
                reps = s[[1, 2, 3]].to_numpy()
                inside, dist = rt.range_check(float(s[MAIN]), reps)
                out.append({"workload": wl, "feature": ft, "profile": f"{k}|{a}", "is_reference": (k, a) == REF,
                            "main_run_median": s[MAIN], "rep_min": reps.min(), "rep_max": reps.max(),
                            "inside_range": inside, "outside_by_frac_of_rep_median": dist})
    return pd.DataFrame(out)


def run_order_table(med: pd.DataFrame) -> pd.DataFrame:
    rep = med[med.run == "replicate"].copy()
    out = []
    for wl in REPLICATE_WORKLOADS:
        sub = rep[rep.workload == wl]
        for ft in rt.TIMING_FEATURES:
            rho, p = rt.spearman(sub["run_order"].to_numpy(), sub[ft].to_numpy())
            centred = sub[ft] - sub.groupby("profile")[ft].transform("mean")   # remove profile means
            rho_c, p_c = rt.spearman(sub["run_order"].to_numpy(), centred.to_numpy())
            out.append({"workload": wl, "feature": ft, "n_pcaps": len(sub), "rho_raw": rho, "p_raw": p,
                        "rho_profile_centred": rho_c, "p_profile_centred": p_c})
    df = pd.DataFrame(out)
    df["p_centred_holm"] = df.groupby("workload")["p_profile_centred"].transform(lambda s: rt.holm(s.to_numpy()))
    return df


def conclusions(var: pd.DataFrame, rng: pd.DataFrame, ordr: pd.DataFrame) -> list[str]:
    lines = []
    for wl in REPLICATE_WORKLOADS:
        v = var[var.workload == wl]
        sig = v[v.perm_p_holm < ALPHA]
        lines.append(f"- **{wl}**: {len(sig)}/{len(v)} timing features have a profile effect at Holm-adjusted p < {ALPHA} "
                     f"(all four pcaps per profile; permutation p floor {1 / (N_PERM + 1):.1e}). "
                     f"Median ICC {v.icc.median():.2f} (range {v.icc.min():.2f} to {v.icc.max():.2f}).")
        for r in v.itertuples():
            lines.append(f"  - {r.feature}: ICC {r.icc:.2f} (95% bootstrap CI {r.icc_ci_lo:.2f} to {r.icc_ci_hi:.2f}), "
                         f"F {r.f_ratio:.3g}, Holm p {r.perm_p_holm:.4f}; replicates only (n=3): ICC {r.icc_rep3:.2f}, "
                         f"Holm p {r.perm_p_rep3_holm:.4f}.")
    ref = rng[rng.is_reference]
    lines.append(f"- **Main-run reference pcap vs its 3 replicates**: inside the replicate range in "
                 f"{int(ref.inside_range.sum())}/{len(ref)} (workload, feature) cells. Outside cells: "
                 + ("; ".join(f"{r.workload}/{r.feature} ({r.outside_by_frac_of_rep_median:.1%} of replicate median)"
                              for r in ref[~ref.inside_range].itertuples()) or "none") + ".")
    allp = rng
    lines.append(f"- All four profiles together: {int(allp.inside_range.sum())}/{len(allp)} cells inside range.")
    sig_o = ordr[ordr.p_centred_holm < ALPHA]
    lines.append(f"- **Run order**: {len(sig_o)}/{len(ordr)} (workload, feature) cells show profile-centred Spearman "
                 f"drift at Holm p < {ALPHA}" + (": " + "; ".join(f"{r.workload}/{r.feature} rho={r.rho_profile_centred:.2f}"
                                                                   for r in sig_o.itertuples()) if len(sig_o) else "") + ".")
    return lines


def write_notes(var: pd.DataFrame, rng: pd.DataFrame, ordr: pd.DataFrame, path: Path) -> None:
    body = ["# Replicate-capture timing analysis (PCAP level)", "",
            "Generated by `scripts/rep_timing.py`; every number below is computed from `data/flows/lab_flows_rep.csv` "
            "and the main-run `data/flows/lab_flows.csv`. Tables: `results/rep_timing.csv`, "
            "`results/rep_timing_range.csv`, `results/rep_timing_runorder.csv`.", "",
            "## Method", "",
            f"- Unit = pcap; statistic = median of the feature over the pcap's connections. 4 profiles (all leaf_int) x "
            f"4 pcaps (replicates 1-3 + the main-run pcap as replicate 0, flagged `main run`) per workload.",
            "- Variance components: balanced one-way random-effects ANOVA. ICC = var_between / (var_between + "
            "var_within); var_within is pcap-to-pcap noise inside one profile. 95% CI: percentile bootstrap, "
            f"pcaps resampled within profile ({N_BOOT} draws, seed {SEED}).",
            f"- Permutation test: profile labels shuffled across the 16 pcaps within each workload ({N_PERM} permutations, "
            "seed fixed), statistic = one-way F of pcap medians. Holm correction across the 6 features within a workload.",
            "- Sensitivity `rep3`: the same ICC and test using replicates 1-3 only (main run excluded, since it was captured "
            "at a different time, in profile-grouped order, with the code commit not recorded).",
            "- Run order: Spearman of run_order vs pcap median over the 12 replicate pcaps per workload; the "
            "`profile_centred` version subtracts each profile's mean first so profile effects cannot masquerade as drift. "
            "The main run has no run_order in the same sequence, so it is excluded.", "",
            "## Conclusions (generated from the numbers)", ""] + conclusions(var, rng, ordr) + [
            "", "## Caveats", "",
            "- Only 4 profiles, 3 replicates plus one main-run pcap each: 4 pcaps per profile gives very wide ICC CIs; the "
            "bootstrap resamples only 4 values per profile.",
            "- Local Docker network on one laptop, one machine, one day: timings do not transfer to real networks.",
            "- The 4 features of a workload are strongly correlated, so Holm over 6 features is conservative and the "
            "'number of significant features' is not a count of independent findings.",
            "- Replicates within a replicate round share the workload seed across profiles (seed 1234 + replicate), "
            "so replicate effects are partly shared by design; the random capture order breaks time-confounding only "
            "in expectation, with one order seed.",
            "- A significant profile effect shows the profiles differ in timing; it does not by itself show the cause "
            "is the cryptography (larger handshakes also change packet counts and flow duration mechanically).",
            "- hs_* features measure the handshake phase and are mechanically linked to handshake size; app_* "
            "features should not be if the phase split is clean."]
    path.write_text("\n".join(body) + "\n", encoding="utf-8", newline="\n")


def main() -> None:
    med = load_medians()
    var, rng, ordr = variance_table(med), range_table(med), run_order_table(med)
    (ROOT / "results").mkdir(exist_ok=True)
    var.to_csv(ROOT / "results/rep_timing.csv", index=False)
    rng.to_csv(ROOT / "results/rep_timing_range.csv", index=False)
    ordr.to_csv(ROOT / "results/rep_timing_runorder.csv", index=False)
    write_notes(var, rng, ordr, ROOT / "docs/rep_timing_notes.md")
    pd.set_option("display.width", 250, "display.max_columns", 30, "display.float_format", "{:.4g}".format)
    print(f"pcaps: {len(med)} ({med.run.value_counts().to_dict()})")
    print("\n== variance components / permutation (all 4 pcaps per profile; rep3 = replicates only)")
    print(var.drop(columns=["n_pcaps"]).to_string(index=False))
    print("\n== main-run reference pcap vs range of its 3 replicates")
    print(rng[rng.is_reference].drop(columns=["profile", "is_reference"]).to_string(index=False))
    print(f"\nall profiles inside range: {int(rng.inside_range.sum())}/{len(rng)}")
    print("\n== run order (Spearman, 12 replicate pcaps per workload)")
    print(ordr.to_string(index=False))


if __name__ == "__main__":
    sys.exit(main())
