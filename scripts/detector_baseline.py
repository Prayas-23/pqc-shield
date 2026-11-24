"""Detector baseline on the lab flows: how do naive / oracle / pooled detectors behave across the 18 profiles?

Run from the repo root:  .venv/Scripts/python scripts/detector_baseline.py [--boot N]
Training and evaluation use data/flows/lab_flows.csv (main run). data/flows/lab_flows_rep.csv is used ONLY to apply
the already-trained naive detectors as an independent confirmation; it is never merged into any training set.
Writes results/detector_baseline.csv (+ _dose_response.csv, _confirmation.csv) and docs/detector_notes.md.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

import pandas as pd
from scipy.stats import spearmanr

from pqdl import detectors as dt
from pqdl.loaders import assert_single_source

ROOT = Path(__file__).resolve().parents[1]
SEEDS = (11, 12, 13, 14, 15)                 # model seeds (5 repeats)
BOOT_SEED = 20261126
CLASSICAL = "X25519|ecdsa_p256|leaf_int"
Rows = list[dict]


def load(name: str) -> pd.DataFrame:
    df = pd.read_csv(ROOT / "data" / "flows" / name)
    assert_single_source(df)                  # one source per call; add_labels and time_block_split assert again
    return dt.time_block_split(dt.add_labels(df))


def evaluate(rows: Rows, dataset: str, df_test: pd.DataFrame, det: str, method: str, view: str,
             dom: dt.Domain, n_boot: int) -> None:
    """Score the test block of every profile in `df_test` with `dom`; append one row per metric."""
    cols = dt.VIEWS[view]
    for profile, g in df_test.groupby("profile", sort=True):
        scores = dom.score(dt.design_matrix(g, cols))
        summ = dt.summarise(scores, g["attack_type"].to_numpy(), dom.thresholds, n_boot, BOOT_SEED)
        kem, auth, chain = profile.split("|")
        for metric, s in summ.items():
            rows.append({"dataset": dataset, "profile": profile, "kem": kem, "auth": auth, "chain": chain,
                         "detector": det, "method": method, "view": view, "metric": metric, "value": s.value,
                         "seed_sd": s.seed_sd, "ci_lo": s.ci_lo, "ci_hi": s.ci_hi,
                         "n_benign": int((~g["attack"]).sum()), "n_attack": int(g["attack"].sum())})


def blocks(df: pd.DataFrame, block: str, profile: str | None = None) -> pd.DataFrame:
    g = df[df["block"] == block]
    return g if profile is None else g[g["profile"] == profile]


def run_main(main: pd.DataFrame, rep: pd.DataFrame, n_boot: int) -> tuple[pd.DataFrame, dict]:
    rows: Rows = []
    naive: dict[tuple[str, str], dt.Domain] = {}
    t0 = time.time()
    for det in dt.DETECTORS:
        for view, method in (("V_FLOW", "naive"), ("V_APP", "naive_app")):
            naive[(det, view)] = dt.fit_domain(det, dt.VIEWS[view], blocks(main, "train", CLASSICAL),
                                               blocks(main, "val", CLASSICAL), SEEDS)
            evaluate(rows, "main", blocks(main, "test"), det, method, view, naive[(det, view)], n_boot)
        pooled = dt.fit_domain(det, dt.V_FLOW, blocks(main, "train"), blocks(main, "val"), SEEDS)
        evaluate(rows, "main", blocks(main, "test"), det, "pooled", "V_FLOW", pooled, n_boot)
        for profile in sorted(main["profile"].unique()):
            oracle = dt.fit_domain(det, dt.V_FLOW, blocks(main, "train", profile), blocks(main, "val", profile), SEEDS)
            evaluate(rows, "main", blocks(main, "test", profile), det, "oracle", "V_FLOW", oracle, n_boot)
        print(f"  {det} done ({time.time() - t0:.0f} s)", flush=True)
    # independent confirmation: the main-run classical-trained naive detectors on the replicate pcaps
    for det in dt.DETECTORS:
        for view, method in (("V_FLOW", "naive"), ("V_APP", "naive_app")):
            test = blocks(rep, "test")
            evaluate(rows, "rep_all", test, det, method, view, naive[(det, view)], n_boot)
            for r in sorted(test["replicate_id"].unique()):
                evaluate(rows, f"rep_r{int(r)}", test[test["replicate_id"] == r], det, method, view,
                         naive[(det, view)], n_boot)
    return pd.DataFrame(rows), naive


def wide(res: pd.DataFrame, dataset: str, metric: str, view_method: list[str]) -> pd.DataFrame:
    sub = res[(res.dataset == dataset) & (res.metric == metric)]
    return sub.pivot_table(index=["profile", "detector"], columns="method", values="value")[view_method]


def sanity(res: pd.DataFrame) -> tuple[pd.DataFrame, bool]:
    """Classical in-domain check: FPR of the naive detector on the classical test block vs the 5% design point.
    Rule fixed in advance: fail if FPR is above the upper 99% binomial limit for n benign test flows; for the
    continuous-score detectors (ae, iforest) also fail if it is below the lower limit (RF scores tie at 0, so it
    can sit below 5% by construction)."""
    sub = res[(res.dataset == "main") & (res.profile == CLASSICAL) & (res.method == "naive") & (res.metric == "fpr")]
    out = []
    for r in sub.itertuples():
        lo, hi = dt.binomial_band(r.n_benign)
        too_high = r.value > hi
        too_low = r.value < lo and r.detector != "rf"
        out.append({"detector": r.detector, "n_benign_test": r.n_benign, "fpr": r.value, "seed_sd": r.seed_sd,
                    "ci_lo": r.ci_lo, "ci_hi": r.ci_hi, "band_lo": lo, "band_hi": hi, "ok": not (too_high or too_low)})
    df = pd.DataFrame(out)
    return df, bool(df["ok"].all())


def dose_response(res: pd.DataFrame, main: pd.DataFrame) -> pd.DataFrame:
    hs = main.groupby("profile")["hs_s2c_bytes"].median().rename("hs_s2c_median")   # descriptive only, never a feature
    sub = res[(res.dataset == "main") & (res.metric == "fpr") & res.method.isin(["naive", "naive_app"])]
    t = sub.pivot_table(index=["profile", "detector"], columns="method", values="value").reset_index()
    t = t.join(hs, on="profile")
    ci = sub[sub.method == "naive"].set_index(["profile", "detector"])[["ci_lo", "ci_hi"]]
    t = t.join(ci, on=["profile", "detector"]).rename(columns={"naive": "fpr_naive", "naive_app": "fpr_naive_app",
                                                               "ci_lo": "fpr_naive_ci_lo", "ci_hi": "fpr_naive_ci_hi"})
    t["fa_per_10k_naive"] = t["fpr_naive"] * 1e4
    return t.sort_values(["detector", "hs_s2c_median"]).reset_index(drop=True)


def confirmation(res: pd.DataFrame) -> pd.DataFrame:
    keys = ["profile", "detector", "method", "view", "metric"]
    m = res[(res.dataset == "main") & res.method.isin(["naive", "naive_app"])]
    r = res[res.dataset == "rep_all"]
    j = m.merge(r, on=keys, suffixes=("_main", "_rep"))
    j["abs_diff"] = (j["value_main"] - j["value_rep"]).abs()
    j["ci_overlap"] = (j["ci_lo_main"] <= j["ci_hi_rep"]) & (j["ci_lo_rep"] <= j["ci_hi_main"])
    spread = (res[res.dataset.isin(["rep_r1", "rep_r2", "rep_r3"]) & (res.metric == "fpr")]
              .groupby(["profile", "detector", "method"])["value"].agg(rep_fpr_min="min", rep_fpr_max="max").reset_index())
    j = j.merge(spread, on=["profile", "detector", "method"], how="left")
    cols = keys + ["value_main", "ci_lo_main", "ci_hi_main", "value_rep", "ci_lo_rep", "ci_hi_rep", "abs_diff",
                   "ci_overlap", "rep_fpr_min", "rep_fpr_max"]
    return j[cols]


def medians_table(res: pd.DataFrame) -> pd.DataFrame:
    sub = res[(res.dataset == "main") & (res.profile != CLASSICAL) & res.metric.isin(["fpr", "tpr_all", "auroc"])]
    return (sub.groupby(["detector", "method", "metric"])["value"].median().unstack("metric")
            .reindex(columns=["fpr", "tpr_all", "auroc"]).reset_index())


def notes(san: pd.DataFrame, dose: pd.DataFrame, conf: pd.DataFrame, med: pd.DataFrame,
          n_boot: int) -> str:
    lines = ["# Detector baseline notes", "",
             "Generated by `scripts/detector_baseline.py`; every number below is computed from the flows CSVs. "
             "Full results: `results/detector_baseline.csv`, `results/detector_baseline_dose_response.csv`, "
             "`results/detector_baseline_confirmation.csv`.", "",
             "## Scope and labels", "",
             "- **The attacks are scripted attack-like workloads, not real attacks.** benign = benign_web + benign_api; "
             "attack = handshake_flood (many short TLS handshakes) + slow_send (slow trickle of data), generated between "
             "our own local containers.",
             "- Data: `data/flows/lab_flows.csv` (source `pq_lab`, main run, 18 profiles) for all training and "
             "evaluation. `lab_flows_rep.csv` is only scored by the already-trained naive detectors (confirmation); "
             "no dataset is ever merged into a training set.", "",
             "## Splits", "",
             f"- Time-blocked inside every pcap (profile x workload): flows sorted by capture order (`conn_index`); first "
             f"{dt.TRAIN_FRAC:.0%} train, next {dt.VAL_FRAC:.0%} validation, last 40% test. Sizes per pcap: 300 -> 120/60/120, "
             "200 -> 80/40/80, 50 -> 20/10/20.",
             "- All methods are evaluated on the SAME test block of each profile. Nothing is tuned on test.", "",
             "## Feature views (explicit lists, asserted in code)", "",
             f"- V_FLOW = LAB_FLOW_FEATURES ({len(dt.V_FLOW)} whole-connection flow features, what an off-the-shelf flow "
             f"detector sees). V_APP = LAB_APP_FEATURES ({len(dt.V_APP)} application-phase features; handshake removed, "
             "needs TLS parsing). Missing packet-size slots (flow shorter than k packets) are filled with 0.",
             "- `hs_*` and every `LAB_EXCLUDED` column are rejected by `assert_clean_features`. `hs_s2c_bytes` appears "
             "only in the dose-response table as a descriptive x-axis.", "",
             "## Detectors and operating point", "",
             f"- RandomForest (100 trees, supervised, score = P(attack)); autoencoder (sklearn MLPRegressor "
             f"{dt.AE_HIDDEN}, benign-only, score = reconstruction MSE on standardised features); IsolationForest "
             "(100 trees, benign-only). Model seeds " + ", ".join(map(str, SEEDS)) + " (5 repeats); values are means over "
             "seeds, `seed_sd` is the spread across seeds.",
             f"- Threshold = 95th percentile of the BENIGN VALIDATION scores of the training domain (design FPR 5%); flag if "
             f"score > threshold. RF scores tie (many exact 0s), so its in-domain FPR can sit below 5%.",
             f"- 95% CIs: {n_boot} seeded bootstrap resamples of test flows (stratified: benign, each attack type), same "
             "resampled flows for every model seed; the CI is for the seed-mean and does not include model-seed or "
             "pcap-level (batch) variance.",
             f"- AE fits that stopped at max_iter={dt.AE_MAX_ITER} without converging: {dt.FIT_LOG.ae_not_converged} of "
             f"{dt.FIT_LOG.ae_fits}.", "",
             "## Methods", "",
             "1. naive: train + threshold on the classical profile (X25519|ecdsa_p256, leaf_int) only, V_FLOW. "
             "2. oracle: train + threshold on the target profile's own train/val blocks. "
             "3. pooled: train on the union of all 18 profiles' train blocks, threshold on the union of validation blocks. "
             "4. naive_app: as naive but on V_APP.", "",
             "## Sanity: classical in-domain FPR", ""]
    lines += ["| detector | n benign test | FPR | 95% CI | 99% binomial band | ok |", "|---|---|---|---|---|---|"]
    for r in san.itertuples():
        lines.append(f"| {r.detector} | {r.n_benign_test} | {r.fpr:.3f} | {r.ci_lo:.3f} to {r.ci_hi:.3f} | "
                     f"{r.band_lo:.3f} to {r.band_hi:.3f} | {r.ok} |")
    lines += ["", "## Headline numbers (median over the 17 non-classical profiles)", "",
              "| detector | method | FPR | TPR (all attacks) | AUROC |", "|---|---|---|---|---|"]
    for r in med.itertuples():
        lines.append(f"| {r.detector} | {r.method} | {r.fpr:.3f} | {r.tpr_all:.3f} | {r.auroc:.3f} |")
    lines += ["", "## TPR per attack type", "",
              "Classical in-domain and oracle TPR for handshake_flood vs slow_send: `results/detector_attack_type_tpr.csv`.", ""]
    lines += ["", "## Dose-response (naive V_FLOW FPR vs median hs_s2c_bytes of the profile)", ""]
    for det, g in dose.groupby("detector"):
        rho, p = spearmanr(g["hs_s2c_median"], g["fpr_naive"])
        rho2, p2 = spearmanr(g["hs_s2c_median"], g["fpr_naive_app"])
        lines.append(f"- {det}: Spearman(hs_s2c_median, naive FPR) = {rho:.2f} (p={p:.3g}, n={len(g)}); "
                     f"for naive_app FPR = {rho2:.2f} (p={p2:.3g}). Max naive FPR {g['fpr_naive'].max():.3f}.")
    lines += ["", "## Confirmation on the replicate run (naive detectors from the main run)", ""]
    for (det, meth), g in conf[conf.metric == "fpr"].groupby(["detector", "method"]):
        lines.append(f"- {det}/{meth}: FPR CIs overlap main vs replicates in {int(g.ci_overlap.sum())}/{len(g)} profiles; "
                     f"largest |FPR difference| {g.abs_diff.max():.3f}.")
    allm = conf[conf.metric.isin(["fpr", "tpr_all", "auroc"])]
    lines.append(f"- All (profile, detector, method, metric) cells (fpr, tpr_all, auroc): CIs overlap in "
                 f"{int(allm.ci_overlap.sum())}/{len(allm)}.")
    lines += ["", "## Caveats", "",
              "- Scripted workloads, not real attacks; benign traffic is two scripted client behaviours.",
              "- One machine, local Docker network, one TLS cipher suite; timing features inherit all lab-noise caveats "
              "from `docs/rep_timing_notes.md`.",
              "- Time-blocked splits within one pcap per (profile, workload): train and test come from the same capture "
              "session, so pcap-level effects are shared by the splits and no cross-capture generalisation is tested "
              "(except the replicate confirmation).",
              "- Handshake feature values are constant (or nearly) within a profile, so a profile's whole shift is one "
              "value; 18 profiles are 18 'doses', not 18 independent samples of traffic.",
              "- Bootstrap CIs resample flows as if independent; flows within a pcap are not exactly independent, so the "
              "intervals are optimistic.",
              "- Per-attack-type TPR for slow_send rests on 20 test flows per profile."]
    return "\n".join(lines) + "\n"


def attack_type_table(res: pd.DataFrame) -> pd.DataFrame:
    """TPR per attack type (handshake_flood vs slow_send): classical in-domain (naive on the classical profile) and the
    oracle (median / min / max over the 18 profiles), per detector, main-run test blocks."""
    m = res[(res.dataset == "main") & res.metric.isin(["tpr_handshake_flood", "tpr_slow_send"])]
    rows = []
    for det in dt.DETECTORS:
        for metric in ("tpr_handshake_flood", "tpr_slow_send"):
            c = m[(m.detector == det) & (m.metric == metric) & (m.method == "naive") & (m.profile == CLASSICAL)].iloc[0]
            o = m[(m.detector == det) & (m.metric == metric) & (m.method == "oracle")]["value"]
            rows.append({"detector": det, "attack_type": metric.replace("tpr_", ""), "classical_in_domain": c.value,
                         "classical_ci_lo": c.ci_lo, "classical_ci_hi": c.ci_hi, "oracle_median": o.median(),
                         "oracle_min": o.min(), "oracle_max": o.max()})
    return pd.DataFrame(rows)


def show(title: str, df: pd.DataFrame) -> None:
    print(f"\n=== {title}")
    print(df.to_string(index=False, float_format=lambda x: f"{x:.3f}"))


def main(argv: list[str]) -> int:
    n_boot = int(argv[argv.index("--boot") + 1]) if "--boot" in argv else 1000
    main_df, rep_df = load("lab_flows.csv"), load("lab_flows_rep.csv")
    assert main_df["profile"].nunique() == 18, main_df["profile"].nunique()
    print(f"main: {len(main_df)} flows, {main_df['profile'].nunique()} profiles | rep: {len(rep_df)} flows; "
          f"test blocks {int((main_df.block == 'test').sum())} / {int((rep_df.block == 'test').sum())}", flush=True)
    res, _ = run_main(main_df, rep_df, n_boot)
    out = ROOT / "results"
    out.mkdir(exist_ok=True)
    res.to_csv(out / "detector_baseline.csv", index=False)
    san, ok = sanity(res)
    show("sanity: classical in-domain FPR of the naive detector (design point 0.05)", san)
    if not ok:
        print("\nSANITY CHECK FAILED: classical in-domain FPR is not ~5%. Stopping before the headline tables and notes.")
        return 2
    dose, conf, med = dose_response(res, main_df), confirmation(res), medians_table(res)
    dose.to_csv(out / "detector_baseline_dose_response.csv", index=False)
    conf.to_csv(out / "detector_baseline_confirmation.csv", index=False)
    (ROOT / "docs" / "detector_notes.md").write_text(notes(san, dose, conf, med, n_boot), encoding="utf-8", newline="\n")
    hs = dose.drop_duplicates("profile").set_index("profile")["hs_s2c_median"]
    for det in dt.DETECTORS:
        for metric in ("fpr", "tpr_all"):
            t = wide(res, "main", metric, ["naive", "oracle", "pooled", "naive_app"]).xs(det, level="detector")
            t.insert(0, "hs_s2c", hs.reindex(t.index))
            show(f"{det}: {metric.upper()} on the test block (main run), sorted by handshake size",
                 t.sort_values("hs_s2c").reset_index())
    show("median over the 17 non-classical profiles", med)
    show("dose-response: naive FPR vs median hs_s2c_bytes", dose.drop(columns=["fpr_naive_ci_lo", "fpr_naive_ci_hi"]))
    show("confirmation: FPR, main vs replicate run (naive detectors from the main run)",
         conf[conf.metric == "fpr"].drop(columns=["metric", "view"]))
    att = attack_type_table(res)
    att.to_csv(out / "detector_attack_type_tpr.csv", index=False)
    show("TPR per attack type: classical in-domain and oracle (test blocks)", att)
    print(f"AE fits not converged at max_iter={dt.AE_MAX_ITER}: {dt.FIT_LOG.ae_not_converged}/{dt.FIT_LOG.ae_fits}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
