"""CANON v0 evaluation (design: docs/canon_design.md, frozen before this ran).

Run from the repo root:  .venv/Scripts/python scripts/canon_eval.py [--boot N]
Same detectors, seeds, time-blocked splits, test blocks, operating point and metrics as scripts/detector_baseline.py.
Main run (lab_flows.csv) for everything fitted; lab_flows_rep.csv only to apply the already-fitted CANON.
Writes results/canon_eval.csv, results/canon_context_*.csv, docs/canon_notes.md.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd

from pqdl import sidecar
from pqdl import canon
from pqdl import detectors as dt
from pqdl.features import CONTEXT_FEATURES
from pqdl.loaders import assert_single_source

ROOT = Path(__file__).resolve().parents[1]
SEEDS = (11, 12, 13, 14, 15)
BOOT_SEED = 20261126                         # same resampling as the detector baseline
CAL_SEED = 20261127
CORRECTED_GROUPS = ["bytes"]                 # frozen in docs/canon_design.md section 10
SHIFTED_COLS = canon.group_features(CORRECTED_GROUPS)
KS = (10, 30, 100)
KS_SPLIT = (60, 100, 120)                    # post-hoc split variant; k=30 would give n=15 and a vacuous threshold
CLASSICAL = canon.CLASSICAL_CONTEXT
BASELINE_METHODS = ("naive", "naive_app", "pooled", "oracle")


def load(name: str) -> pd.DataFrame:
    df = pd.read_csv(ROOT / "data" / "flows" / name)
    assert_single_source(df)
    return dt.time_block_split(dt.add_labels(df))


def blocks(df: pd.DataFrame, block: str, profile: str | None = None) -> pd.DataFrame:
    g = df[df["block"] == block]
    return g if profile is None else g[g["profile"] == profile]


class Canon:
    """Everything CANON fits on the MAIN run: c-hat, the calibration banks, and per detector the naive domain.

    Bank keys: "b{k}"  = CANON-B, the same k flows fit the shift and set the threshold (original v0);
               "bs{k}" = CANON-B split (post-hoc correction): first k/2 flows fit the shift, last k/2 set the threshold."""

    def __init__(self, main: pd.DataFrame, o_cert: dict[str, float] | None) -> None:
        self.o_cert = o_cert                                  # CANON-A2 (exploratory); None = A2 not run
        self.estimator = canon.fit_context_estimator(blocks(main, "train"), seed=0)
        self.contexts = sorted(main["profile"].unique())
        self.ref = blocks(main, "train", CLASSICAL)
        self.ref = self.ref[~self.ref["attack"]]
        self.naive: dict[str, dt.Domain] = {
            det: dt.fit_domain(det, dt.V_FLOW, blocks(main, "train", CLASSICAL), blocks(main, "val", CLASSICAL), SEEDS)
            for det in dt.DETECTORS}
        self.shifts: dict[str, dict[str, np.ndarray]] = {}
        self.tau: dict[tuple[str, str], dict[str, np.ndarray]] = {}
        for i, c in enumerate(self.contexts):
            val_benign = blocks(main, "val", c)
            val_benign = val_benign[~val_benign["attack"]]
            for k in KS:
                cal = canon.calibration_draw(val_benign, k, CAL_SEED + i)
                self._add(f"b{k}", c, cal, cal)
            for k in KS_SPLIT:
                fit_part, thr_part = canon.split_calibration(canon.calibration_draw(val_benign, k, CAL_SEED + i))
                self._add(f"bs{k}", c, fit_part, thr_part)

    def _add(self, key: str, c: str, fit_part: pd.DataFrame, thr_part: pd.DataFrame) -> None:
        shift = canon.location_shift(fit_part, self.ref, SHIFTED_COLS)
        self.shifts.setdefault(key, {})[c] = shift
        res = canon.residualise(thr_part, [c] * len(thr_part), {c: shift}, SHIFTED_COLS)
        for det in dt.DETECTORS:
            sc = self.naive[det].score(dt.design_matrix(res, dt.V_FLOW))                    # (S, n_thr)
            self.tau.setdefault((det, key), {})[c] = np.array([canon.conformal_threshold(x) for x in sc])

    def predict(self, df: pd.DataFrame) -> np.ndarray:
        return canon.predict_context(self.estimator, df)

    def margins_a(self, det: str, g: pd.DataFrame, ctx: np.ndarray, o_cert: dict[str, float] | None = None) -> np.ndarray:
        """CANON-A (o_cert None) or exploratory CANON-A2: naive detector on bytes-corrected features;
        margin = score - classical validation threshold."""
        X = dt.design_matrix(canon.correct_a(g, ctx, CORRECTED_GROUPS, o_cert), dt.V_FLOW)
        return self.naive[det].score(X) - self.naive[det].thresholds[:, None]

    def margins_b(self, det: str, key: str, g: pd.DataFrame, ctx: np.ndarray) -> np.ndarray:
        """CANON-B: naive detector on residualised features; margin = score - per-context conformal tau."""
        X = dt.design_matrix(canon.residualise(g, ctx, self.shifts[key], SHIFTED_COLS), dt.V_FLOW)
        taus = np.stack([self.tau[(det, key)][c] for c in ctx], axis=1)                     # (S, n)
        with np.errstate(invalid="ignore"):
            return self.naive[det].score(X) - taus


def method_margins(cn: Canon, det: str, g: pd.DataFrame) -> dict[str, np.ndarray]:
    true = (g["kem"] + "|" + g["auth"] + "|" + g["chain"]).to_numpy()
    chat = cn.predict(g)
    out = {"canon_a_true": cn.margins_a(det, g, true), "canon_a_chat": cn.margins_a(det, g, chat)}
    if cn.o_cert is not None:                                 # EXPLORATORY, post-hoc
        out["canon_a2_true"] = cn.margins_a(det, g, true, cn.o_cert)
        out["canon_a2_chat"] = cn.margins_a(det, g, chat, cn.o_cert)
    for k in KS:
        out[f"canon_b_k{k}_true"] = cn.margins_b(det, f"b{k}", g, true)
        out[f"canon_b_k{k}_chat"] = cn.margins_b(det, f"b{k}", g, chat)
    for k in KS_SPLIT:
        out[f"canon_bs_k{k}_true"] = cn.margins_b(det, f"bs{k}", g, true)
        out[f"canon_bs_k{k}_chat"] = cn.margins_b(det, f"bs{k}", g, chat)
    return out


def evaluate(rows: list[dict], dataset: str, test: pd.DataFrame, cn: Canon, n_boot: int) -> None:
    for det in dt.DETECTORS:
        for profile, g in test.groupby("profile", sort=True):
            kem, auth, chain = profile.split("|")
            for method, margin in method_margins(cn, det, g).items():
                summ = dt.summarise(margin, g["attack_type"].to_numpy(), np.zeros(margin.shape[0]), n_boot, BOOT_SEED)
                for metric, s in summ.items():
                    rows.append({"dataset": dataset, "profile": profile, "kem": kem, "auth": auth, "chain": chain,
                                 "detector": det, "method": method, "view": "V_FLOW", "metric": metric, "value": s.value,
                                 "seed_sd": s.seed_sd, "ci_lo": s.ci_lo, "ci_hi": s.ci_hi,
                                 "n_benign": int((~g["attack"]).sum()), "n_attack": int(g["attack"].sum())})


def context_report(cn: Canon, df: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame, float]:
    """(per-profile recall table, confusion matrix, overall accuracy) of c-hat on the test block of `df`."""
    t = blocks(df, "test")
    true, pred = t["profile"].to_numpy(), cn.predict(t)
    cm = canon.confusion(true, pred, cn.contexts)
    per = (pd.DataFrame({"profile": true, "correct": true == pred}).groupby("profile")["correct"]
           .agg(n="size", recall="mean").reset_index())
    return per, cm, float((true == pred).mean())


def baseline_rows() -> pd.DataFrame:
    return pd.read_csv(ROOT / "results" / "detector_baseline.csv")


def comparison(canon_res: pd.DataFrame, base: pd.DataFrame) -> pd.DataFrame:
    """Median over the 17 non-classical profiles (+ count of profiles with FPR <= 2x design) per detector and method."""
    b = base[(base.dataset == "main") & base.method.isin(BASELINE_METHODS)]
    c = canon_res[canon_res.dataset == "main"]
    both = pd.concat([b[canon_res.columns.intersection(b.columns)], c], ignore_index=True)
    sub = both[(both.profile != CLASSICAL) & both.metric.isin(["fpr", "tpr_all", "auroc"])]
    med = sub.groupby(["detector", "method", "metric"])["value"].median().unstack("metric")
    fpr = sub[sub.metric == "fpr"]
    med["n_profiles_fpr_le_010"] = fpr.groupby(["detector", "method"])["value"].apply(lambda s: int((s <= 0.10).sum()))
    return med.reindex(columns=["fpr", "tpr_all", "auroc", "n_profiles_fpr_le_010"]).reset_index()


def coverage(canon_res: pd.DataFrame) -> pd.DataFrame:
    """FPR per context vs alpha: median FPR, mean |FPR - alpha|, and how many of the 18 contexts have alpha inside the CI."""
    s = canon_res[(canon_res.dataset == "main") & (canon_res.metric == "fpr") & canon_res.method.str.startswith("canon_b")]
    s = s.assign(contains=(s.ci_lo <= dt.DESIGN_FPR) & (dt.DESIGN_FPR <= s.ci_hi), dev=(s.value - dt.DESIGN_FPR).abs())
    return (s.groupby(["detector", "method"]).agg(median_fpr=("value", "median"), mean_abs_dev=("dev", "mean"),
                                                  contexts_alpha_in_ci=("contains", "sum"), n_contexts=("value", "size"))
            .reset_index())


def agreement(canon_res: pd.DataFrame) -> pd.DataFrame:
    keys = ["profile", "detector", "method", "metric"]
    m = canon_res[canon_res.dataset == "main"]
    r = canon_res[canon_res.dataset == "rep_all"]
    j = m.merge(r, on=keys, suffixes=("_main", "_rep"))
    j["abs_diff"] = (j["value_main"] - j["value_rep"]).abs()
    j["ci_overlap"] = (j["ci_lo_main"] <= j["ci_hi_rep"]) & (j["ci_lo_rep"] <= j["ci_hi_main"])
    return j[keys + ["value_main", "ci_lo_main", "ci_hi_main", "value_rep", "ci_lo_rep", "ci_hi_rep", "abs_diff", "ci_overlap"]]


def per_context_coverage(res: pd.DataFrame) -> pd.DataFrame:
    """Per context: FPR and 95% CI of the CANON-B variants (true context) on the main test block, '*' if alpha is outside."""
    m = res[(res.dataset == "main") & (res.metric == "fpr") & res.method.str.startswith("canon_b") & res.method.str.endswith("_true")]
    out = m[["profile", "detector", "method", "value", "ci_lo", "ci_hi"]].copy()
    out["alpha_in_ci"] = (out.ci_lo <= dt.DESIGN_FPR) & (dt.DESIGN_FPR <= out.ci_hi)
    out["cell"] = [f"{r.value:.3f} [{r.ci_lo:.3f},{r.ci_hi:.3f}]" + ("" if r.alpha_in_ci else " *") for r in out.itertuples()]
    return out


def ae_before_after(before_dir: Path | None, base_after: pd.DataFrame, res_after: pd.DataFrame) -> pd.DataFrame:
    """Median FPR / TPR / AUROC over the 17 non-classical profiles for the AE, before (max_iter 500) and after (2000)."""
    def med(df: pd.DataFrame) -> pd.DataFrame:
        d = df[(df.dataset == "main") & (df.detector == "ae") & (df.profile != CLASSICAL) & df.metric.isin(["fpr", "tpr_all", "auroc"])]
        return d.groupby(["method", "metric"])["value"].median().unstack("metric")
    after = pd.concat([med(base_after), med(res_after)])
    if before_dir is None:
        return after.reset_index()
    before = pd.concat([med(pd.read_csv(before_dir / "detector_baseline.csv")), med(pd.read_csv(before_dir / "canon_eval.csv"))])
    j = before.join(after, lsuffix="_before", rsuffix="_after", how="outer")
    return j[[f"{m}_{w}" for m in ("fpr", "tpr_all", "auroc") for w in ("before", "after")]].reset_index()


def show(title: str, df: pd.DataFrame) -> None:
    print(f"\n=== {title}")
    print(df.to_string(index=False, float_format=lambda x: f"{x:.3f}"))


def notes(cmp_: pd.DataFrame, cov: pd.DataFrame, acc: dict[str, float], per_main: pd.DataFrame, agr: pd.DataFrame,
          n_boot: int) -> str:
    L = ["# CANON v0 results (generated by scripts/canon_eval.py)", "",
         "Design frozen in `docs/canon_design.md` (sections 1-9 before any run; section 10 after the pre-registered "
         "attribution on validation blocks). Corrected feature group: **bytes** only (the only driver). "
         "Attacks are scripted attack-like workloads, not real attacks. All numbers computed; nothing hard-coded.", "",
         "## Context estimator c-hat", "",
         f"- Accuracy on the main test blocks: {acc['main']:.3f}; on the replicate test blocks: {acc['rep']:.3f}.",
         "- Per-profile recall (main test): " + ", ".join(f"{r.profile.split('|')[0]}/{r.profile.split('|')[1]}/{r.profile.split('|')[2]}={r.recall:.2f}"
                                                         for r in per_main.itertuples()) + ".",
         "- Full confusion matrices: `results/canon_context_confusion_main.csv`, `_rep.csv`.", "",
         f"## Median over the 17 non-classical profiles (main run, {n_boot} bootstrap resamples per cell in the CSV)", "",
         "| detector | method | FPR | TPR (all) | AUROC | profiles with FPR <= 0.10 |", "|---|---|---|---|---|---|"]
    for r in cmp_.itertuples():
        L.append(f"| {r.detector} | {r.method} | {r.fpr:.3f} | {r.tpr_all:.3f} | {r.auroc:.3f} | {r.n_profiles_fpr_le_010} |")
    L += ["", "## Post-hoc additions (recorded in `docs/canon_design.md` change log; NOT part of the frozen v0 design)", "",
          f"- **canon_bs_k*** = CANON-B *split*: the first k/2 calibration flows fit the shift, the last k/2 set the conformal "
          f"threshold (k in {list(KS_SPLIT)}; k=30 would give n=15 and a vacuous threshold, so it is skipped). Reason: v0 used "
          "the same k flows for both, which voids the conformal guarantee.",
          "- **canon_a2_*** = CANON-A2, EXPLORATORY and post-hoc: the default 40 B per-certificate overhead is replaced by the "
          "measured value from the lab's own certificates (`results/cert_overhead.csv`). CANON-A is unchanged.",
          f"- AE re-run with max_iter={dt.AE_MAX_ITER} (was 500). AE fits not converged in this script: "
          f"{dt.FIT_LOG.ae_not_converged}/{dt.FIT_LOG.ae_fits}.", "",
          "CANON-B AUROC is computed on the margin (score minus the per-context threshold). With k=10 the conformal "
          "threshold is +inf (rank 11 > 10), so nothing is flagged: FPR = TPR = 0 and AUROC = 0.5 by construction.", "",
          "## Conformal coverage of CANON-B (FPR per context vs alpha = 0.05, main test blocks)", "",
          "| detector | method | median FPR | mean abs deviation | contexts with alpha in 95% CI |", "|---|---|---|---|---|"]
    for r in cov.itertuples():
        L.append(f"| {r.detector} | {r.method} | {r.median_fpr:.3f} | {r.mean_abs_dev:.3f} | {r.contexts_alpha_in_ci}/{r.n_contexts} |")
    a = agr[agr.metric.isin(["fpr", "tpr_all", "auroc"])]
    L += ["", "## Confirmation on the replicate run (CANON fitted on the main run, nothing refitted)", "",
          f"- CIs overlap in {int(a.ci_overlap.sum())}/{len(a)} (profile, detector, method, metric) cells (fpr, tpr_all, auroc); "
          f"largest absolute difference {a.abs_diff.max():.3f}.", "",
          "## Caveats", "",
          "- Scripted workloads, one machine, one cipher suite, 18 profiles = 18 'doses'; time-blocked splits inside one pcap.",
          "- The context estimator needs labelled flows of every context, so 'zero PQ training data' holds for the CANON-A "
          "correction rule only; the TRUE-context variants isolate that.",
          "- CANON-A uses default size-model overheads; byte deltas are off by ~34 B for leaf_int and 170-370 B for leaf profiles.",
          "- CANON-B uses the same k flows for the shift and for tau (mildly optimistic) and corrects bytes only.",
          "- Bootstrap CIs resample flows and ignore pcap-level variance."]
    return "\n".join(L) + "\n"


def main(argv: list[str]) -> int:
    n_boot = int(argv[argv.index("--boot") + 1]) if "--boot" in argv else 1000
    main_df, rep_df = load("lab_flows.csv"), load("lab_flows_rep.csv")
    assert not set(CONTEXT_FEATURES) & set(dt.V_FLOW)
    t0 = time.time()
    cert_path = ROOT / "results" / "cert_overhead.csv"
    o_cert = dict(pd.read_csv(cert_path)[["auth", "o_cert"]].itertuples(index=False)) if cert_path.exists() else None
    if o_cert is None:
        print("results/cert_overhead.csv missing: CANON-A2 (exploratory) NOT run; run scripts/measure_cert_overhead.py")
    cn = Canon(main_df, o_cert)
    print(f"fitted c-hat, banks and naive domains ({time.time() - t0:.0f} s)", flush=True)
    per_main, cm_main, acc_main = context_report(cn, main_df)
    per_rep, cm_rep, acc_rep = context_report(cn, rep_df)
    out = ROOT / "results"
    cm_main.to_csv(out / "canon_context_confusion_main.csv")
    cm_rep.to_csv(out / "canon_context_confusion_rep.csv")
    per_main.assign(dataset="main").pipe(lambda d: pd.concat([d, per_rep.assign(dataset="rep")])).to_csv(
        out / "canon_context_accuracy.csv", index=False)
    show(f"context estimator c-hat: recall per profile, main test blocks (accuracy {acc_main:.3f})", per_main)
    show(f"context estimator c-hat: recall per profile, replicate test blocks (accuracy {acc_rep:.3f})", per_rep)
    rows: list[dict] = []
    evaluate(rows, "main", blocks(main_df, "test"), cn, n_boot)
    print(f"main evaluated ({time.time() - t0:.0f} s)", flush=True)
    rep_test = blocks(rep_df, "test")
    evaluate(rows, "rep_all", rep_test, cn, n_boot)
    for r in sorted(rep_test["replicate_id"].unique()):
        evaluate(rows, f"rep_r{int(r)}", rep_test[rep_test["replicate_id"] == r], cn, n_boot)
    res = pd.DataFrame(rows)
    res.to_csv(out / "canon_eval.csv", index=False)
    base = baseline_rows()
    cmp_, cov, agr = comparison(res, base), coverage(res), agreement(res)
    cmp_.to_csv(out / "canon_comparison.csv", index=False)
    cov.to_csv(out / "canon_coverage.csv", index=False)
    agr.to_csv(out / "canon_confirmation.csv", index=False)
    (ROOT / "docs" / "canon_notes.md").write_text(notes(cmp_, cov, {"main": acc_main, "rep": acc_rep}, per_main, agr, n_boot),
                                                   encoding="utf-8", newline="\n")
    order = ["naive", "naive_app", "pooled", "oracle", "canon_a_true", "canon_a_chat", "canon_a2_true", "canon_a2_chat",
             *[f"canon_b_k{k}_{v}" for k in KS for v in ("true", "chat")],
             *[f"canon_bs_k{k}_{v}" for k in KS_SPLIT for v in ("true", "chat")]]
    cmp_["method"] = pd.Categorical(cmp_["method"], order)
    show("median over the 17 non-classical profiles (main run); canon_a2 = EXPLORATORY post-hoc, canon_bs = post-hoc split",
         cmp_.sort_values(["detector", "method"]))
    show("CANON-B conformal coverage (summary over the 18 contexts): FPR vs alpha = 0.05", cov)
    pc = per_context_coverage(res)
    pc.to_csv(out / "canon_coverage_per_context.csv", index=False)
    for det in ("ae", "rf"):
        t = pc[pc.detector == det].pivot_table(index="profile", columns="method", values="cell", aggfunc="first")
        show(f"{det}: FPR per context [95% CI] on the test block, '*' = alpha 0.05 outside the CI "
             "(true and c-hat contexts are identical: c-hat accuracy is 100%)", t.reset_index())
    show("AE before/after max_iter 500 -> 2000 (median over the 17 non-classical profiles)",
         ae_before_after(Path(argv[argv.index("--before") + 1]) if "--before" in argv else None, base, res))
    print(f"AE fits in this script (naive domains) not converged at max_iter={dt.AE_MAX_ITER}: "
          f"{dt.FIT_LOG.ae_not_converged}/{dt.FIT_LOG.ae_fits}")
    allm = pd.concat([base[(base.dataset == "main") & base.method.isin(BASELINE_METHODS)], res[res.dataset == "main"]])
    keep = ["naive", "naive_app", "oracle", "canon_a_true", "canon_a2_true", "canon_b_k100_true", "canon_bs_k60_true",
            "canon_bs_k100_true", "canon_bs_k120_true"]
    for det in dt.DETECTORS:
        t = allm[(allm.detector == det) & (allm.metric == "fpr")].pivot_table(index="profile", columns="method", values="value")
        show(f"{det}: FPR per profile", t[[c for c in keep if c in t.columns]].reset_index())
    a = agr[agr.metric == "fpr"]
    show("confirmation: FPR main vs replicate (CANON from the main run), cells where CIs do not overlap",
         a[~a.ci_overlap])
    print(f"\nconfirmation: CIs overlap in {int(agr[agr.metric.isin(['fpr', 'tpr_all', 'auroc'])].ci_overlap.sum())}/"
          f"{len(agr[agr.metric.isin(['fpr', 'tpr_all', 'auroc'])])} cells")
    return 0


if __name__ == "__main__":
    sys.exit(sidecar.tracked(main, ROOT, __file__, sys.argv[1:]))
