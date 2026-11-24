"""Statistical analysis of the detector baseline and CANON results -> docs/stats_notes.md (+ results/stats_*.csv).

Run from the repo root:  .venv/Scripts/python scripts/stats_eval.py [--draws R]
Needs results/detector_baseline*.csv, results/canon_*.csv (scripts/detector_baseline.py, scripts/canon_eval.py first).
Sections: (2) marginal coverage over repeated calibration draws, (3) Friedman + Nemenyi, (4) McNemar per profile,
(5) pcap-level uncertainty for the 4 replicated profiles, (6) claims table. The thresholds that turn measured shares into
PASS / PARTIAL / FAIL are the constants CLAIM_* below, written before the first run.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd
from scipy.stats import spearmanr

import canon_eval as ce
from pqdl import sidecar
from pqdl import canon
from pqdl import detectors as dt
from pqdl import stats as st
from pqdl.rep_timing import holm

ROOT = Path(__file__).resolve().parents[1]
RES = ROOT / "results"
SEEDS, ALPHA, SLACK = ce.SEEDS, canon.ALPHA, 0.02
DRAW_SEED, STAT_SEED = 20261201, 20261202
CLASSICAL = canon.CLASSICAL_CONTEXT
DETS_MAIN = ("rf", "ae")                        # headline detectors; IsolationForest is flagged weak (misses floods)
VARIANTS = {"b100": ("v0 k=100", "b", 100), "bs60": ("split k=60", "bs", 60), "bs100": ("split k=100", "bs", 100),
            "bs120": ("split k=120", "bs", 120)}
METHODS = {"naive": "naive", "naive_app": "V_APP", "pooled": "pooled", "oracle": "oracle", "canon_a_true": "CANON-A",
           "canon_a2_true": "CANON-A2 (exploratory)", "canon_b_k100_true": "CANON-B v0 k=100",
           "canon_bs_k120_true": "CANON-B split k=120"}
# --- claim status rules (fixed BEFORE the first run): status_from_share(share, pass_at, partial_at)
CLAIM_PASS, CLAIM_PARTIAL = 0.75, 0.25            # default: share of profiles / cells
CLAIM_COVERAGE = (0.90, 0.50)                      # share of contexts with >= 80% of draws at FPR <= alpha + 0.02
CLAIM_BOOT = (0.90, 0.50)                          # share of pcap-level cells where the flow CI is not understated
CLAIM_CONFIRM = (0.90, 0.75)                       # share of confirmation cells with overlapping CIs
TIGHT_FPR = 0.03                                   # coverage is "tight" if mean FPR over draws >= this in >= 50% contexts
VALID_SHARE = 0.80                                 # a context is "valid" if >= 80% of draws have FPR <= alpha + SLACK


# --------------------------------------------------------------------------- setup
def build_domains(main: pd.DataFrame, cn: ce.Canon) -> dict:
    cls_tr, cls_va = ce.blocks(main, "train", CLASSICAL), ce.blocks(main, "val", CLASSICAL)
    dom = {"naive": cn.naive}
    dom["naive_app"] = {d: dt.fit_domain(d, dt.V_APP, cls_tr, cls_va, SEEDS) for d in dt.DETECTORS}
    dom["pooled"] = {d: dt.fit_domain(d, dt.V_FLOW, ce.blocks(main, "train"), ce.blocks(main, "val"), SEEDS) for d in dt.DETECTORS}
    dom["oracle"] = {(d, p): dt.fit_domain(d, dt.V_FLOW, ce.blocks(main, "train", p), ce.blocks(main, "val", p), SEEDS)
                     for d in dt.DETECTORS for p in cn.contexts}
    return dom


def flags_for(cn: ce.Canon, dom: dict, det: str, method: str, g: pd.DataFrame) -> np.ndarray:
    """Boolean decisions (n_seeds, n) of `method` on the flows `g` (true contexts), at the method's operating point."""
    ctx = (g["kem"] + "|" + g["auth"] + "|" + g["chain"]).to_numpy()
    if method in ("naive", "pooled"):
        d = dom[method][det]
        return d.score(dt.design_matrix(g, dt.V_FLOW)) > d.thresholds[:, None]
    if method == "naive_app":
        d = dom[method][det]
        return d.score(dt.design_matrix(g, dt.V_APP)) > d.thresholds[:, None]
    if method == "oracle":
        out = np.zeros((len(SEEDS), len(g)), bool)
        for p in set(ctx):
            m = ctx == p
            d = dom["oracle"][(det, p)]
            out[:, m] = d.score(dt.design_matrix(g[m], dt.V_FLOW)) > d.thresholds[:, None]
        return out
    if method == "canon_a_true":
        return cn.margins_a(det, g, ctx) > 0
    if method == "canon_a2_true":
        return cn.margins_a(det, g, ctx, cn.o_cert) > 0
    if method == "canon_b_k100_true":
        return cn.margins_b(det, "b100", g, ctx) > 0
    if method == "canon_bs_k120_true":
        return cn.margins_b(det, "bs120", g, ctx) > 0
    raise ValueError(method)


# --------------------------------------------------------------------------- 2. marginal coverage over calibration draws
def coverage_draws(cn: ce.Canon, main: pd.DataFrame, n_draws: int) -> pd.DataFrame:
    idx = [list(dt.V_FLOW).index(c) for c in ce.SHIFTED_COLS]
    refmed = cn.ref[ce.SHIFTED_COLS].median().to_numpy(float)
    val_x, test_x = {}, {}
    for c in cn.contexts:
        v, t = ce.blocks(main, "val", c), ce.blocks(main, "test", c)
        val_x[c] = dt.design_matrix(v[~v["attack"]], dt.V_FLOW)
        test_x[c] = dt.design_matrix(t[~t["attack"]], dt.V_FLOW)
    fpr = {(d, v): np.zeros((n_draws, len(cn.contexts))) for d in DETS_MAIN for v in VARIANTS}
    for r in range(n_draws):
        perms = [np.random.default_rng(DRAW_SEED + 1000 * r + i).permutation(len(val_x[c])) for i, c in enumerate(cn.contexts)]
        for vkey, (_, kind, k) in VARIANTS.items():
            thr_rows, te_rows, bounds = [], [], []
            for c, perm in zip(cn.contexts, perms):
                fit, thr = (perm[:k], perm[:k]) if kind == "b" else (perm[: k // 2], perm[k // 2: k])
                shift = np.median(val_x[c][fit][:, idx], axis=0) - refmed
                xt, xe = val_x[c][thr].copy(), test_x[c].copy()
                xt[:, idx] -= shift
                xe[:, idx] -= shift
                thr_rows.append(xt)
                te_rows.append(xe)
                bounds.append((len(xt), len(xe)))
            stack = np.vstack(thr_rows + te_rows)
            n_thr = sum(b[0] for b in bounds)
            for d in DETS_MAIN:
                sc = cn.naive[d].score(stack)                                    # (S, N)
                s_thr, s_te = sc[:, :n_thr], sc[:, n_thr:]
                o_t = o_e = 0
                for j, (nt, ne) in enumerate(bounds):
                    taus = np.array([canon.conformal_threshold(s_thr[s, o_t:o_t + nt]) for s in range(sc.shape[0])])
                    fpr[(d, vkey)][r, j] = float(np.mean(s_te[:, o_e:o_e + ne] > taus[:, None]))
                    o_t, o_e = o_t + nt, o_e + ne
    rows = []
    for (d, vkey), arr in fpr.items():
        label, kind, k = VARIANTS[vkey]
        n_cal = k if kind == "b" else k // 2
        t_mean, t_sd, t_share = st.conformal_fpr_distribution(n_cal, ALPHA, SLACK)
        for j, c in enumerate(cn.contexts):
            rows.append({"detector": d, "variant": label, "profile": c, "n_threshold_flows": n_cal, "draws": n_draws,
                         "mean_fpr": arr[:, j].mean(), "sd_fpr": arr[:, j].std(ddof=1),
                         "share_fpr_le_alpha_plus_0.02": float((arr[:, j] <= ALPHA + SLACK + 1e-12).mean()),
                         "theory_mean": t_mean, "theory_sd": t_sd, "theory_share": t_share})
    return pd.DataFrame(rows)


def coverage_summary(cov: pd.DataFrame) -> pd.DataFrame:
    g = cov.groupby(["detector", "variant"])
    out = g.agg(n_thr=("n_threshold_flows", "first"), mean_fpr=("mean_fpr", "median"), sd_fpr=("sd_fpr", "median"),
                theory_mean=("theory_mean", "first"), theory_sd=("theory_sd", "first"),
                share_draws_ok=("share_fpr_le_alpha_plus_0.02", "median"), theory_share=("theory_share", "first")).reset_index()
    out["contexts_valid"] = [float(((cov[(cov.detector == r.detector) & (cov.variant == r.variant)]["share_fpr_le_alpha_plus_0.02"]) >= VALID_SHARE).mean())
                             for r in out.itertuples()]
    out["contexts_tight"] = [float(((cov[(cov.detector == r.detector) & (cov.variant == r.variant)]["mean_fpr"]) >= TIGHT_FPR).mean())
                             for r in out.itertuples()]
    return out


# --------------------------------------------------------------------------- 3. Friedman + Nemenyi
def fpr_table(det: str, base: pd.DataFrame, cres: pd.DataFrame) -> pd.DataFrame:
    parts = []
    for df in (base, cres):
        d = df[(df.dataset == "main") & (df.detector == det) & (df.metric == "fpr") & (df.profile != CLASSICAL)
               & df.method.isin(METHODS)]
        parts.append(d.pivot_table(index="profile", columns="method", values="value"))
    t = pd.concat(parts, axis=1)[list(METHODS)]
    assert t.shape == (17, len(METHODS)) and not t.isna().any().any()
    return t.rename(columns=METHODS)


def friedman_section(base: pd.DataFrame, cres: pd.DataFrame) -> tuple[dict, pd.DataFrame, pd.DataFrame]:
    out, diffs, pairs = {}, [], []
    for det in dt.DETECTORS:
        t = fpr_table(det, base, cres)
        chi, p = st.friedman(t)
        ranks, cd = st.average_ranks(t), st.nemenyi_cd(t.shape[1], t.shape[0])
        out[det] = {"chi2": chi, "p": p, "ranks": ranks, "cd": cd, "table": t, "pairs": st.nemenyi_pairs(ranks, cd)}
        for ref in ("naive", "oracle"):
            for m in t.columns:
                if m == ref:
                    continue
                med, lo, hi = st.paired_median_diff_ci(t[m].to_numpy(), t[ref].to_numpy(), 10_000, STAT_SEED)
                diffs.append({"detector": det, "method": m, "reference": ref, "median_fpr_diff": med, "ci_lo": lo, "ci_hi": hi})
        pairs.append(out[det]["pairs"].assign(detector=det, cd=cd))
    return out, pd.DataFrame(diffs), pd.concat(pairs, ignore_index=True)


def calibration_section(base: pd.DataFrame, cres: pd.DataFrame) -> dict:
    """Friedman + Nemenyi on |FPR - 0.05| (calibration error) per profile, RF and AE; lower is better."""
    out = {}
    for det in DETS_MAIN:
        t = st.calibration_error_table(fpr_table(det, base, cres), ALPHA)
        chi, p = st.friedman(t)
        ranks, cd = st.average_ranks(t), st.nemenyi_cd(t.shape[1], t.shape[0])
        out[det] = {"chi2": chi, "p": p, "ranks": ranks, "cd": cd, "median_err": t.median(),
                    "pairs": st.nemenyi_pairs(ranks, cd).assign(detector=det, cd=cd)}
    return out


# --------------------------------------------------------------------------- 4. McNemar
def mcnemar_section(cn: ce.Canon, dom: dict, main: pd.DataFrame) -> pd.DataFrame:
    rows = []
    comps = [("naive", "CANON-B"), ("CANON-B", "naive_app"), ("CANON-B", "oracle")]
    bvars = {"v0 k=100": "canon_b_k100_true", "split k=120": "canon_bs_k120_true"}
    for det in dt.DETECTORS:
        for profile in cn.contexts:
            g = ce.blocks(main, "test", profile)
            attack = g["attack"].to_numpy()
            fl = {m: flags_for(cn, dom, det, m, g)[0] for m in ("naive", "naive_app", "oracle", *bvars.values())}   # model seed 11
            for bname, bm in bvars.items():
                for a, b in comps:
                    fa, fb = fl[bm if a == "CANON-B" else a], fl[bm if b == "CANON-B" else b]
                    for cls, mask in (("benign", ~attack), ("attack", attack)):
                        only_a, only_b, p = st.mcnemar_exact(fa[mask], fb[mask])
                        rows.append({"detector": det, "profile": profile, "b_variant": bname, "comparison": f"{a} vs {b}",
                                     "flows": cls, "n_flows": int(mask.sum()), "only_first_flags": only_a,
                                     "only_second_flags": only_b, "p": p})
    df = pd.DataFrame(rows)
    df["p_holm"] = df.groupby(["detector", "b_variant", "comparison", "flows"])["p"].transform(lambda s: holm(s.to_numpy()))
    return df


# --------------------------------------------------------------------------- 5. pcap-level uncertainty
def pcap_level(cn: ce.Canon, dom: dict, main: pd.DataFrame, rep: pd.DataFrame, base: pd.DataFrame, cres: pd.DataFrame) -> pd.DataFrame:
    rep_profiles = sorted(rep["profile"].unique())
    rows = []
    for det in dt.DETECTORS:
        for profile in rep_profiles:
            sets = {"main": ce.blocks(main, "test", profile)}
            for r in sorted(rep["replicate_id"].unique()):
                sets[f"rep{int(r)}"] = ce.blocks(rep, "test", profile)[lambda d, r=r: d["replicate_id"] == r]
            for method, label in METHODS.items():
                vals = {}
                for name, g in sets.items():
                    gb = g[~g["attack"]]                                  # benign_web + benign_api pcaps of this capture set
                    vals[name] = float(flags_for(cn, dom, det, method, gb).mean())
                v = np.array(list(vals.values()))
                src = base if method in ("naive", "naive_app", "pooled", "oracle") else cres
                ci = src[(src.dataset == "main") & (src.detector == det) & (src.profile == profile) & (src.method == method) & (src.metric == "fpr")].iloc[0]
                se = (ci.ci_hi - ci.ci_lo) / 2 / 1.96
                sd = float(v.std(ddof=1))
                rows.append({"detector": det, "profile": profile, "method": label, "n_capture_sets": len(v),
                             "mean_fpr": v.mean(), "sd_across_pcaps": sd, "min": v.min(), "max": v.max(),
                             "main_fpr": vals["main"], "flow_ci_lo": ci.ci_lo, "flow_ci_hi": ci.ci_hi, "flow_se": se,
                             "sd_over_flow_se": (sd / se) if se > 0 else (float("inf") if sd > 0 else float("nan")),
                             "flow_ci_understates": bool(sd > se and sd > 0)})
    return pd.DataFrame(rows)


# --------------------------------------------------------------------------- 6. claims
def claims_table(base, cres, cov_s, fr, mc, pc, dose, conf_base, conf_canon, att) -> pd.DataFrame:
    P, PP = CLAIM_PASS, CLAIM_PARTIAL
    rows = []

    def add(claim, evidence, test, statuses, detail, exploratory=False):
        rows.append({"claim": claim + (" [EXPLORATORY, post-hoc]" if exploratory else ""), "evidence_file": evidence,
                     "test": test, "status": st.combine_status(statuses), "detail": detail})

    def share_where(df, det, method, cond):
        d = df[(df.dataset == "main") & (df.detector == det) & (df.method == method) & (df.metric == "fpr") & (df.profile != CLASSICAL)]
        return float(cond(d).mean())

    # C1 naive failure
    sh = {d: share_where(base, d, "naive", lambda x: x.ci_lo > 0.10) for d in dt.DETECTORS}
    add("Classical-trained (naive) detectors fail on PQ handshakes", "results/detector_baseline.csv",
        "share of 17 profiles with naive FPR CI lower bound > 0.10 (RF, AE judged; IsolationForest reported)",
        [st.status_from_share(sh[d], P, PP) for d in DETS_MAIN],
        "; ".join(f"{d}: {sh[d]:.2f}" for d in dt.DETECTORS))
    # C2 V_APP
    sh = {d: share_where(base, d, "naive_app", lambda x: x.value <= 0.10) for d in dt.DETECTORS}
    add("Removing the handshake (V_APP) restores the design FPR", "results/detector_baseline.csv",
        "share of 17 profiles with V_APP-naive FPR <= 0.10 (RF, AE judged)", [st.status_from_share(sh[d], P, PP) for d in DETS_MAIN],
        "; ".join(f"{d}: {sh[d]:.2f}" for d in dt.DETECTORS))
    # C3 dose-response
    sig = {}
    for d, g in dose.groupby("detector"):
        rho, p = spearmanr(g["hs_s2c_median"], g["fpr_naive"])
        sig[d] = (rho, p)
    n_sig = sum(1 for rho, p in sig.values() if p < 0.05 and rho > 0)
    add("Naive FPR rises monotonically with handshake size (dose-response)", "results/detector_baseline_dose_response.csv",
        "Spearman(hs_s2c_median, naive FPR), p < 0.05 and rho > 0, share of 3 detectors (pass >= 0.67, partial >= 0.33)",
        [st.status_from_share(n_sig / 3, 0.67, 0.33)], "; ".join(f"{d}: rho={r:.2f} p={p:.3g}" for d, (r, p) in sig.items()))
    # C4 baseline confirmation
    c = conf_base[(conf_base.method == "naive") & (conf_base.metric == "fpr")]
    add("The naive failure replicates on the independent replicate captures", "results/detector_baseline_confirmation.csv",
        "share of naive FPR cells (4 profiles x 3 detectors) whose main/replicate CIs overlap (pass >= 0.90, partial >= 0.75)",
        [st.status_from_share(float(c.ci_overlap.mean()), *CLAIM_CONFIRM)], f"{int(c.ci_overlap.sum())}/{len(c)} cells overlap")
    # C5-C8 restoration
    for label, method, expl in (("CANON-A (model-based, no PQ calibration data)", "canon_a_true", False),
                                ("CANON-A2 (measured certificate overhead)", "canon_a2_true", True),
                                ("CANON-B v0 k=100 (k-shot, in-sample threshold)", "canon_b_k100_true", False),
                                ("CANON-B split k=120 (k-shot, split conformal)", "canon_bs_k120_true", False)):
        sh = {d: share_where(cres, d, method, lambda x: x.value <= 0.10) for d in dt.DETECTORS}
        add(f"{label} restores FPR <= 0.10", "results/canon_eval.csv",
            "share of 17 profiles with FPR <= 0.10 (RF, AE judged)", [st.status_from_share(sh[d], P, PP) for d in DETS_MAIN],
            "; ".join(f"{d}: {sh[d]:.2f}" for d in dt.DETECTORS), expl)
    # C9 marginal validity of the split variant
    sts, det_txt = [], []
    for d in DETS_MAIN:
        r = cov_s[(cov_s.detector == d) & (cov_s.variant == "split k=120")].iloc[0]
        s = st.status_from_share(r.contexts_valid, *CLAIM_COVERAGE)
        if s == "PASS" and r.contexts_tight < 0.5:
            s = "PARTIAL"                                                   # valid but vacuous (FPR ~ 0): not tight
        sts.append(s)
        det_txt.append(f"{d}: valid contexts {r.contexts_valid:.2f}, tight contexts {r.contexts_tight:.2f}, median SD {r.sd_fpr:.3f} vs theory {r.theory_sd:.3f}")
    add("CANON-B split k=120 has marginal conformal validity (FPR <= alpha+0.02 in >= 80% of calibration draws)",
        "results/stats_coverage_draws.csv", "share of contexts valid (pass >= 0.90, partial >= 0.50), PASS capped to PARTIAL if not tight",
        sts, "; ".join(det_txt))
    # C10 / C11 Nemenyi
    s10, s11, t10, t11 = [], [], [], []
    for d in DETS_MAIN:
        pr, cd, rk = fr[d]["pairs"], fr[d]["cd"], fr[d]["ranks"]
        better = [int(rk[b] < rk["naive"] and abs(rk[b] - rk["naive"]) > cd) for b in ("CANON-B v0 k=100", "CANON-B split k=120")]
        worse = [int(rk[b] - rk["oracle"] > cd) for b in ("CANON-B v0 k=100", "CANON-B split k=120")]
        s10.append(st.status_from_share(sum(better) / 2, 1.0, 0.5))
        s11.append(st.status_from_share(1 - sum(worse) / 2, 1.0, 0.5))
        t10.append(f"{d}: {sum(better)}/2 variants beat naive by > CD={cd:.2f}")
        t11.append(f"{d}: {sum(worse)}/2 variants worse than oracle by > CD")
    add("CANON-B has significantly lower FPR ranks than naive (Friedman/Nemenyi)", "results/stats_nemenyi_pairs.csv",
        "Nemenyi, 17 profiles as blocks (not independent), share of the 2 B variants significantly better than naive", s10, "; ".join(t10))
    add("CANON-B is not significantly worse than the oracle (absence of evidence, NOT equivalence)", "results/stats_nemenyi_pairs.csv",
        "Nemenyi, share of the 2 B variants not significantly worse than oracle", s11, "; ".join(t11))
    # C12 McNemar
    sts, txt = [], []
    for d in DETS_MAIN:
        m = mc[(mc.detector == d) & (mc.b_variant == "split k=120") & (mc.comparison == "naive vs CANON-B") & (mc.flows == "benign")]
        sig_ = (m.p_holm < 0.05) & (m.only_first_flags > m.only_second_flags)
        sts.append(st.status_from_share(float(sig_.mean()), P, PP))
        txt.append(f"{d}: {int(sig_.sum())}/18 profiles")
    add("Per profile, CANON-B (split k=120) raises fewer false alarms than naive on the same benign flows (McNemar, Holm)",
        "results/stats_mcnemar.csv", "share of 18 profiles with Holm p < 0.05 and fewer flags under CANON-B (model seed 11)", sts, "; ".join(txt))
    # C13 attacks detected in-domain
    ok = {d: float(att[att.detector == d]["classical_in_domain"].min() >= 0.5) for d in dt.DETECTORS}
    add("Benign-only/supervised detectors detect both attack types in-domain", "results/detector_attack_type_tpr.csv",
        "share of 3 detectors whose classical in-domain TPR is >= 0.5 for BOTH handshake_flood and slow_send (pass 1.0, partial 0.5)",
        [st.status_from_share(sum(ok.values()) / 3, 1.0, 0.5)], "; ".join(f"{d}: {'yes' if v else 'no'}" for d, v in ok.items()))
    # C14 pcap-level
    sh = float(1 - pc["flow_ci_understates"].mean())
    add("Flow-level bootstrap CIs capture capture-to-capture (pcap-level) variability", "results/stats_pcap_level.csv",
        "share of (profile, detector, method) cells where SD across 4 capture sets <= flow-bootstrap SE (pass >= 0.90, partial >= 0.50)",
        [st.status_from_share(sh, *CLAIM_BOOT)], f"{sh:.2f} of {len(pc)} cells not understated")
    # C15 CANON confirmation
    c = conf_canon[conf_canon.metric.isin(["fpr", "tpr_all", "auroc"])]
    add("CANON results replicate on the independent replicate captures (CANON fitted on the main run only)", "results/canon_confirmation.csv",
        "share of (profile, detector, method, metric in fpr/tpr_all/auroc) cells with overlapping main/replicate CIs (pass >= 0.90, partial >= 0.75)",
        [st.status_from_share(float(c.ci_overlap.mean()), *CLAIM_CONFIRM)], f"{int(c.ci_overlap.sum())}/{len(c)} cells overlap")
    return pd.DataFrame(rows)


# --------------------------------------------------------------------------- notes
def md_table(df: pd.DataFrame, floatfmt: str = "{:.3f}") -> str:
    cols = list(df.columns)
    out = ["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
    for r in df.itertuples(index=False):
        out.append("| " + " | ".join(floatfmt.format(v) if isinstance(v, (float, np.floating)) else str(v) for v in r) + " |")
    return "\n".join(out)


def write_notes(cov_s, fr, diffs, mc, pc, claims, old_cov, n_draws, cal) -> str:
    L = ["# Statistical notes (generated by scripts/stats_eval.py)", "",
         "Every number is computed from the results CSVs or from repeated draws; nothing is typed. Attacks are scripted "
         "attack-like workloads, not real attacks. IsolationForest is shown but flagged WEAK: it misses handshake floods "
         "even in-domain, so its tables say little about CANON.", "",
         f"## 2. Marginal coverage over {n_draws} calibration draws (AE and RF)", "",
         "For each context the calibration flows are re-drawn at random from the 120 benign validation flows "
         f"({n_draws} seeded draws), the correction and the conformal threshold are rebuilt, and the FPR is measured on the FIXED "
         "test block. Per context: mean FPR over draws, SD over draws, share of draws with FPR <= alpha + 0.02. "
         "Theory: split conformal with n exchangeable calibration scores has true FPR ~ Beta(n + 1 - l, l), l = "
         "ceil((n + 1)(1 - alpha)). Per-context values: `results/stats_coverage_draws.csv`. Medians over the 18 contexts:", "",
         md_table(cov_s), "",
         "**Why the earlier 'alpha inside the flow-bootstrap CI' metric understates calibration randomness.** That bootstrap "
         "resamples test flows while the calibration draw, and therefore the threshold, stays fixed: it measures only "
         "test-sampling noise around the FPR of ONE threshold. A valid conformal procedure does not make that one realised "
         "threshold hit alpha; the realised FPR itself varies from draw to draw (SD in the table), and for n = 50 the mean is "
         "also below alpha (1/(n+1)-type slack). So 'alpha outside the CI' happens often even for a valid procedure, "
         "and 'alpha inside the CI' can happen by chance for an invalid one. The earlier table is kept below for reference.", "",
         "**Why the empirical SD over draws is below the theoretical SD.** The draws are subsets of the SAME 120 benign "
         "validation flows (sampling without replacement from a finite pool; k = 100 or 120 of 120 overlap almost completely, "
         "and for k = 120 only the split into fit/threshold halves changes). Re-drawing from a fixed pool therefore captures "
         "much less variation than collecting NEW calibration flows would, which is what the Beta spread describes. The "
         "measured SD is a lower bound on the real calibration randomness, not an estimate of it; the 'share of draws ok' "
         "column is correspondingly optimistic. RF has FPR 0 in every draw (tied scores), so its SD is 0 and it is valid "
         "but vacuous (mean FPR far below the 0.05 target).", "",
         "**Exchangeability.** Calibration flows come from the validation block and test flows from the later test block "
         "of the same pcap; the time-blocked split therefore slightly violates exchangeability (drift inside a capture), "
         "so the theory is an approximation. Also the test block is fixed, so the SD over draws excludes test-sampling "
         "noise (binomial SD about 0.014 at 240 benign flows).", "",
         "Reference: earlier flow-bootstrap coverage table (`results/canon_coverage.csv`, AE and RF):", "", md_table(old_cov), "",
         "## 3. Friedman + Nemenyi (17 non-classical profiles as blocks, FPR, lower is better)", "",
         "**The 17 profiles are not independent blocks**: they share one reference run, one machine, and several differ only in "
         "chain length or one algorithm. Treat p-values as descriptive.", ""]
    for det in ("rf", "ae", "iforest"):
        f = fr[det]
        L += [f"### {det}" + (" (WEAK detector: misses floods)" if det == "iforest" else ""), "",
              f"Friedman chi2 = {f['chi2']:.2f}, p = {f['p']:.3g}; Nemenyi critical difference = {f['cd']:.2f} (k = 8, N = 17).", "",
              md_table(f["ranks"].sort_values().rename("average rank").reset_index().rename(columns={"index": "method"})), ""]
        d = diffs[diffs.detector == det]
        L += ["Paired median FPR difference over profiles (method minus reference), 95% bootstrap CI over profiles:", "",
              md_table(d.drop(columns="detector")), ""]
    L += ["## 3b. Calibration-error ranking: Friedman + Nemenyi on |FPR - 0.05| (RF and AE, same 17 profiles and 8 methods)", "",
          "**Why this table exists.** Ranking raw FPR (section 3) rewards any method that flags less, so a conservative threshold "
          "wins by construction: RF scores tie at 0, the 95th-percentile threshold lands at 0 or above, and RF can reach FPR "
          "= 0 on benign flows while still catching attacks. That says nothing about being calibrated to the 5% design point. "
          "|FPR - 0.05| penalises both over- and under-flagging, so it measures calibration. Lower is better; same caveats "
          "(profiles are not independent blocks; claims-table rules are unchanged and still use the raw-FPR analysis).", ""]
    for det in DETS_MAIN:
        c = cal[det]
        tab = pd.DataFrame({"average rank": c["ranks"], "median |FPR - 0.05|": c["median_err"]}).sort_values("average rank")
        L += [f"### {det}: Friedman chi2 = {c['chi2']:.2f}, p = {c['p']:.3g}; Nemenyi CD = {c['cd']:.2f}", "",
              md_table(tab.reset_index().rename(columns={tab.index.name or "index": "method"})), ""]
    s = mc.copy()
    summ = (s.assign(sig=(s.p_holm < 0.05)).groupby(["detector", "b_variant", "comparison", "flows"])["sig"].sum().reset_index()
            .rename(columns={"sig": "profiles_significant_of_18"}))
    L += ["## 4. McNemar (exact), paired flow decisions on the same test flows, per profile, Holm within each family", "",
          "Model seed 11 only (one detector instance per method). `benign` = false alarms, `attack` = detections. "
          "Per-profile counts in `results/stats_mcnemar.csv`. Profiles significant at Holm p < 0.05 (either direction):", "",
          md_table(summ, "{:.0f}"), "",
          "## 5. Pcap-level uncertainty (4 replicated profiles; main run + 3 replicates = 4 capture sets of benign test flows)", "",
          "FPR is computed per capture set (the benign_web + benign_api test blocks of one capture run). `sd_across_pcaps` is the SD "
          "over the 4 sets; `flow_se` is the main-run flow-bootstrap CI half-width / 1.96. A cell is flagged where the SD across "
          "captures exceeds the flow-bootstrap SE: there the flow CI understates the uncertainty.", "",
          f"Flagged cells: {int(pc.flow_ci_understates.sum())} of {len(pc)}. By detector: " +
          ", ".join(f"{d}: {int(g.flow_ci_understates.sum())}/{len(g)}" for d, g in pc.groupby("detector")) + ". By method: " +
          ", ".join(f"{m}: {int(g.flow_ci_understates.sum())}/{len(g)}" for m, g in pc.groupby("method")) + ".", "",
          md_table(pc[pc.detector.isin(DETS_MAIN)][["detector", "profile", "method", "mean_fpr", "sd_across_pcaps", "min", "max", "flow_ci_lo", "flow_ci_hi", "sd_over_flow_se"]]), "",
          "## 6. CLAIMS TABLE", "",
          "Status rules were fixed before the first run (constants `CLAIM_*` in the script). PASS / PARTIAL / FAIL is "
          "computed, not judged by hand. Do not claim beyond the evidence column.", "", md_table(claims), "",
          "## Caveats", "",
          "- Scripted workloads, one machine, one cipher suite, 18 profiles are 18 doses and not independent samples.",
          "- Profiles are not independent blocks (shared reference run), so Friedman/Nemenyi p-values are descriptive.",
          "- Absence of a significant difference (CANON-B vs oracle) is not equivalence.",
          "- McNemar uses one model seed and treats test flows within a pcap as independent.",
          "- CANON-A2 is exploratory and post-hoc; the split variant was added after seeing v0 results."]
    return "\n".join(L) + "\n"


# --------------------------------------------------------------------------- main
def show(title: str, df: pd.DataFrame, fmt: str = "{:.3f}") -> None:
    print(f"\n=== {title}")
    print(df.to_string(index=False, float_format=lambda x: fmt.format(x)))


def main(argv: list[str]) -> int:
    n_draws = int(argv[argv.index("--draws") + 1]) if "--draws" in argv else 200
    t0 = time.time()
    main_df, rep_df = ce.load("lab_flows.csv"), ce.load("lab_flows_rep.csv")
    cert = RES / "cert_overhead.csv"
    o_cert = dict(pd.read_csv(cert)[["auth", "o_cert"]].itertuples(index=False)) if cert.exists() else None
    cn = ce.Canon(main_df, o_cert)
    base, cres = pd.read_csv(RES / "detector_baseline.csv"), pd.read_csv(RES / "canon_eval.csv")
    dom = build_domains(main_df, cn)
    print(f"setup done ({time.time() - t0:.0f} s)", flush=True)

    cov = coverage_draws(cn, main_df, n_draws)
    cov.to_csv(RES / "stats_coverage_draws.csv", index=False)
    cov_s = coverage_summary(cov)
    cov_s.to_csv(RES / "stats_coverage_summary.csv", index=False)
    show(f"2. marginal coverage over {n_draws} calibration draws: medians over the 18 contexts", cov_s)
    print(f"   ({time.time() - t0:.0f} s)", flush=True)

    fr, diffs, pairs = friedman_section(base, cres)
    diffs.to_csv(RES / "stats_paired_median_diffs.csv", index=False)
    pairs.to_csv(RES / "stats_nemenyi_pairs.csv", index=False)
    for det in ("rf", "ae", "iforest"):
        f = fr[det]
        show(f"3. Friedman ranks, {det}{' (WEAK detector)' if det == 'iforest' else ''}: chi2={f['chi2']:.2f} p={f['p']:.3g} "
             f"Nemenyi CD={f['cd']:.2f} (k=8, N=17; profiles are not independent blocks)",
             f["ranks"].sort_values().rename("avg_rank").reset_index().rename(columns={"index": "method"}), "{:.2f}")

    cal = calibration_section(base, cres)
    pd.concat([c["pairs"] for c in cal.values()]).to_csv(RES / "stats_nemenyi_pairs_calibration.csv", index=False)
    for det in DETS_MAIN:
        c = cal[det]
        show(f"3b. Calibration-error ranking |FPR - 0.05|, {det}: chi2={c['chi2']:.2f} p={c['p']:.3g} Nemenyi CD={c['cd']:.2f} "
             "(lower is better; profiles are not independent blocks)",
             pd.DataFrame({"avg_rank": c["ranks"], "median_abs_err": c["median_err"]}).sort_values("avg_rank").reset_index(), "{:.3f}")

    mc = mcnemar_section(cn, dom, main_df)
    mc.to_csv(RES / "stats_mcnemar.csv", index=False)
    pc = pcap_level(cn, dom, main_df, rep_df, base, cres)
    pc.to_csv(RES / "stats_pcap_level.csv", index=False)
    print(f"mcnemar and pcap-level done ({time.time() - t0:.0f} s)", flush=True)

    dose = pd.read_csv(RES / "detector_baseline_dose_response.csv")
    cb, cc = pd.read_csv(RES / "detector_baseline_confirmation.csv"), pd.read_csv(RES / "canon_confirmation.csv")
    cc = cc[cc.method.str.startswith("canon_")]
    att = pd.read_csv(RES / "detector_attack_type_tpr.csv")
    claims = claims_table(base, cres, cov_s, fr, mc, pc, dose, cb, cc, att)
    claims.to_csv(RES / "stats_claims.csv", index=False)
    old = pd.read_csv(RES / "canon_coverage.csv")
    old = old[old.detector.isin(DETS_MAIN) & old.method.isin(["canon_b_k100_true", "canon_bs_k60_true", "canon_bs_k100_true", "canon_bs_k120_true"])]
    (ROOT / "docs" / "stats_notes.md").write_text(write_notes(cov_s, fr, diffs, mc, pc, claims, old, n_draws, cal), encoding="utf-8", newline="\n")
    pd.set_option("display.width", 250, "display.max_colwidth", 90)
    show("6. CLAIMS TABLE", claims[["claim", "test", "status", "detail"]])
    print(f"\nflow CI understates pcap-level uncertainty in {int(pc.flow_ci_understates.sum())}/{len(pc)} cells")
    return 0


if __name__ == "__main__":
    sys.exit(sidecar.tracked(main, ROOT, __file__, sys.argv[1:]))
