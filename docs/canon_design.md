# CANON v0 — design and evaluation plan (written BEFORE any CANON code or run)

Status: **frozen design**. Any later change is recorded in the "Change log" at the bottom with the reason; nothing
is changed silently after test results exist. No CANON test-block result existed when this was written.

Reading of the request: item 6 of the brief was cut off after "apply CANON trained on the main run to the 4"; it is
read (and confirmed by the user) as "the 4 replicate profiles in `lab_flows_rep.csv`, same metrics, plus agreement
with the main run".

## 1. Setting

CANON is for detectors that **cannot isolate the handshake** (an off-the-shelf flow detector). It sees only
`V_FLOW` (`LAB_FLOW_FEATURES`, 11 whole-connection features) plus the early-packet **context features**
`CONTEXT_FEATURES`. It never sees `hs_*` or `app_*` columns. Context features are used only by the context
estimator and are **never given to any detector** (asserted in code and tested). Attacks are scripted attack-like
workloads, not real attacks. Data: `lab_flows.csv` (main run, source `pq_lab`) for everything fitted;
`lab_flows_rep.csv` only for confirmation; never merged.

## 2. Parser addition (item 0)

`CONTEXT_FEATURES` in `features.py`: `flow_first12_c2s_size_1..12` and `flow_first12_s2c_size_1..12`: TCP payload
sizes of the first 12 data packets (payload > 0) of the connection in each direction, in capture order, padded with
0. FEATURES_VERSION is bumped to "4". The existing columns must come out byte-identical when the flows are
regenerated (checked, reported). `data/flows/lab_flows.csv` and `lab_flows_rep.csv` are regenerated.

## 3. Context and estimator (item 1)

Context c = profile (kem, auth, chain) = 18 classes. Context estimator c-hat: RandomForest (300 trees, seed 0) on
the 24 CONTEXT_FEATURES, trained on the **training blocks only** of the main run (all 18 profiles, both labels,
all workloads: the context must be recognised for attack flows too). Reported: accuracy, per-profile recall and
the full confusion matrix on the main test blocks and on the replicate test blocks. Note: c-hat needs labelled
training flows from every context, so "zero PQ training data" holds for the CANON-A correction rule, **not** for
the estimator; the TRUE-context variants (item 4) isolate this.

## 4. CANON-A: model-based correction (item 2)

For a flow with context c and classical reference c0 = `X25519|ecdsa_p256|leaf_int`, with `handshake.py`,
default `Overheads`, `mss = LAB_MSS (1448)`, n_certs = 1 for chain `leaf`, 2 for `leaf_int`, auth/kem names mapped
to the `SIZES` table (`mlkem768`->MLKEM768, `ecdsa_p256`->ECDSA-P256, ...):

- delta_s2c = B_S(c) - B_S(c0);  delta_c2s = B_C(c) - B_C(c0)
- dpkt_s2c = n_packets(B_S(c)) - n_packets(B_S(c0));  dpkt_c2s = n_packets(B_C(c)) - n_packets(B_C(c0))

Differences only (the size model was validated on differences). Corrections, applied to the feature groups that the
attribution of section 8 marks as drivers AND the model can express:

- bytes group: `flow_s2c_bytes -= delta_s2c`, `flow_c2s_bytes -= delta_c2s`
- pkts group: `flow_s2c_pkts -= dpkt_s2c`, `flow_c2s_pkts -= dpkt_c2s`
- pktlen group, **mean only**: `flow_pkt_len_mean` recomputed as corrected total bytes / corrected total packets
  (exact identity: the feature is total payload / all packets of the connection). `flow_pkt_len_std` and
  `flow_pkt_len_max` are not expressible from differences and are left uncorrected.
- time group (`flow_iat_*`, `flow_duration`): **no model** (the model has a timing term but it is not validated
  against the lab); never corrected by CANON-A.

Known limits stated in advance: ACK packets the client sends in response to extra server packets are not modelled
(the size model has no ACK term), the default `o_cert` (40 B) is far from the lab's measured per-certificate
overhead, and the model's ClientHello base (250 B) is approximate. No constant is tuned. Counts are floored at 0
after correction.

The detector is the **naive** detector (trained and thresholded on the classical profile only, V_FLOW), applied to
corrected features: no PQ data of any kind enters CANON-A's correction.

## 5. CANON-B: k-shot data-driven correction with conformal threshold (item 3)

- Calibration bank: for every context c (profile) draw k benign flows from that profile's **validation block**
  (seeded permutation, first k; so k=10 ⊂ k=30 ⊂ k=100). k in {10, 30, 100}. Test blocks are never touched.
- Per-context regression g_j(c): regression of feature j on the context indicator, i.e. the per-context robust
  location shift: `g_j(c) = median(x_j | calibration flows of c) - median(x_j | classical train benign flows)`.
  Residualised feature: `x_j' = x_j - g_j(c)`, for every feature j in the driver groups of section 8
  (`shifted` set); other features are untouched. v0 is deliberately additive and constant per context.
- Detector: the naive detector (classical train block, V_FLOW). Score s(x') on residualised features.
- Per-context split-conformal threshold: `tau_c` = the `ceil((n_c + 1)(1 - alpha))`-th smallest score of the n_c = k
  residualised calibration flows of context c, alpha = 0.05; flag if score > tau_c. If that rank exceeds n_c
  (k = 10: rank 11 > 10), tau_c = +infinity (the conformal guarantee is vacuous at this k, nothing is flagged).
- The same k flows are used for g_j and tau_c (as in the brief); this is mildly optimistic and the coverage report
  (section 7) shows whether it matters.

## 6. Variants (item 4)

Each of CANON-A and CANON-B runs with the **TRUE** context (profile label of the flow, an oracle for the estimator)
and with **c-hat** (the estimator's prediction per flow). TRUE vs c-hat separates estimator error from correction
error. For c-hat, a flow predicted as context c uses c's correction / g_j(c) / tau_c from the calibration bank.

## 7. Evaluation (items 5 and 6)

- Same three detectors (RF, AE, IsolationForest), same model seeds (11-15), same time-blocked splits (first 40%
  train, next 20% validation, last 40% test, per pcap), same test blocks, same 95th-percentile validation operating
  point where a threshold is not replaced by tau_c, same metrics (FPR, TPR overall and per attack type, AUROC,
  false alarms per 10,000, FPR ratio) and the same stratified seeded 1,000-resample bootstrap, **all 18 profiles**.
- Compared against naive, V_APP-naive, pooled and oracle from `detector_baseline.csv`, re-run if any code or flow
  file changed (results must reproduce; differences reported).
- Conformal coverage: FPR per context vs alpha = 0.05 on the test block (benign), per k, detector and variant;
  also the share of contexts whose FPR 95% CI contains alpha.
- Confirmation: CANON built on the main run (c-hat, bank, thresholds; nothing refitted) applied to the test blocks
  of the 4 replicate profiles (pooled and per replicate); metrics as above; agreement with the main run as in the
  detector baseline (CI overlap, absolute difference). c-hat accuracy and confusion matrix also reported there.
- Success is not pre-judged; every number is computed; no result is hard-coded. Failures are reported.

## 8. Attribution protocol (pre-registered; uses training and validation blocks only, never test)

No attribution analysis existed in the repository, so one is run *before* the corrected-feature list is frozen.
Feature groups: **bytes** {flow_c2s_bytes, flow_s2c_bytes}; **pkts** {flow_c2s_pkts, flow_s2c_pkts};
**pktlen** {flow_pkt_len_mean, flow_pkt_len_std, flow_pkt_len_max}; **time** {flow_iat_mean, flow_iat_std,
flow_iat_max, flow_duration}.
For each detector (RF, AE, IsolationForest; 5 model seeds) the naive detector (classical train block, classical
validation threshold) is evaluated on the **validation-block benign flows** of the 17 other profiles, (a) with all
V_FLOW features, (b) leaving one group out (retrained), (c) with that group only (retrained). The median over the
17 profiles of the benign FPR is the statistic. **Rule, fixed now:** a group is a *driver* if, for RF or AE, either
(a) minus (b) >= 0.10 (leaving it out lowers FPR by at least 0.10) or (c) >= 0.25. The corrected set of CANON-A is
the drivers that section 4 can express; the residualised set of CANON-B is all features of the drivers. Also
reported descriptively (no tuning): observed vs model-predicted delta of the per-profile benign validation medians
of flow_s2c_bytes, flow_c2s_bytes, flow_s2c_pkts, flow_c2s_pkts.

## 9. Caveats

Scripted workloads, one machine, one cipher suite, 18 profiles are 18 "doses" not 18 independent traffic samples;
time-blocked splits inside one pcap; the c-hat/bank/threshold are fitted on the same captures they are tested on
(different time blocks) except in the replicate confirmation; bootstrap CIs resample flows and ignore pcap-level
variance; conformal coverage is only claimed for exchangeable calibration/test flows.

## Change log

(none yet)
