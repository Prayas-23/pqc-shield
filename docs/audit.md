# Repository audit

Scope: all tracked files (code, docs, API, web UI, tests, lab scripts) at the commit that adds this file. Method: searches of the
tracked tree (typed numbers in code and generated-text templates, `synthetic` usage, imports, `random` calls), a function-by-test
cross-reference for `src/pqdl`, a check of capture windows against commit times, a pattern search for secrets, personal paths and
e-mail addresses, and a read of the hand-written docs. This is a review by the project's assistant, not an independent audit;
it will have missed things. **Fixed** = changed in this commit. **Open** = listed for the project owners to decide.

## (a) Hard-coded result numbers

| # | Where | Finding | Status |
|---|---|---|---|
| a1 | `scripts/canon_eval.py` (text of `docs/canon_notes.md`) | A typed measurement ("byte deltas are off by ~34 B ... 170-370 B") in generated notes | **Fixed**: now points to `docs/canon_attribution.md` |
| a2 | `scripts/canon_eval.py` (console) | Typed "c-hat accuracy is 100%" | **Fixed**: prints the computed accuracy |
| a3 | `scripts/stats_eval.py` (text of `docs/stats_notes.md`) | Typed "/18 profiles", "binomial SD about 0.014 at 240 benign flows", "n = 50", "18 profiles" | **Fixed**: denominators computed, other wording made generic |
| a4 | `api/app.py` caveats (shown in `/api/meta` and the UI) | "The 18 profiles are 18 'doses'" (a count typed into a caveat) | **Fixed** |
| a5 | `docs/canon_design.md` section 10 | Attribution numbers typed by hand (they equal `docs/canon_attribution.md`) | Open: left as written because the design doc is a frozen record; the generated file is the source of truth |
| a6 | `docs/lab_findings.md` | One-off observations typed from the lab image (error text, "0 matches for slh", counts of failed profiles) | Open: not re-runnable by a script; the smoke test (`lab/smoke_test.sh`) reproduces the pass/fail |
| a7 | `api/app.py`, `docs/api.md` | `CI_LEVEL = 0.95` is typed; it duplicates the quantiles in `pqdl.detectors.summarise` | Open: should be one constant imported from `pqdl` |
| a8 | `api/app.py` caveats; `scripts/stats_eval.py`, `scripts/detector_baseline.py` text | Qualitative result statements typed into generators ("IsolationForest misses handshake floods even in-domain", "RF has FPR 0 in every draw") | Open: true for the current results, but not conditioned on the data |
| a9 | `scripts/detector_baseline.py` text | Design arithmetic typed ("300 -> 120/60/120 ...", "last 40% test") rather than computed from `block_sizes` | Open: design constants, not results |
| a10 | `src/pqdl/profiles.py`, `src/pqdl/handshake.py` | Standards sizes and overhead defaults (all marked VERIFY) | Open: inputs to the model, not results, but still unverified against the standards |
| a11 | `docs/screens/*.png` | Static images of the UI with numbers rendered from the results at that time | Open: go stale if results are regenerated |
| a12 | README, web UI | Checked: no result numbers in `README.md`; the UI contains only chart scales, control ranges and colours (design point and CI level come from `/api/meta`) | OK |

Generated docs (`docs/*_notes.md`, `docs/stats_notes.md`, `docs/results_summary.md`, `docs/data_schema.md`) contain many numbers
by construction; they are written by scripts from the data and say so in their headers.

## (b) SYNTHETIC output not labelled

* Synthetic data exists only in `src/pqdl/synth.py` (label constant `SYNTHETIC_SOURCE`), the pcap fixtures in
  `tests/test_pcap*.py` (files named `synthetic*.pcap`) and `tests/synthetic_api_fixture.py` (every file name and `source` value
  says SYNTHETIC). None of it is written outside pytest temporary folders.
* The API answers `"synthetic": true` and `"data_source": "SYNTHETIC_TEST_FIXTURE"` when pointed at a fixture; the web header
  shows "SYNTHETIC test fixture, not lab data" in that case. Both are tested.
* **Fixed:** the toy files in `tests/test_loaders.py` imitated the real dataset schemas without saying they are synthetic; the module docstring now says so.
* No unlabelled synthetic output found in `results/`, `docs/`, the API or the UI.

## (c) Claims in the docs that are not in the claims table, or conflict with it

The claims table (`docs/stats_notes.md`) covers the detector and CANON claims. These statements appear elsewhere and have no row:

| # | Statement and where | Issue |
|---|---|---|
| c1 | Handshake bytes are fixed by key exchange and signature (`docs/lab_drift_notes.md`, H1) | Not in the table |
| c2 | Application-phase features are invariant to the profile within the noise floor (`docs/lab_drift_notes.md`, H3) | Not in the table; the table's "naive failure" claims rest on it |
| c3 | Whole-connection flow features drift strongly (`docs/lab_drift_notes.md`, H4) | Not in the table |
| c4 | Handshake-phase timing differs between profiles beyond capture-to-capture noise (`docs/rep_timing_notes.md`) | Not in the table |
| c5 | The size model reproduces profile-to-profile byte differences (`docs/size_model_check.md`; the lab comparison in `docs/canon_attribution.md`) | Not in the table; the model is off by a large margin for single-certificate chains with default overheads |
| c6 | The context estimator is exact (`docs/canon_notes.md`) | Not in the table; true only because the lab is deterministic |
| c7 | "CANON-B is not significantly worse than the oracle" is PASS (rank test on raw FPR) | **Possible conflict:** the calibration-error ranking (section 3b of `docs/stats_notes.md`) ranks CANON-B clearly below the oracle for RF, because RF's CANON-B FPR is near zero (over-conservative). The claim is true under its pre-set rule and still misleading for RF; the rules were not changed, as instructed |
| c8 | "Detectors detect both attack types in-domain" (PARTIAL) | TPR is not informative about real attacks because the attacks are scripted; the claim wording should say so |
| c9 | `lab/README.md` said three workloads and "Part B done"; `data/README.md` listed BCCC-UDP-QUIC-IDS-2025 as planned | Stale. **Fixed** (four workloads, current status; BCCC marked not used) |

Recommendation: add rows c1-c6 to the claims table (with rules fixed in advance) or remove the corresponding prose conclusions.

## (d) `AGENTS.md` rules not met

| Rule | Finding |
|---|---|
| 1 | Met: Python 3.11+ is declared, FastAPI, React + Vite + TypeScript, free tools. |
| 2 | Not fully met: items a1-a11 above (a1-a4 fixed). Main-run capture code version is untraceable (the manifest says `unknown`, git was set up after the run). |
| 3 | Met for code, filenames, API and UI (section b). |
| 4 | Met as far as the repo shows: the compose network is `internal: true`, no published ports, no decryption, no scanning code. Not testable from the repo: that nothing was ever run outside the lab. |
| 5 | **Gaps.** Public functions in `src/pqdl` with no test that names them: `detectors.bootstrap_metrics`, `lab_drift.invariance_for_workloads`, `lab_drift.handshake_two_way`, `lab_drift.render_notes`, `lab_drift.md_table`, several loader helpers (`normalise_label_series`, `numeric_to_float64`, `label_counts`, `nonzero_nan_counts`, `resolve_fwd_header_twin`, `read_observed_kem`), `profiles.kem_sizes`, `profiles.auth_sizes`, `sidecar.write_for_outputs`. Most are exercised indirectly through tested callers, which is not the same as a direct test. Maths that lives in `scripts/` (for example `coverage_draws` in `stats_eval.py`, `variance_table` in `rep_timing.py`, `Canon` in `canon_eval.py`) is a composition of tested primitives but has no test of its own. Seeds: no unseeded random call found in `src`, `scripts` or `api`. |
| 6 | Met for flows (every row has `source`); no mixing of the two public datasets. Results CSVs are aggregates and carry no `source` column. The "pooled" method unions profiles of one source (the lab), which the rule allows. |
| 7 | Process rule; followed in the task summaries, not enforceable from the repo. |
| 8 | `requirements.txt` lists `torch` (with a CPU index) and nothing imports it: an unused heavy dependency from the initial skeleton. All web and API dependencies are on the approved lists (`vitest` is pinned to 3.x for the local Node version). |
| 9 | No commit falls inside either capture window (checked against the manifests). Historically, code was edited and tests were run during the main capture run before this rule existed (reported earlier by the project owners); that run's timing features carry that risk, and its manifest has no code version. |

## (e) Tracked files that should not be

* Tracked: source, docs, lab scripts, web sources, `web/package-lock.json`, screenshots (a few MB in total). No datasets, pcaps, CSV
  results, pickles, `node_modules` or build output are tracked (`.gitignore` covers them).
* No secrets, keys or tokens found by a pattern search; no local absolute paths, user names or e-mail addresses in tracked file
  contents.
* **Open, personal data in git metadata:** commit author name and e-mail address are stored in every commit. They cannot be removed
  without rewriting history; decide this before making the repository public.
* **Open, dataset content in a doc:** `docs/data_schema.md` (generated, the largest tracked file) contains a few sample rows of the
  public datasets (flow identifiers and IP addresses of the datasets' testbed). Check the dataset licence before publishing, or
  drop the sample rows from `scripts/inspect_data.py`.
* **Open, provenance gap:** `results/*.csv` are untracked (by design) and have no commit record until each analysis is re-run with
  the sidecar-writing scripts. `canon_eval.py` and `stats_eval.py` were re-run for this audit (every results CSV came out
  byte-identical except the wording of `stats_claims.csv`, and no claim status changed) and their sidecars record the commit with a
  `-dirty` suffix, because untracked files existed in the tree at the time; the other analyses still report "unknown (generated
  before tracking)".
