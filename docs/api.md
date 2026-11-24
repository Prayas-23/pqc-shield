# PQ-DRIFTLAB API (read-only)

A FastAPI service over the project's **stored** results. It does not recompute research results on request, capture
traffic, run shell commands or write files. It binds to `127.0.0.1` only and its CORS policy allows only
`http://localhost:5173` (GET only).

```
make api            # .venv/Scripts/python -m uvicorn api.main:app --host 127.0.0.1 --port 8000
```

Needs the stored files produced by the pipeline scripts: `data/flows/lab_flows.csv` and `results/lab_drift.csv`,
`detector_baseline.csv`, `canon_eval.csv`, `stats_pcap_level.csv`. A missing results file gives `503` with a message.
`stats_pcap_level.csv` is optional (the `pcap_level` field is then `null`).

**WebSocket.** `/api/stream` is served by uvicorn through the `websockets` library (in `requirements.txt`).

## Provenance block (every response)

```json
"provenance": {"data_source": "lab_captures", "synthetic": false,
               "results_code_commit": "<commit that produced the results, from the sidecar>",
               "served_by_commit": "<git HEAD sha of the repository serving the request>",
               "results_files": {"results/detector_baseline.csv": {"code_commit": "...", "generated_at": "...", "script": "..."}},
               "generated_at": "<newest sidecar time, else newest file mtime, UTC>", "source_files": ["results/..."]}
```

* `results_code_commit` comes from the sidecar `results/<name>.meta.json` that every analysis script writes
  (`{code_commit, generated_at, script}`; `-dirty` is appended if the working tree had changes when the script started;
  see `pqdl.sidecar.tracked`). A source file with no sidecar (everything produced before tracking existed, and the lab flows
  file) counts as unknown: if no source file has one the value is `"unknown (generated before tracking)"`; if all agree it
  is that commit; otherwise `"mixed (see results_files)"`. Sidecars are never created by the API and were not back-filled.
* `served_by_commit` is read from `.git` (no subprocess); it says which code served the response, not which code made the
  results.
* Test-only responses from the SYNTHETIC fixture say `"data_source": "SYNTHETIC_TEST_FIXTURE", "synthetic": true`.

## Routes

| Route | Parameters | Returns |
|---|---|---|
| `GET /api/meta` | none | `version`, `served_by_commit`, `profiles` (18 lab profiles `kem\|auth\|chain`), `methods` (baseline, canon, stream), `detectors`, `caveats`, `classical_profile`, `design_fpr` (the 5 % operating point), `ci_level` (level of the bootstrap intervals) |
| `GET /api/ladder` | `kem`, `auth`, `chain` (required) | `model.ladder` = `handshake_ladder()` at `LAB_MSS = 1448`, `model.B_S/B_C`, `observed` (median `hs_s2c_bytes`/`hs_c2s_bytes`, `n_flows`), `comparison` (observed, model, difference, % of observed). 404 for an unknown profile |
| `GET /api/drift` | `workload`, `view` (`hs`\|`app`\|`flow`), `limit`, `offset` | rows of `lab_drift.csv`: `eta2`, `partial_eta2`, `psi`, `mmd2`, `mmd2_p_value`, with the noise floors `noise95_eta2`, `noise95_max_psi` |
| `GET /api/detectors` | `detector` (`rf`\|`ae`\|`iforest`), `method`, `profile`, `dataset` (default `main`), `metric`, `limit` | one record per (dataset, detector, method, profile) with `metrics{fpr,tpr_all,tpr_*,auroc,...}` each `{value, ci_lo, ci_hi, seed_sd}`; `pcap_level` (mean FPR and SD across the 4 capture sets, min, max, whether the flow CI understates) only where it exists (4 replicated profiles, 8 methods) |
| `GET /api/pqmix` | `pi` in [0, 1], `detector`, `profile` (all required) | for `naive`, `V_APP`, `CANON-B split k=120`, `CANON-B v0 k=100`: `fpr_mix = pi * fpr_profile + (1 - pi) * fpr_classical`, with both measured FPRs and their CIs; `formula` states it; `simulation: false` |
| `WS /api/stream` | `detector`, `method` (`naive`\|`naive_app`\|`canon_a`\|`canon_b`), `profile` (default `mlkem768\|mldsa65\|leaf_int`), `speed` (flows/s, default 50), `limit` | a **replay** of recorded test-block flows in recorded start-time order |

### Stream protocol

Messages are JSON: one `hello` (`replay: true`, a `notice` saying it is a REPLAY of recorded captures and not live traffic, the
provenance block), then one `flow` per recorded flow (`index`, `recorded_offset_s`, `workload`, `label`, `score`,
`threshold`, `alert`, `flow_s2c_bytes`, `flow_c2s_bytes`), then `done` (alert counts). Invalid parameters close the socket
with code 1008. The replay rate is `speed` flows per second; the original captures are separate files, so recorded gaps
between workloads are not replayed in real time.

Detectors are trained once (model seed 11, classical training block, threshold = 95th percentile of the classical benign
validation scores) and cached: at startup when `eager_train` is on (the default for `make api`), lazily otherwise.
`canon_a` corrects the bytes group with the size-model difference; `canon_b` is the split-conformal variant (k = 120: first 60
benign validation flows fit the shift, last 60 set the per-context threshold). The profile's true context is used for the
correction (c-hat is 100% accurate in the lab data).

### pqmix caveats

The mix is a weighted average of two measured per-profile FPRs (main run, test blocks). It assumes the detector's behaviour on
each traffic type does not depend on the mix, ignores flow ordering and attack flows, and gives no CI for the mix itself.

## Caveats (also in `/api/meta`)

Single machine; local Docker network; scripted attack-like workloads (not real attacks); one cipher suite; 18 profiles are
18 doses, not independent samples; time-blocked splits inside one pcap; IsolationForest is a weak baseline.

## Tests

`.venv/Scripts/python -m pytest tests/test_api.py` runs the SYNTHETIC-fixture tests (`tests/synthetic_api_fixture.py`, every
file and `source` value labelled SYNTHETIC). `pytest -m realdata tests/test_api.py` runs one test per route against the real
results.
