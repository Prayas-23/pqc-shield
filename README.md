# PQ-DRIFTLAB

PQ-DRIFTLAB measures how post-quantum TLS handshakes (ML-KEM key exchange, ML-DSA signatures) shift network-flow features and
raise the false-alarm rate of ML intrusion detectors, using real handshake captures from a local container lab. It also
contains a correction method, CANON, and the statistics used to check what the data does and does not support.

## Project status

A research prototype by two B.Tech CSE students. The pipeline runs end to end on one Windows machine: Docker lab, pcap-to-flow
parser, drift analysis, detector baseline, CANON v0, statistics, a read-only API and a web viewer. It has not been peer reviewed.
Some of the claims we set out to test are only partly supported; the status of each one is computed, not asserted, in the
claims table (see "Where the results are"). CANON v0 was frozen before it was evaluated, and later additions are recorded as
post-hoc in `docs/canon_design.md`.

## What is real and what is SYNTHETIC

* **Real:** the lab captures (`data/pcaps*`, local only), the flows parsed from them (`data/flows/`), every file in `results/`, and
  everything the API and the web UI show. The two public datasets (below) are real third-party data, used only for the
  dataset-level analyses.
* **SYNTHETIC:** appears only in unit-test fixtures (`tests/`, `src/pqdl/synth.py`, `tests/synthetic_api_fixture.py`). Every
  such file, column value and API response is labelled SYNTHETIC. If the API is ever started on a fixture it answers
  `"synthetic": true` and the web header says so.
* No result number is typed into code, the UI or this README. Numbers come from code you can re-run; `docs/results_summary.md`
  is generated from the results files and names the provenance of each.

## Requirements

* Windows 11 (developed and tested there; the detached capture launcher is PowerShell) with **Docker Desktop** using Linux
  containers.
* **Python 3.11 or newer** (`make` is optional; the commands are shown without it where it matters).
* **Node.js 20 or newer** with npm (developed on 22.11) for the web viewer.
* Internet access is needed once, at build time, to fetch the base image, the OpenSSL source tarball (verified by checksum) and the
  packages. Nothing in the lab reaches the network when it runs.

## Reproducing everything from scratch, in order

Commands are for PowerShell or Git Bash at the repository root. Results depend on the seeds in the scripts; all randomness is seeded.

1. **Setup.** `make setup` creates `.venv`, installs `requirements.txt` and the package (`pip install -e .`). Then
   `cd web && npm install`.
2. **Datasets** (see "Datasets"). Put them under `data/cic_pqc_oav/` and `data/cic_ids2017/`. Then, from the root:
   `.venv/Scripts/python scripts/inspect_data.py` (writes `docs/data_schema.md`), `scripts/feature_audit.py`,
   `scripts/pqc_drift.py` and `scripts/size_model_check.py`.
3. **Lab build.** `docker build --target lab -t pqdl-lab:openssl-3.5.9 lab/` (verifies the OpenSSL tarball's SHA-256), then the
   smoke test `docker run --rm pqdl-lab:openssl-3.5.9 /lab/smoke_test.sh`. A profile that the toolchain cannot negotiate fails
   there and is dropped, never faked. `lab/README.md` has the safety rules and details.
4. **Capture run.** Leave the machine idle (CPU load adds noise to timing features) and do not edit code while it runs
   (`AGENTS.md` rule 9). Main matrix: `powershell -ExecutionPolicy Bypass -File lab\start_run.ps1 -Mode full`. Replicate run:
   `... -Mode rep`. A short check run: `-Mode mini`. Progress is in `lab/run.log` and the manifest of each output folder; the run
   resumes if started again. The driver rejects a capture that drops packets, has offloads on, or has an unexpected number of
   connections.
5. **Flows.** `.venv/Scripts/python scripts/pcaps_to_flows.py --summary` (main run, writes `data/flows/lab_flows.csv`) and
   `.venv/Scripts/python scripts/pcaps_to_flows.py --pcaps data/pcaps_rep --out data/flows/lab_flows_rep.csv`
   (add `--no-smoke` when Docker is not available to the script).
6. **Analyses**, in this order, each writing to `results/` (and a provenance sidecar `results/<name>.meta.json`) and mostly to
   `docs/`: `scripts/lab_drift.py`, `scripts/rep_timing.py`, `scripts/detector_baseline.py`, `scripts/canon_attribution.py`,
   `scripts/measure_cert_overhead.py` (needs Docker), `scripts/canon_eval.py`, `scripts/stats_eval.py`, then
   `scripts/make_results_summary.py`.
7. **API.** `make api` (read-only, bound to `127.0.0.1`; routes in `docs/api.md`).
8. **Web viewer.** `make web`, then open `http://localhost:5173` (details in `docs/web.md`). `scripts/screenshots.py` regenerates
   `docs/screens/` while both are running.
9. **Tests.** `make test` (Python), `.venv/Scripts/python -m pytest -m realdata` (needs the real data), `cd web && npm test`.

## Datasets

Datasets are downloaded manually from their official distribution pages and are **never committed** (`data/` is git-ignored except
`data/README.md`). They are never merged into one training set: every row carries a `source` column and splits do not mix sources.
Follow the licence and citation terms stated by each distributor.

* **CIC-PQC_OAV**: obtain it from its official distribution page and cite it exactly as that page requests. We have not verified
  the citation text here; do not rely on this README for it.
* **CIC-IDS2017**: Canadian Institute for Cybersecurity, University of New Brunswick. The authors request citing: I. Sharafaldin,
  A. Habibi Lashkari and A. A. Ghorbani, "Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic
  Characterization", ICISSP 2018.
* **BCCC-UDP-QUIC-IDS-2025** was planned and is **not used**: QUIC is outside what the lab captured.

`docs/data_schema.md` is generated from the files in `data/`; it includes a few sample rows of the datasets for schema
inspection and should be removed from any public copy of the repository if the dataset licence forbids redistribution.

## Safety rules

Defensive research only (`AGENTS.md` rule 4, `lab/README.md`):

* All traffic is generated between **our own containers** on one Docker network declared `internal: true`: no route to the
  internet, the LAN or the host's other networks, no published ports.
* Attack-like traffic (handshake floods, slow sends) is sent only from one lab container to another. No exploit code.
* **No decryption**: no key logging, no TLS interception. Captures are analysed through what is visible on the wire.
* **No scanning** of any third-party host, and nothing is ever placed inline on a real network.
* The PKI is a private throwaway CA for the lab; its keys are never installed into any trust store and never reused.
* Captures stay on the local disk. The API and the web viewer are read-only and bind to `127.0.0.1`.

## Where the results are

* **Claims table:** `docs/stats_notes.md`, section "CLAIMS TABLE". Each headline claim lists its evidence file, its test and a
  PASS / PARTIAL / FAIL computed by rules fixed before the run. Do not claim anything beyond it.
* **Generated summary with provenance:** `docs/results_summary.md` (from `scripts/make_results_summary.py`).
* Per-analysis notes: `docs/detector_notes.md`, `docs/canon_notes.md`, `docs/canon_design.md`, `docs/lab_drift_notes.md`,
  `docs/rep_timing_notes.md`, `docs/size_model_check.md`.
* The repository audit (hard-coded numbers, unlabelled synthetic output, rule gaps, tracked files): `docs/audit.md`.

## Limitations

* **Single machine and local network.** There is no real round-trip time, loss or congestion. Timing features are lab timings and
  do not transfer to real networks.
* **Scripted workloads.** Benign traffic is two scripted client behaviours. The "attacks" are scripted attack-like workloads
  (handshake floods, slow sends), not real attacks, so true-positive rates are not informative about real intrusions.
* **One cipher suite.** Profiles differ only in key exchange, signature algorithm and certificate-chain length.
* **TLS 1.3 over TCP only.** QUIC is not covered, so the QUIC amplification part of the size model is not tested against captures.
* **SLH-DSA cannot be negotiated** in TLS 1.3 by OpenSSL 3.5.9 (details in `docs/lab_findings.md`); it is not in the capture matrix.
* **The CANON context estimator needs labelled contexts** for training and is exact here only because the lab is deterministic
  (the first packets of a handshake identify the profile). A real network would not be this clean.
* **Replication is thin.** Results come from the main run plus a replicate run of four profiles; the profiles are doses, not
  independent samples, and one reference run is shared by all comparisons.
* **Flow-level confidence intervals understate capture-to-capture variability.** They resample flows within a capture and ignore
  pcap-level variation; the pcap-level table in `docs/stats_notes.md` shows where this matters.
* **Time-blocked splits inside one pcap**, so train and test come from the same capture session.
* **Cache files are pickles.** The loaders cache parsed datasets under `data/cache/` as pickle files; only load a cache you
  created yourself, since unpickling untrusted data can execute code.
* The size model's constants are defaults marked VERIFY; the post-hoc CANON-A2 and the split-conformal variant are exploratory
  additions and are labelled as such.
