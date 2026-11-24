# PQ-DRIFTLAB — Agent Rules

PQ-DRIFTLAB is a research prototype built by two B.Tech CSE students. It measures how post-quantum handshakes (ML-KEM, ML-DSA, SLH-DSA over TLS 1.3 / QUIC) shift network-flow features and break ML intrusion detectors, and it includes a correction method called CANON.

## Rules for the whole project

1. Python 3.11+, FastAPI, React + Vite + TypeScript. Free tools only.
2. Never hard-code, estimate, or "expect" experiment results. Every number must be computed by code we can re-run. If something can't run, say so plainly.
3. Anything synthetic must be labelled SYNTHETIC in code, filenames, API responses and UI.
4. Defensive only: no exploit code, no scanning external hosts, no decrypting traffic, attack traffic only between our own local containers.
5. Write pytest tests for every maths function. Fixed random seeds everywhere.
6. Never merge different datasets into one training set. Every row carries a `source` column, and splits must not mix sources unless the user explicitly asks for that experiment.
7. After each task, print: files changed, how to run it, how to run its tests, known gaps.
8. Keep functions small and typed. No new dependencies without asking.
9. No code, script, image or config changes, and no test or other CPU-heavy runs, while a capture run is in progress
   (`lab/.run.lock` exists or `lab/run.log` is still growing). Edits can break the running scripts (the matrix driver
   imports `pqdl.pcap` after every pcap), and CPU load adds noise to timing features such as `flow_duration`. Wait for
   the run to finish. If asked to change code during a run, say so and defer it; read-only checks of the log and manifest
   are fine.
