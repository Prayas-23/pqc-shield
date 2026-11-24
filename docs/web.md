# Web UI (read-only)

`web/` is a Vite + React + TypeScript viewer for the stored lab results. It reads **only** from the read-only API on
`127.0.0.1:8000` through the Vite dev/preview proxy (`/api`, HTTP and WebSocket). No control starts a capture, runs a command or
writes a file. No number is hard-coded in the UI: every value, the 5 % design point and the bootstrap level included, comes from
the API (`/api/meta` gives `design_fpr` and `ci_level`).

```
make api      # terminal 1: the API on 127.0.0.1:8000
make web      # terminal 2: the UI on http://localhost:5173
cd web && npm run build      # type-check (tsc --noEmit) and production build
cd web && npm test           # vitest: data mappers and number formatting (SYNTHETIC fixtures)
```

## Screens (`#ladder`, `#drift`, `#detectors`, `#replay`, `#caveats`)

1. **Handshake sizes**: client/server sequence diagram from `/api/ladder` (bytes and packets per message), model-vs-observed table, the
   same table against the classical reference profile, and a toggle for the per-certificate overhead measured on the lab's
   certificate files.
2. **Feature drift**: features x profiles heatmap from `/api/drift` (workload, view and effect-size selectors). Cells within the
   permutation noise floor are grey; click a cell for its numbers.
3. **Detectors and mixed traffic**: FPR per profile for naive, V_APP, CANON-B and oracle with bootstrap CIs and the design line, the
   capture-to-capture table for the replicated profiles, and the PQ-share slider from `/api/pqmix` (labelled as computed from
   measured per-profile FPRs, not a simulation).
4. **Replay**: two `/api/stream` sockets (naive and CANON-B) over the same recorded flows, with running false-alarm and detection
   counters and a speed control. Labelled as a replay of recorded captures, not live traffic. `?autostart=1` starts it on load.

Every figure has a source footer (files, the commit that produced the results, the commit serving them). Where the API gives no
interval the UI says `n/a`.

## Screenshots

`docs/screens/` is produced by `scripts/screenshots.py` (API and UI must be running): each screen at 1280x800 (viewport) and full
height, and at phone width (390x844 viewport and full height), plus the ladder with the certificate-overhead toggle on.

## Deviations from the brief

* **Playwright was not used.** It is not on the approved dependency list, so the script drives the installed Chrome over the
  DevTools protocol with the `websockets` package that is already a dependency.
* **vitest is pinned to 3.x.** vitest 4 does not start on Node 22.11 (it needs 22.12 or newer).
* The API gained three read-only additions for the UI: `classical_profile`, `design_fpr` and `ci_level` in `/api/meta`, and a
  `cert_overhead=measured` option on `/api/ladder`.
