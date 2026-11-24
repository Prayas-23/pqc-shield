# Web UI (read-only)

`web/` is a Vite + React + TypeScript application for the stored lab results. It reads **only** from the read-only API on
`127.0.0.1:8000` through the Vite dev/preview proxy (`/api`, HTTP and WebSocket). No control starts a capture, runs a command or
writes a file. No number is hard-coded in the UI: every value, the design point and the bootstrap level included, comes from the API
(`/api/meta` gives `design_fpr` and `ci_level`).

```
make api      # terminal 1: the API on 127.0.0.1:8000
make web      # terminal 2: the UI on http://localhost:5173
cd web && npm run build      # type-check (tsc --noEmit) and production build
cd web && npm test           # vitest: data mappers and number formatting (SYNTHETIC fixtures)
```

## Shell

A full-window application (the page itself never scrolls). **Top bar:** project name, data-source chip ("real lab captures", or a
SYNTHETIC warning), results commit. **Left rail:** the five views as tabs; keys **1-5** switch views (ignored while a field has focus).
**Workspace:** one view at a time, with a title strip and a collapsible **help** panel (closed by default; the explanatory prose lives
there, with one short sentence above each chart). **Control panel** docked on the right for that view's selectors. **Status bar:** API
connection state, `served_by` commit, results commit (hover for the commit of each source file; "mixed" when they differ), caveats link.
Every view ends with a footer naming its source files. Where the API gives no interval the UI says `n/a`.

Visual style: deep charcoal-blue with three layered surface tones, thin luminous borders and a faint grid and noise texture. Colour
carries meaning: amber = shifted / PQ, teal = normal / corrected, red-orange = alerts only (colour-blind safe). Serif titles, monospace
for all numbers and identifiers, large monospace key figures with units. Motion is 150-250 ms and informative only (the ladder animation,
row flashes on arrival, the pulsing replay dot, the curve draw-in); `prefers-reduced-motion` turns all of it off. Loading shows skeleton
shapes shaped like the content, errors and empty states are designed boxes. No purple, glass blur or rainbow gradients.

## Views (`#ladder`, `#drift`, `#detectors`, `#replay`, `#caveats`)

1. **Handshake ladder** (`/api/ladder`): the sequence diagram fills the workspace; arrow thickness is proportional to bytes and packets travel along each arrow (plays on selection and with the replay button); a compact model-vs-observed table and the table
   against the classical reference sit beside it; the measured-certificate-overhead toggle is in the control panel.
2. **Feature drift** (`/api/drift`): profiles on the rows, features on the columns (short labels, full name on hover), coloured by
   effect size; cells within the permutation noise floor are grey. Click a cell for its numbers (in the control panel). In the
   handshake view the rows are model terms. The matrix fits the window at 1280x800, also for the 32 application features.
3. **Detectors and mix** (`/api/detectors`, `/api/pqmix`): a dot plot (one row per profile, one marker per method, CI whiskers, the
   shaded design band, sorted by the naive detector's rate; a second tab shows the capture-to-capture table), and the PQ-share slider with
   an animated mixed-traffic curve with a draggable marker and a live readout of both methods, labelled "computed from measured per-profile FPR, not a simulation".
4. **Replay** (`/api/stream`, two sockets), the hero view: naive and CANON-B panes with a large false-alarm counter, a rolling alert-rate sparkline, score-versus-threshold bars on each row, rows that flash on arrival and stay tinted when alerting, a dense scrolling table (index, workload,
   class, score, threshold, decision) and a speed control, under a "Replay of recorded lab captures, not live traffic" banner.
   `?autostart=1` starts a replay on load.
5. **Caveats**: the list from `/api/meta`.

At phone width the rail becomes a tab strip, the controls dock above the workspace and the panes stack; the page still does not
scroll, the workspace scrolls inside itself (the drift matrix scrolls sideways).

## Screenshots

`docs/screens/` is produced by `scripts/screenshots.py` (API and UI must be running): each view at 1280x800 and at 390x844, plus the
ladder with the overhead toggle, the drift view on the 32 application features and the detectors view with help open. The script also
prints which boxes have content larger than their box (clipping or inner scroll).

## Deviations from the brief

* **Playwright was not used.** It is not on the approved dependency list, so the script drives the installed Chrome over the
  DevTools protocol with the `websockets` package that is already a dependency.
* **vitest is pinned to 3.x.** vitest 4 does not start on Node 22.11 (it needs 22.12 or newer).
* `recharts` is no longer used (the charts are CSS and SVG) and was removed. The API gained three read-only additions for the UI: `classical_profile`, `design_fpr` and `ci_level` in `/api/meta`, and a
  `cert_overhead=measured` option on `/api/ladder`.
