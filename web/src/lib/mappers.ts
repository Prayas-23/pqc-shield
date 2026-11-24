// Pure mappers from API responses to what the figures draw. No data lives here; the tests use SYNTHETIC fixtures.
import type { DetectorRecord, DriftRow, Ladder, MixResponse, StreamFlow } from "./types";

export interface ProfileParts { kem: string; auth: string; chain: string }

export function parseProfile(p: string): ProfileParts {
  const [kem, auth, chain] = p.split("|");
  if (!kem || !auth || !chain) throw new Error(`not a profile string: ${p}`);
  return { kem, auth, chain };
}

export const profileString = (x: ProfileParts): string => `${x.kem}|${x.auth}|${x.chain}`;

/** Distinct kem / auth / chain values, in the order the API lists the profiles. */
export function profileOptions(profiles: string[]): { kems: string[]; auths: string[]; chains: string[] } {
  const uniq = (xs: string[]) => [...new Set(xs)];
  const parts = profiles.map(parseProfile);
  return { kems: uniq(parts.map((x) => x.kem)), auths: uniq(parts.map((x) => x.auth)), chains: uniq(parts.map((x) => x.chain)) };
}

// ------------------------------------------------------------------ ladder
export interface SequenceStep { step: string; direction: "C->S" | "S->C"; bytes: number; packets: number; share: number }

/** Ladder steps with each message's share of the largest message (for the bar under the arrow). */
export function sequenceSteps(l: Ladder): SequenceStep[] {
  const max = Math.max(...l.model.ladder.map((s) => s.bytes), 1);
  return l.model.ladder.map((s) => ({ ...s, share: s.bytes / max }));
}

export interface DeltaRow { direction: string; observed: number; model: number; residual: number }

/** Profile minus reference, observed and modelled, per direction. residual = observed delta - model delta. */
export function ladderDelta(p: Ladder, ref: Ladder): DeltaRow[] {
  const one = (direction: string, a: { observed: number; model: number }, b: { observed: number; model: number }): DeltaRow => {
    const observed = a.observed - b.observed, model = a.model - b.model;
    return { direction, observed, model, residual: observed - model };
  };
  return [
    one("server to client", p.comparison.server_to_client_bytes, ref.comparison.server_to_client_bytes),
    one("client to server", p.comparison.client_to_server_bytes, ref.comparison.client_to_server_bytes),
  ];
}

// ------------------------------------------------------------------ drift heatmap
export type DriftMetric = "psi" | "eta2" | "mmd2" | "partial_eta2";

export function metricsForView(view: string): DriftMetric[] {
  return view === "hs" ? ["partial_eta2"] : ["psi", "eta2", "mmd2"];
}

export interface HeatCell { feature: string; column: string; value: number | null; floor: number | null; above: boolean | null; row: DriftRow }
export interface HeatMatrix { features: string[]; columns: string[]; cells: Map<string, HeatCell>; vmax: number; hasFloor: boolean }

const floorOf = (r: DriftRow, m: DriftMetric): number | null =>
  m === "psi" ? r.noise95_max_psi : m === "eta2" ? r.noise95_eta2 : null;

export const cellKey = (feature: string, column: string): string => `${feature}\u0000${column}`;

/** Features x (profiles | model terms) for one workload and view. Cells are above the permutation noise floor or not. */
export function driftMatrix(rows: DriftRow[], workload: string, view: string, metric: DriftMetric): HeatMatrix {
  const sel = rows.filter((r) => r.workload === workload && r.view === view);
  const features: string[] = [], columns: string[] = [];
  const cells = new Map<string, HeatCell>();
  let vmax = 0, hasFloor = false;
  for (const r of sel) {
    const column = (view === "hs" ? r.term : r.compared_group) ?? "n/a";
    if (!features.includes(r.feature)) features.push(r.feature);
    if (!columns.includes(column)) columns.push(column);
    const value = r[metric], floor = floorOf(r, metric);
    if (floor !== null) hasFloor = true;
    if (value !== null && Number.isFinite(value)) vmax = Math.max(vmax, value);
    cells.set(cellKey(r.feature, column), { feature: r.feature, column, value, floor, above: value !== null && floor !== null ? value > floor : null, row: r });
  }
  return { features, columns, cells, vmax, hasFloor };
}

/** 0..1 colour intensity: square root of value / largest value in the matrix. */
export const intensity = (value: number | null, vmax: number): number =>
  value === null || !(vmax > 0) ? 0 : Math.sqrt(Math.min(Math.max(value / vmax, 0), 1));

// ------------------------------------------------------------------ detectors
export type BarRow = { profile: string } & Record<string, number | string | [number, number] | null>;

/** One row per profile; per method its FPR and the two error lengths (value - lo, hi - value). Sorted by `sortMethod`. */
export function fprBars(records: DetectorRecord[], methods: string[], sortMethod: string): BarRow[] {
  const byProfile = new Map<string, BarRow>();
  for (const r of records) {
    if (!methods.includes(r.method)) continue;
    const m = r.metrics["fpr"];
    if (!m) continue;
    const row = byProfile.get(r.profile) ?? ({ profile: r.profile } as BarRow);
    row[r.method] = m.value;
    row[`${r.method}_err`] = m.value !== null && m.ci_lo !== null && m.ci_hi !== null ? [m.value - m.ci_lo, m.ci_hi - m.value] : null;
    row[`${r.method}_n`] = r.n_benign;
    byProfile.set(r.profile, row);
  }
  const val = (x: BarRow) => (typeof x[sortMethod] === "number" ? (x[sortMethod] as number) : -1);
  return [...byProfile.values()].sort((a, b) => val(a) - val(b) || a.profile.localeCompare(b.profile));
}

// ------------------------------------------------------------------ pq mix
export interface MixPoint { pi: number; [k: string]: number | [number, number] }

/** Two end points per method (all classical, all PQ) from the measured FPRs, and the API's mixed value at the slider. */
export function mixLines(resp: MixResponse): { lines: MixPoint[]; marks: { label: string; pi: number; fpr: number }[] } {
  const a: MixPoint = { pi: 0 }, b: MixPoint = { pi: 1 };
  const marks: { label: string; pi: number; fpr: number }[] = [];
  for (const [label, m] of Object.entries(resp.methods)) {
    a[label] = m.fpr_classical;
    a[`${label}_err`] = [m.fpr_classical - m.fpr_classical_ci[0], m.fpr_classical_ci[1] - m.fpr_classical];
    b[label] = m.fpr_profile;
    b[`${label}_err`] = [m.fpr_profile - m.fpr_profile_ci[0], m.fpr_profile_ci[1] - m.fpr_profile];
    marks.push({ label, pi: resp.pi, fpr: m.fpr_mix });
  }
  return { lines: [a, b], marks };
}

// ------------------------------------------------------------------ replay
export interface Counters { benign: number; attack: number; falseAlarms: number; detections: number }

export function replayCounters(flows: StreamFlow[]): Counters {
  const c: Counters = { benign: 0, attack: 0, falseAlarms: 0, detections: 0 };
  for (const f of flows) {
    if (f.label === "benign") { c.benign += 1; if (f.alert) c.falseAlarms += 1; }
    else { c.attack += 1; if (f.alert) c.detections += 1; }
  }
  return c;
}

export const rate = (num: number, den: number): number | null => (den > 0 ? num / den : null);

/** Short header words from the API caveats: the text before the first colon or bracket. */
export function caveatTags(caveats: string[], n: number): string[] {
  return caveats.slice(0, n).map((c) => c.split(/[:(]/)[0]!.trim());
}

// ------------------------------------------------------------------ heatmap annotation
export interface HeatSummary { total: number; above: number; within: number; na: number; weakest: { feature: string; above: number; n: number } | null }

/** Counts of cells above / within the noise floor / without a value, and the feature with the fewest cells above it. */
export function heatSummary(m: HeatMatrix): HeatSummary {
  let above = 0, within = 0, na = 0;
  const perFeature = new Map<string, { above: number; n: number }>();
  for (const c of m.cells.values()) {
    if (c.value === null) { na += 1; continue; }
    const f = perFeature.get(c.feature) ?? { above: 0, n: 0 };
    f.n += 1;
    if (c.above === true) { above += 1; f.above += 1; } else if (c.above === false) within += 1;
    perFeature.set(c.feature, f);
  }
  let weakest: HeatSummary["weakest"] = null;
  if (m.hasFloor) for (const [feature, f] of perFeature) if (weakest === null || f.above < weakest.above) weakest = { feature, ...f };
  return { total: m.cells.size, above, within, na, weakest };
}

/** Index of the first row where every method has a value above zero (zero-length bars cannot carry a label); else the last row. */
export function labelRow(rows: BarRow[], keys: string[]): number {
  const i = rows.findIndex((r) => keys.every((k) => typeof r[k] === "number" && (r[k] as number) > 0));
  return i >= 0 ? i : Math.max(rows.length - 1, 0);
}

// ------------------------------------------------------------------ short labels (full names stay in the hover text)
/** "X25519MLKEM768|mldsa65|leaf_int" -> "X25519+MLKEM768 / MLDSA65 / leaf_int". */
export function shortProfile(p: string): string {
  const { kem, auth, chain } = parseProfile(p);
  const k = kem.replace(/^x25519mlkem/i, "X25519+MLKEM").replace(/^mlkem/i, "MLKEM").replace(/^x25519$/i, "X25519");
  return `${k} / ${auth.toUpperCase().replace(/_/g, "-")} / ${chain}`;
}

/** "flow_c2s_bytes" -> "c2s_bytes": the view prefix is already named by the selector. */
export const shortFeature = (f: string): string => f.replace(/^(flow|app|hs)_/, "");

// ------------------------------------------------------------------ visual scales (drawing helpers, not data)
/** Arrow thickness in px for a message of `bytes`: linear in bytes, so a large flight visibly dwarfs a small one. */
export const arrowThickness = (bytes: number): number => Math.min(1.5 + Math.max(bytes, 0) / 1000, 16);

/** Mixed rate for a PQ share `pi`: pi * FPR(PQ profile) + (1 - pi) * FPR(classical). Same formula the API states. */
export const mixAt = (pi: number, fprProfile: number, fprClassical: number): number => pi * fprProfile + (1 - pi) * fprClassical;

/** Rolling alert rate over the flows, oldest first. `newestFirst` is the feed order; the window is in flows. */
export function rollingAlertRate(newestFirst: StreamFlow[], window: number, maxPoints: number): number[] {
  const flows = newestFirst.slice(0, maxPoints + window).reverse();
  const out: number[] = [];
  for (let i = 0; i < flows.length; i++) {
    const w = flows.slice(Math.max(0, i - window + 1), i + 1);
    out.push(w.filter((f) => f.alert).length / w.length);
  }
  return out.slice(-maxPoints);
}

/** Upper end of the score bars: the largest score or threshold seen, so the threshold tick stays on the track. */
export function barScale(flows: StreamFlow[]): number {
  let m = 0;
  for (const f of flows) m = Math.max(m, f.score, f.threshold);
  return m > 0 ? m : 1;
}
