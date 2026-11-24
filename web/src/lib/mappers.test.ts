// SYNTHETIC fixtures only: the numbers below are invented to check the arithmetic of the mappers, never quoted anywhere.
import { describe, expect, it } from "vitest";
import {
  caveatTags, cellKey, driftMatrix, fprBars, heatSummary, labelRow, intensity, ladderDelta, metricsForView, mixLines, parseProfile,
  profileOptions, rate, replayCounters, sequenceSteps,
} from "./mappers";
import { fmtBytes, fmtInt, fmtPct, fmtSigned, shortSha } from "./format";
import type { DetectorRecord, DriftRow, Ladder, MixResponse, StreamFlow } from "./types";

const prov = { data_source: "SYNTHETIC_TEST_FIXTURE", synthetic: true, results_code_commit: "x", served_by_commit: "y", results_files: {}, generated_at: null, source_files: [] };
const cmp = (observed: number, model: number) => ({ observed, model, difference: observed - model, difference_pct_of_observed: null });
const ladder = (s2c: [number, number], c2s: [number, number]): Ladder => ({
  provenance: prov, profile: "a|b|c", mss: 1448,
  model: { ladder: [{ step: "ClientHello", direction: "C->S", bytes: 100, packets: 1 }, { step: "ServerHello", direction: "S->C", bytes: 400, packets: 1 }],
           B_S: s2c[1], B_C: c2s[1], cert_overhead: "default", o_cert_bytes: 40, note: "" },
  observed: { n_flows: 10, hs_s2c_bytes_median: s2c[0], hs_c2s_bytes_median: c2s[0] },
  comparison: { server_to_client_bytes: cmp(...s2c), client_to_server_bytes: cmp(...c2s) },
});

describe("profiles", () => {
  it("parses and lists options in API order", () => {
    expect(parseProfile("k|a|c")).toEqual({ kem: "k", auth: "a", chain: "c" });
    expect(() => parseProfile("k|a")).toThrow();
    expect(profileOptions(["k1|a1|c1", "k2|a1|c2", "k1|a2|c1"])).toEqual({ kems: ["k1", "k2"], auths: ["a1", "a2"], chains: ["c1", "c2"] });
  });
});

describe("ladder", () => {
  it("scales message shares to the largest message", () => {
    const s = sequenceSteps(ladder([100, 90], [10, 8]));
    expect(s.map((x) => x.share)).toEqual([0.25, 1]);
  });
  it("computes observed and model deltas against the reference and their residual", () => {
    const d = ladderDelta(ladder([15000, 14000], [1400, 1450]), ladder([1400, 600], [270, 290]));
    expect(d[0]).toEqual({ direction: "server to client", observed: 13600, model: 13400, residual: 200 });
    expect(d[1]).toEqual({ direction: "client to server", observed: 1130, model: 1160, residual: -30 });
  });
});

const row = (o: Partial<DriftRow>): DriftRow => ({
  test: "t", workload: "w", view: "flow", feature: "f1", ref_group: "ref", compared_group: "p1", term: null, design: null,
  eta2: null, partial_eta2: null, psi: null, mmd2: null, mmd2_p_value: null, noise95_eta2: null, noise95_max_psi: null,
  n_ref: null, n_group: null, deterministic: null, note: null, ...o,
});

describe("drift matrix", () => {
  const rows = [
    row({ feature: "f1", compared_group: "p1", psi: 4, noise95_max_psi: 0.2 }),
    row({ feature: "f1", compared_group: "p2", psi: 0.1, noise95_max_psi: 0.2 }),
    row({ feature: "f2", compared_group: "p1", psi: null, noise95_max_psi: null }),
    row({ feature: "f9", workload: "other", compared_group: "p1", psi: 99, noise95_max_psi: 1 }),
    row({ feature: "h1", view: "hs", term: "kem", partial_eta2: 0.9 }),
  ];
  it("marks cells above or within the noise floor and ignores other workloads", () => {
    const m = driftMatrix(rows, "w", "flow", "psi");
    expect(m.features).toEqual(["f1", "f2"]);
    expect(m.columns).toEqual(["p1", "p2"]);
    expect(m.vmax).toBe(4);
    expect(m.hasFloor).toBe(true);
    expect(m.cells.get(cellKey("f1", "p1"))?.above).toBe(true);
    expect(m.cells.get(cellKey("f1", "p2"))?.above).toBe(false);
    expect(m.cells.get(cellKey("f2", "p1"))?.above).toBeNull();
  });
  it("uses model terms as columns for the handshake view and has no floor", () => {
    const m = driftMatrix(rows, "w", "hs", "partial_eta2");
    expect(m.columns).toEqual(["kem"]);
    expect(m.hasFloor).toBe(false);
    expect(metricsForView("hs")).toEqual(["partial_eta2"]);
    expect(metricsForView("app")).toEqual(["psi", "eta2", "mmd2"]);
  });
  it("intensity is a bounded square root", () => {
    expect(intensity(4, 4)).toBe(1);
    expect(intensity(1, 4)).toBe(0.5);
    expect(intensity(null, 4)).toBe(0);
    expect(intensity(5, 0)).toBe(0);
  });
});

const rec = (profile: string, method: string, v: number | null, lo: number | null, hi: number | null): DetectorRecord => ({
  dataset: "main", detector: "rf", method, profile, n_benign: 240, n_attack: 100,
  metrics: { fpr: { value: v, ci_lo: lo, ci_hi: hi, seed_sd: 0 } }, pcap_level: null,
});

describe("detector bars", () => {
  it("builds error lengths and sorts by the chosen method", () => {
    const rows = fprBars([rec("p1", "naive", 0.9, 0.85, 0.95), rec("p2", "naive", 0.1, 0.05, 0.2), rec("p1", "oracle", 0.04, 0.03, 0.06), rec("p1", "other", 0.5, 0.4, 0.6)], ["naive", "oracle"], "naive");
    expect(rows.map((r) => r.profile)).toEqual(["p2", "p1"]);
    expect(rows[1]!["naive_err"]).toEqual([0.9 - 0.85, 0.95 - 0.9]);
    expect(rows[0]!["oracle"]).toBeUndefined();
    expect(rows[1]!["other"]).toBeUndefined();
  });
  it("keeps a missing interval as null so the figure can print n/a", () => {
    const rows = fprBars([rec("p1", "naive", 0.9, null, null)], ["naive"], "naive");
    expect(rows[0]!["naive_err"]).toBeNull();
  });
});

describe("pq mix", () => {
  it("makes end points from measured FPRs and marks the API mixed value", () => {
    const resp: MixResponse = {
      provenance: prov, pi: 0.25, detector: "rf", profile: "p", classical_profile: "c", formula: "f", simulation: false,
      methods: { naive: { method_name: "naive", fpr_profile: 0.9, fpr_profile_ci: [0.8, 1], fpr_classical: 0.02, fpr_classical_ci: [0.01, 0.03], fpr_mix: 0.24 } },
    };
    const { lines, marks } = mixLines(resp);
    expect(lines[0]).toMatchObject({ pi: 0, naive: 0.02 });
    expect(lines[1]).toMatchObject({ pi: 1, naive: 0.9 });
    expect(marks).toEqual([{ label: "naive", pi: 0.25, fpr: 0.24 }]);
  });
});

describe("replay and formatting", () => {
  const f = (label: "benign" | "attack", alert: boolean): StreamFlow => ({ type: "flow", replay: true, index: 0, recorded_offset_s: 0, workload: "w", label, score: 0, threshold: 0, alert, flow_s2c_bytes: 0, flow_c2s_bytes: 0 });
  it("counts false alarms on benign and detections on attack", () => {
    const c = replayCounters([f("benign", true), f("benign", false), f("attack", true), f("attack", false), f("attack", true)]);
    expect(c).toEqual({ benign: 2, attack: 3, falseAlarms: 1, detections: 2 });
    expect(rate(c.falseAlarms, c.benign)).toBe(0.5);
    expect(rate(1, 0)).toBeNull();
  });
  it("formats units and n/a", () => {
    expect(fmtBytes(15976)).toBe("15,976 B");
    expect(fmtBytes(null)).toBe("n/a");
    expect(fmtInt(NaN)).toBe("n/a");
    expect(fmtSigned(-52, " B")).toBe("−52 B");
    expect(fmtSigned(813, " B")).toBe("+813 B");
    expect(fmtPct(0.058333)).toBe("5.8 %");
    expect(shortSha("b3b644cc1f4b51d0db98fb3a4e32bcb083b06f3b")).toBe("b3b644cc");
    expect(shortSha("unknown (generated before tracking)")).toBe("unknown (generated before tracking)");
  });
  it("takes header words from the caveats", () => {
    expect(caveatTags(["Single machine: all captures", "One cipher suite (TLS_X); more"], 2)).toEqual(["Single machine", "One cipher suite"]);
  });
});

describe("heat summary", () => {
  it("counts cells above, within and without a value, and names the weakest feature", () => {
    const rows = [
      row({ feature: "f1", compared_group: "p1", psi: 4, noise95_max_psi: 0.2 }),
      row({ feature: "f1", compared_group: "p2", psi: 5, noise95_max_psi: 0.2 }),
      row({ feature: "f2", compared_group: "p1", psi: 0.1, noise95_max_psi: 0.2 }),
      row({ feature: "f2", compared_group: "p2", psi: 6, noise95_max_psi: 0.2 }),
      row({ feature: "f3", compared_group: "p1", psi: null, noise95_max_psi: null }),
    ];
    const s = heatSummary(driftMatrix(rows, "w", "flow", "psi"));
    expect(s).toEqual({ total: 5, above: 3, within: 1, na: 1, weakest: { feature: "f2", above: 1, n: 2 } });
    expect(heatSummary(driftMatrix([row({ view: "hs", term: "kem", partial_eta2: 1 })], "w", "hs", "partial_eta2")).weakest).toBeNull();
  });
});

describe("label row", () => {
  it("picks the first row in which every method has a bar", () => {
    const rows = fprBars([rec("p1", "naive", 0, 0, 0), rec("p1", "oracle", 0.02, 0.01, 0.03), rec("p2", "naive", 0.4, 0.3, 0.5), rec("p2", "oracle", 0.03, 0.02, 0.04)], ["naive", "oracle"], "naive");
    expect(labelRow(rows, ["naive", "oracle"])).toBe(1);
    expect(labelRow(rows.slice(0, 1), ["naive", "oracle"])).toBe(0);
    expect(labelRow([], ["naive"])).toBe(0);
  });
});
