// Shapes of the read-only API responses (docs/api.md). Nothing here is data; all values come from the API.

export interface SidecarMeta { code_commit: string; generated_at: string; script: string }

export interface Provenance {
  data_source: string;
  synthetic: boolean;
  results_code_commit: string;
  served_by_commit: string;
  results_files: Record<string, SidecarMeta | null>;
  generated_at: string | null;
  source_files: string[];
}

export interface Meta {
  provenance: Provenance;
  version: string;
  served_by_commit: string;
  profiles: string[];
  methods: { baseline: string[]; canon: string[]; stream: string[] };
  detectors: string[];
  caveats: string[];
  classical_profile: string;
  design_fpr: number;
  ci_level: number;
}

export interface LadderStep { step: string; direction: "C->S" | "S->C"; bytes: number; packets: number }
export interface Comparison { observed: number; model: number; difference: number; difference_pct_of_observed: number | null }
export interface Ladder {
  provenance: Provenance;
  profile: string;
  mss: number;
  model: { ladder: LadderStep[]; B_S: number; B_C: number; cert_overhead: string; o_cert_bytes: number; note: string };
  observed: { n_flows: number; hs_s2c_bytes_median: number; hs_c2s_bytes_median: number };
  comparison: { server_to_client_bytes: Comparison; client_to_server_bytes: Comparison };
}

export interface DriftRow {
  test: string; workload: string; view: string; feature: string;
  ref_group: string | null; compared_group: string | null; term: string | null; design: string | null;
  eta2: number | null; partial_eta2: number | null; psi: number | null; mmd2: number | null; mmd2_p_value: number | null;
  noise95_eta2: number | null; noise95_max_psi: number | null; n_ref: number | null; n_group: number | null;
  deterministic: boolean | null; note: string | null;
}
export interface DriftResponse { provenance: Provenance; n_rows: number; rows: DriftRow[]; note: string }

export interface Metric { value: number | null; ci_lo: number | null; ci_hi: number | null; seed_sd: number | null }
export interface PcapLevel {
  n_capture_sets: number; mean_fpr: number; sd_across_pcaps: number; min: number; max: number;
  flow_ci_understates: boolean; note: string;
}
export interface DetectorRecord {
  dataset: string; detector: string; method: string; profile: string; n_benign: number; n_attack: number;
  metrics: Record<string, Metric>; pcap_level: PcapLevel | null;
}
export interface DetectorsResponse { provenance: Provenance; n_records: number; records: DetectorRecord[] }

export interface MixMethod {
  method_name: string; fpr_profile: number; fpr_profile_ci: [number, number];
  fpr_classical: number; fpr_classical_ci: [number, number]; fpr_mix: number;
}
export interface MixResponse {
  provenance: Provenance; pi: number; detector: string; profile: string; classical_profile: string;
  formula: string; simulation: boolean; methods: Record<string, MixMethod>;
}

export interface StreamHello { type: "hello"; replay: boolean; notice: string; n_flows: number; provenance: Provenance }
export interface StreamFlow {
  type: "flow"; replay: boolean; index: number; recorded_offset_s: number; workload: string; label: "benign" | "attack";
  score: number; threshold: number; alert: boolean; flow_s2c_bytes: number; flow_c2s_bytes: number;
}
export interface StreamDone { type: "done"; replay: boolean; n_flows: number; alerts: number; notice: string }
export type StreamMessage = StreamHello | StreamFlow | StreamDone;
