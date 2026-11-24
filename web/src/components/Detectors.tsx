import { useEffect, useMemo, useState } from "react";
import { Bar, BarChart, CartesianGrid, ErrorBar, LabelList, Line, LineChart, ReferenceDot, ReferenceLine, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { useApi } from "../lib/api";
import type { DetectorsResponse, Meta, MixResponse } from "../lib/types";
import { fprBars, labelRow, mixLines } from "../lib/mappers";
import type { BarRow } from "../lib/mappers";
import { fmtNum, fmtPct } from "../lib/format";
import { Section, Select, Source, Status } from "./Common";

// method name in the results files -> label drawn on the figure, and its ink. The signal colour marks the shifted state.
const SERIES = [
  { key: "naive", label: "naive", fill: "#d55e00", ink: "#d55e00" },
  { key: "naive_app", label: "V_APP", fill: "#d2cfc4", ink: "#8a887f" },
  { key: "canon_bs_k120_true", label: "CANON-B", fill: "#1d1d1b", ink: "#1d1d1b" },
  { key: "oracle", label: "oracle", fill: "#8a887f", ink: "#5f5d56" },
] as const;
const MIX_SERIES = [
  { key: "naive", label: "naive", ink: "#d55e00" },
  { key: "V_APP", label: "V_APP", ink: "#8a887f" },
  { key: "CANON-B split k=120", label: "CANON-B", ink: "#1d1d1b" },
] as const;

type LP = { x?: number | string; y?: number | string; width?: number | string; height?: number | string; index?: number };

const barEndLabel = (text: string, ink: string, last: number) => (p: LP) =>
  p.index === last ? (
    <text x={Number(p.x) + Number(p.width) + 5} y={Number(p.y) + Number(p.height) / 2} dy="0.34em" fontSize={11} fill={ink} fontFamily="var(--serif)" fontStyle="italic">{text}</text>
  ) : null;

function BarTip({ active, payload }: { active?: boolean; payload?: { payload: BarRow }[] }) {
  if (!active || !payload?.length) return null;
  const row = payload[0]!.payload;
  return (
    <div className="tip">
      <div>{row.profile}</div>
      {SERIES.map((s) => {
        const v = row[s.key], e = row[`${s.key}_err`];
        if (typeof v !== "number") return null;
        const ci = Array.isArray(e) ? `[${fmtPct(v - e[0])}, ${fmtPct(v + e[1])}]` : "CI n/a";
        return <div key={s.key}>{s.label}: <b>{fmtPct(v)}</b> {ci}</div>;
      })}
    </div>
  );
}

export function DetectorsScreen({ meta }: { meta: Meta }) {
  const [detector, setDetector] = useState(meta.detectors.includes("rf") ? "rf" : meta.detectors[0]!);
  const det = useApi<DetectorsResponse>(`/api/detectors?detector=${detector}&dataset=main&limit=10000`);
  const bars = useMemo(() => (det.data ? fprBars(det.data.records, SERIES.map((s) => s.key), "naive") : []), [det.data]);
  const design = meta.design_fpr;
  const lab = labelRow(bars, SERIES.map((s) => s.key));
  const ci = fmtPct(meta.ci_level, 0);
  const narrow = typeof window !== "undefined" && window.innerWidth < 700;
  const pcap = (det.data?.records ?? []).filter((r) => r.pcap_level && SERIES.some((s) => s.key === r.method));

  // ---- pq mix
  const pqProfiles = meta.profiles.filter((p) => p !== meta.classical_profile);
  const [profile, setProfile] = useState(pqProfiles[0] ?? meta.classical_profile);
  const [share, setShare] = useState(50);
  const [applied, setApplied] = useState(50);
  useEffect(() => { const t = setTimeout(() => setApplied(share), 150); return () => clearTimeout(t); }, [share]);
  const mix = useApi<MixResponse>(`/api/pqmix?pi=${applied / 100}&detector=${detector}&profile=${encodeURIComponent(profile)}`);
  const { lines, marks } = useMemo(() => (mix.data ? mixLines(mix.data) : { lines: [], marks: [] }), [mix.data]);
  const mixMethods = mix.data ? mix.data.methods : {};

  return (
    <Section id="detectors" no={3} title="Detector false alarms and mixed traffic"
      lede={`False-positive rate of each detector on benign test flows of each profile. Each detector is set to flag ${fmtPct(design, 0)} of benign flows in its training domain; the figure shows what it does on the other profiles.`}>
      <div className="controls">
        <Select label="detector" value={detector} options={meta.detectors} onChange={setDetector} />
      </div>
      <Status loading={det.loading} error={det.error} what="/api/detectors" />
      {bars.length > 0 ? (
        <div className="fig">
          <div className="chart">
            <ResponsiveContainer width="100%" height={bars.length * 68 + 80}>
              <BarChart layout="vertical" data={bars} margin={{ top: 22, right: 64, left: 4, bottom: 30 }} barGap={2} barCategoryGap="14%">
                <CartesianGrid horizontal={false} />
                <XAxis type="number" domain={[0, 1]} tickFormatter={(v: number) => String(Math.round(v * 100))}
                  label={{ value: "false-positive rate on benign test flows, %", position: "insideBottom", offset: -18, fontSize: 11 }} />
                <YAxis type="category" dataKey="profile" width={narrow ? 132 : 246} tick={{ fontSize: 10 }} interval={0} />
                <Tooltip content={<BarTip />} cursor={{ fill: "var(--wash)", fillOpacity: 0.6 }} />
                <ReferenceLine x={design} stroke="#1d1d1b" strokeDasharray="3 3" label={{ value: `design point ${fmtPct(design, 0)}`, position: "top", fontSize: 11, fill: "#1d1d1b" }} />
                {SERIES.map((s) => (
                  <Bar key={s.key} dataKey={s.key} fill={s.fill} stroke={s.ink} strokeWidth={0.5} barSize={10} isAnimationActive={false}>
                    <ErrorBar dataKey={`${s.key}_err`} direction="x" width={3} stroke={s.ink} strokeWidth={1} />
                    <LabelList dataKey={s.key} content={barEndLabel(s.label, s.ink, lab) as never} />
                  </Bar>
                ))}
              </BarChart>
            </ResponsiveContainer>
          </div>
          <div className="margin">
            <p><b>Read this first.</b> The dashed line is the false-positive rate the detectors were set to (the design point). A bar far to its right means the detector raises alarms on ordinary benign traffic of that profile.</p>
            <p>Bars are the mean over model seeds; whiskers are {ci} flow-bootstrap intervals. Profiles are sorted by the naive detector's rate. <em>naive</em>: trained and thresholded on the classical profile only, on whole-connection flow features. <em>V_APP</em>: same, on application-phase features only. <em>CANON-B</em>: naive plus the k-shot, split-conformal correction. <em>oracle</em>: trained on the profile itself.</p>
            <p>The whiskers do not include capture-to-capture variation (table below).</p>
          </div>
        </div>
      ) : null}
      <Source prov={det.data?.provenance} />

      {pcap.length > 0 ? (
        <>
          <h3>Capture-to-capture variation, replicated profiles</h3>
          <div className="scroll-x">
            <table>
              <thead><tr><th>profile</th><th>method</th><th className="num">flow bootstrap, % ({ci} CI)</th><th className="num">across capture sets, % (mean ± SD)</th><th className="gap">flow CI</th></tr></thead>
              <tbody>
                {pcap.map((r) => {
                  const f = r.metrics["fpr"], p = r.pcap_level!;
                  return (
                    <tr key={r.profile + r.method}>
                      <td className="mono">{r.profile}</td><td style={{ whiteSpace: "nowrap" }}>{SERIES.find((s) => s.key === r.method)?.label}</td>
                      <td className="num">{fmtNum(f?.value != null ? f.value * 100 : null, 1)} ({fmtNum(f?.ci_lo != null ? f.ci_lo * 100 : null, 1)} to {fmtNum(f?.ci_hi != null ? f.ci_hi * 100 : null, 1)})</td>
                      <td className="num">{fmtNum(p.mean_fpr * 100, 1)} ± {fmtNum(p.sd_across_pcaps * 100, 1)} (n = {p.n_capture_sets})</td>
                      <td className={`gap ${p.flow_ci_understates ? "signal" : "mid"}`}>{p.flow_ci_understates ? "understates" : "covers"}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
          <p className="caption">The unit of the right-hand column is a capture set (the main run and each replicate). "Understates" means the SD across capture sets exceeds the standard error implied by the flow bootstrap.</p>
        </>
      ) : null}

      <h3>Mixed traffic: share of benign flows on a PQ profile</h3>
      <div className="controls">
        <Select label="PQ profile" value={profile} options={pqProfiles} onChange={setProfile} />
        <label>share of benign flows on the PQ profile
          <input type="range" min={0} max={100} step={1} value={share} onChange={(e) => setShare(Number(e.target.value))} aria-label="share of benign flows on the PQ profile, percent" />
          <span className="mono">{share} %</span>
        </label>
      </div>
      <Status loading={mix.loading} error={mix.error} what="/api/pqmix" />
      {mix.data ? (
        <div className="fig">
          <div className="chart">
            <ResponsiveContainer width="100%" height={340}>
              <LineChart data={lines} margin={{ top: 22, right: narrow ? 70 : 96, left: 4, bottom: 34 }}>
                <CartesianGrid vertical={false} />
                <XAxis type="number" dataKey="pi" domain={[0, 1]} ticks={[0, 0.25, 0.5, 0.75, 1]} tickFormatter={(v: number) => String(Math.round(v * 100))}
                  label={{ value: "share of benign flows on the PQ profile, %", position: "insideBottom", offset: -20, fontSize: 11 }} />
                <YAxis domain={[-0.04, 1.04]} ticks={[0, 0.25, 0.5, 0.75, 1]} tickFormatter={(v: number) => String(Math.round(v * 100))}
                  label={{ value: "false-positive rate, %", angle: -90, position: "insideLeft", offset: 10, fontSize: 11 }} />
                <Tooltip formatter={(v: unknown) => (typeof v === "number" ? fmtPct(v) : "n/a")} labelFormatter={(l: unknown) => `PQ share ${fmtPct(Number(l), 0)}`} />
                <ReferenceLine y={design} stroke="#1d1d1b" strokeDasharray="3 3" label={{ value: `design point ${fmtPct(design, 0)}`, position: "insideTopLeft", fontSize: 11, fill: "#1d1d1b", dy: -8, dx: 90 }} />
                <ReferenceLine x={mix.data.pi} stroke="#9a988f" />
                {MIX_SERIES.filter((s) => s.key in mixMethods).map((s, si) => (
                  <Line key={s.key} dataKey={s.key} stroke={s.ink} strokeWidth={1.25} dot={{ r: 2.5, fill: s.ink, stroke: s.ink }} isAnimationActive={false}>
                    <ErrorBar dataKey={`${s.key}_err`} direction="y" width={4} stroke={s.ink} strokeWidth={1} />
                    <LabelList dataKey={s.key} content={((p: LP) => p.index === 1
                      ? <text x={Number(p.x) + 8} y={Number(p.y) + (si === 1 ? -8 : si === 2 ? 9 : 0)} dy="0.34em" fontSize={11} fill={s.ink} fontFamily="var(--serif)" fontStyle="italic">{s.label}</text> : null) as never} />
                  </Line>
                ))}
                {marks.filter((mk) => MIX_SERIES.some((s) => s.key === mk.label)).map((mk) => (
                  <ReferenceDot key={mk.label} x={mk.pi} y={mk.fpr} r={4.5} fill="var(--bg)" stroke={MIX_SERIES.find((s) => s.key === mk.label)!.ink} strokeWidth={1.5} />
                ))}
              </LineChart>
            </ResponsiveContainer>
          </div>
          <div className="margin">
            <p><b>Computed from measured per-profile false-positive rates, not a simulation.</b></p>
            <p className="mono small">{mix.data.formula.split(", using")[0]}</p>
            <p>The line ends are the measured rates on the classical profile (left) and on {mix.data.profile} (right), with their {ci} bootstrap CIs. Open circles: the mixed rate the API returns at the slider position.</p>
            <table>
              <tbody>
                {MIX_SERIES.filter((s) => s.key in mixMethods).map((s) => (
                  <tr key={s.key}><td>{s.label}</td><td className="num">{fmtPct(mixMethods[s.key]!.fpr_mix)}</td></tr>
                ))}
              </tbody>
            </table>
            {mix.data.simulation ? <p className="warn">The API reports simulation = true; this figure assumes it is not.</p> : null}
            <p>No interval is given for the mixed value; it would need the joint distribution of the two measurements.</p>
          </div>
        </div>
      ) : null}
      <Source prov={mix.data?.provenance} />
    </Section>
  );
}
