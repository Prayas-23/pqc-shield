import { useEffect, useMemo, useState } from "react";
import type React from "react";
import { CartesianGrid, ErrorBar, LabelList, Line, LineChart, ReferenceDot, ReferenceLine, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { useApi } from "../lib/api";
import type { DetectorRecord, DetectorsResponse, Meta, MixResponse } from "../lib/types";
import { fprBars, labelRow, mixLines, shortProfile } from "../lib/mappers";
import type { BarRow } from "../lib/mappers";
import { fmtNum, fmtPct } from "../lib/format";
import { Msg, Select, ViewFrame } from "./Common";

type Mark = "circle" | "ring" | "square" | "diamond";
// method name in the results files -> label, marker and colour. Amber marks the shifted state (naive); the rest are greys.
const SERIES: { key: string; label: string; mark: Mark; color: string }[] = [
  { key: "naive", label: "naive", mark: "circle", color: "#ffb000" },
  { key: "naive_app", label: "V_APP", mark: "ring", color: "#a3a9b3" },
  { key: "canon_bs_k120_true", label: "CANON-B", mark: "square", color: "#e4e7ec" },
  { key: "oracle", label: "oracle", mark: "diamond", color: "#6b717b" },
];
const MIX_SERIES = [
  { key: "naive", label: "naive", color: "#ffb000" },
  { key: "V_APP", label: "V_APP", color: "#a3a9b3" },
  { key: "CANON-B split k=120", label: "CANON-B", color: "#e4e7ec" },
] as const;

function Marker({ mark, color, left, top }: { mark: Mark; color: string; left: string; top: number }) {
  return <i className={`mk ${mark}`} style={{ left, top, "--c": color } as React.CSSProperties} />;
}

/** Dot plot in HTML/CSS so labels stay at their real pixel size: one row per profile, one marker per method, whiskers = CI. */
function DotPlot({ rows, design, hover, onHover }: { rows: BarRow[]; design: number; hover: number | null; onHover: (i: number | null) => void }) {
  const lab = labelRow(rows, SERIES.map((s) => s.key));
  const pct = (v: number) => `${Math.min(Math.max(v, 0), 1) * 100}%`;
  const offs = [-6, -2, 2, 6];
  return (
    <div className="dp" role="img" aria-label="false-positive rate per profile and method">
      <div className="dp-body">
        {rows.map((r, i) => {
          const isLab = i === lab;
          const rh = isLab ? 48 : 22;
          const xr = Math.max(...SERIES.map((s) => (typeof r[s.key] === "number" ? (r[s.key] as number) : 0)));
          return (
            <div key={r.profile} className={`dp-row${hover === i ? " hov" : ""}`} style={{ height: rh }} onMouseEnter={() => onHover(i)} onMouseLeave={() => onHover(null)}>
              <div className="dp-lab" title={r.profile}>{shortProfile(r.profile)}</div>
              <div className="dp-plot">
                {[0, 0.25, 0.5, 0.75, 1].map((t) => <span key={t} className="dp-tick" style={{ left: pct(t) }} />)}
                <span className="dp-design" style={{ left: pct(design) }} />
                {SERIES.map((s, si) => {
                  const v = r[s.key];
                  if (typeof v !== "number") return null;
                  const e = r[`${s.key}_err`];
                  const top = rh / 2 + offs[si]!;
                  return (
                    <span key={s.key}>
                      {Array.isArray(e) ? <i className="wh" style={{ left: pct(v - e[0]), width: `${(Math.min(v + e[1], 1) - Math.max(v - e[0], 0)) * 100}%`, top, background: s.color }} /> : null}
                      <Marker mark={s.mark} color={s.color} left={pct(v)} top={top} />
                    </span>
                  );
                })}
                {isLab ? (
                  <span className="dp-labels" style={{ left: `calc(${pct(xr)} + 12px)` }}>
                    {SERIES.map((s) => (typeof r[s.key] === "number" ? <span key={s.key} style={{ color: s.color }}>{s.label}</span> : null))}
                  </span>
                ) : null}
              </div>
            </div>
          );
        })}
      </div>
      <div className="dp-row axis">
        <div className="dp-lab dim">false-positive rate, %</div>
        <div className="dp-plot">
          {[0, 0.25, 0.5, 0.75, 1].map((t) => <span key={t} className="dp-tl" style={{ left: pct(t) }}>{Math.round(t * 100)}</span>)}
          <span className="dp-dl" style={{ left: pct(design) }}>design point {fmtPct(design, 0)}</span>
        </div>
      </div>
    </div>
  );
}

function readout(r: BarRow | undefined): string {
  if (!r) return "hover a row for exact values";
  return SERIES.map((s) => {
    const v = r[s.key], e = r[`${s.key}_err`];
    if (typeof v !== "number") return `${s.label} n/a`;
    return `${s.label} ${fmtPct(v)} ${Array.isArray(e) ? `[${fmtPct(v - e[0])}, ${fmtPct(v + e[1])}]` : "[CI n/a]"}`;
  }).join("   ");
}

function pcapRows(records: DetectorRecord[]) {
  return records.filter((r) => r.pcap_level && SERIES.some((s) => s.key === r.method));
}

export function DetectorsView({ meta }: { meta: Meta }) {
  const [detector, setDetector] = useState(meta.detectors.includes("rf") ? "rf" : meta.detectors[0]!);
  const det = useApi<DetectorsResponse>(`/api/detectors?detector=${detector}&dataset=main&limit=10000`);
  const rows = useMemo(() => (det.data ? fprBars(det.data.records, SERIES.map((s) => s.key), "naive") : []), [det.data]);
  const [hover, setHover] = useState<number | null>(null);
  const [tab, setTab] = useState<"dots" | "captures">("dots");
  const design = meta.design_fpr;
  const ci = fmtPct(meta.ci_level, 0);
  const pcap = pcapRows(det.data?.records ?? []);

  const pq = meta.profiles.filter((p) => p !== meta.classical_profile);
  const [profile, setProfile] = useState(pq[0] ?? meta.classical_profile);
  const [share, setShare] = useState(50);
  const [applied, setApplied] = useState(50);
  useEffect(() => { const t = setTimeout(() => setApplied(share), 150); return () => clearTimeout(t); }, [share]);
  const mix = useApi<MixResponse>(`/api/pqmix?pi=${applied / 100}&detector=${detector}&profile=${encodeURIComponent(profile)}`);
  const { lines, marks } = useMemo(() => (mix.data ? mixLines(mix.data) : { lines: [], marks: [] }), [mix.data]);
  const mm = mix.data?.methods ?? {};

  const controls = (
    <>
      <Select label="detector" value={detector} options={meta.detectors} onChange={setDetector} />
      <Select label="PQ profile for the mix" value={profile} options={pq} onChange={setProfile} format={shortProfile} />
      <label className="field"><span>PQ share of benign flows: <span style={{ color: "var(--ink)" }}>{share} %</span></span>
        <input type="range" min={0} max={100} step={1} value={share} onChange={(e) => setShare(Number(e.target.value))} aria-label="share of benign flows on the PQ profile, percent" />
      </label>
      <div className="sect">mixed rate at this share</div>
      <table className="kv"><tbody>
        {MIX_SERIES.filter((s) => s.key in mm).map((s) => (
          <tr key={s.key}><td style={{ color: s.color }}>{s.label}</td><td className="num">{fmtPct(mm[s.key]!.fpr_mix)}</td></tr>
        ))}
      </tbody></table>
      <div className="dim">bars are means over model seeds; whiskers are {ci} flow-bootstrap intervals.</div>
    </>
  );

  const help = (
    <>
      <p>Each detector is set to flag {fmtPct(design, 0)} of benign flows in its training domain; the dashed line marks that design point. A dot far to its right means the detector raises alarms on ordinary benign traffic of that profile. Profiles are sorted by the naive detector's rate.</p>
      <p><em>naive</em>: trained and thresholded on the classical profile only, on whole-connection flow features. <em>V_APP</em>: the same on application-phase features only. <em>CANON-B</em>: naive plus the k-shot split-conformal correction. <em>oracle</em>: trained on the profile itself. Whiskers are flow-bootstrap intervals; they do not include capture-to-capture variation, which the second tab shows for the replicated profiles.</p>
      <p>The mix curve is a weighted average of two measured rates (classical profile and the chosen PQ profile), so it is a straight line between them. It is computed from measured per-profile false-positive rates, not a simulation, and carries no interval of its own.</p>
    </>
  );

  return (
    <ViewFrame title="Detectors and mix" help={help} controls={controls} prov={mix.data?.provenance ?? det.data?.provenance}
      status={<span>detector {detector}</span>}>
      <Msg loading={det.loading && !det.data} error={det.error} what="/api/detectors" />
      <div className="panes2">
        <section className="pane">
          <div className="strip">
            <button type="button" className={tab === "dots" ? "on" : ""} onClick={() => setTab("dots")}>flow CI</button>
            <button type="button" className={tab === "captures" ? "on" : ""} onClick={() => setTab("captures")}>capture sets</button>
            <span className="grow" />
            <span>false-positive rate</span>
          </div>
          <div className="pbody">
            {tab === "dots" ? (
              <>
                <p className="one">Benign test flows flagged, per profile and method.</p>
                {rows.length ? <DotPlot rows={rows} design={design} hover={hover} onHover={setHover} /> : null}
                <div className="readout" aria-live="polite">{hover !== null ? <><span style={{ color: "var(--ink)" }}>{rows[hover] ? shortProfile(rows[hover]!.profile) : ""}</span><br /></> : null}{readout(hover !== null ? rows[hover] : undefined)}</div>
              </>
            ) : (
              <>
                <p className="one">Replicated profiles: spread across capture sets next to the flow-bootstrap interval.</p>
                <div style={{ overflow: "auto", flex: 1, minHeight: 0 }}>
                  <table className="dense">
                    <thead><tr><th>profile</th><th>method</th><th className="num">flow, % ({ci} CI)</th><th className="num">captures, % mean ± SD</th><th>flow CI</th></tr></thead>
                    <tbody>
                      {pcap.map((r) => {
                        const f = r.metrics["fpr"], p = r.pcap_level!;
                        return (
                          <tr key={r.profile + r.method} title={r.profile}>
                            <td>{shortProfile(r.profile)}</td><td>{SERIES.find((s) => s.key === r.method)?.label}</td>
                            <td className="num">{fmtNum(f?.value != null ? f.value * 100 : null, 1)} ({fmtNum(f?.ci_lo != null ? f.ci_lo * 100 : null, 1)} to {fmtNum(f?.ci_hi != null ? f.ci_hi * 100 : null, 1)})</td>
                            <td className="num">{fmtNum(p.mean_fpr * 100, 1)} ± {fmtNum(p.sd_across_pcaps * 100, 1)} (n = {p.n_capture_sets})</td>
                            <td className={p.flow_ci_understates ? "sig" : "dim"} style={{ paddingLeft: "0.6rem" }}>{p.flow_ci_understates ? "understates" : "covers"}</td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </>
            )}
          </div>
        </section>

        <section className="pane">
          <div className="strip">
            <b>mixed traffic</b><span className="grow" />
            
          </div>
          <div className="pbody">
            <p className="one"><span className="sig">Computed from measured per-profile FPR, not a simulation.</span> A share of benign flows uses {shortProfile(profile)}; the rest is classical.</p>
            <Msg loading={mix.loading && !mix.data} error={mix.error} what="/api/pqmix" />
            {mix.data ? (
              <div className="chartbox chart" style={{ minHeight: 200 }}>
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart data={lines} margin={{ top: 14, right: 78, left: 0, bottom: 22 }}>
                    <CartesianGrid vertical={false} />
                    <XAxis type="number" dataKey="pi" domain={[0, 1]} ticks={[0, 0.25, 0.5, 0.75, 1]} tickFormatter={(v: number) => String(Math.round(v * 100))}
                      label={{ value: "share of benign flows on the PQ profile, %", position: "insideBottom", offset: -14, fontSize: 10 }} />
                    <YAxis domain={[-0.04, 1.04]} ticks={[0, 0.25, 0.5, 0.75, 1]} allowDataOverflow tickFormatter={(v: number) => `${Math.round(v * 100)} %`} width={46} />
                    <Tooltip contentStyle={{ background: "#171a1e", border: "1px solid #3a3f48", borderRadius: 0, fontSize: 11 }}
                      formatter={(v: unknown) => (typeof v === "number" ? fmtPct(v) : "n/a")} labelFormatter={(l: unknown) => `PQ share ${fmtPct(Number(l), 0)}`} />
                    <ReferenceLine y={design} stroke="#8b919b" strokeDasharray="3 3" label={{ value: `design ${fmtPct(design, 0)}`, position: "insideTopLeft", fontSize: 10, fill: "#8b919b", dx: 70, dy: -3 }} />
                    <ReferenceLine x={mix.data.pi} stroke="#3a3f48" />
                    {MIX_SERIES.filter((s) => s.key in mm).map((s, si) => (
                      <Line key={s.key} dataKey={s.key} stroke={s.color} strokeWidth={1.2} dot={{ r: 2.5, fill: s.color, stroke: s.color }} isAnimationActive={false}>
                        <ErrorBar dataKey={`${s.key}_err`} direction="y" width={4} stroke={s.color} strokeWidth={1} />
                        <LabelList dataKey={s.key} content={((p: { x?: number | string; y?: number | string; index?: number }) => p.index === 1
                          ? <text x={Number(p.x) + 8} y={Number(p.y) + (si === 1 ? -8 : si === 2 ? 9 : 0)} dy="0.34em" fontSize={10} fill={s.color}>{s.label}</text> : null) as never} />
                      </Line>
                    ))}
                    {marks.filter((mk) => MIX_SERIES.some((s) => s.key === mk.label)).map((mk) => (
                      <ReferenceDot key={mk.label} x={mk.pi} y={mk.fpr} r={4.5} fill="#121417" stroke={MIX_SERIES.find((s) => s.key === mk.label)!.color} strokeWidth={1.5} />
                    ))}
                  </LineChart>
                </ResponsiveContainer>
              </div>
            ) : null}
            <div className="readout">{mix.data ? mix.data.formula.split(", using")[0] : ""}</div>
          </div>
        </section>
      </div>
    </ViewFrame>
  );
}
