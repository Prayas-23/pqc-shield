import { useMemo, useState } from "react";
import type React from "react";
import { useApi } from "../lib/api";
import type { DetectorRecord, DetectorsResponse, Meta, MixResponse } from "../lib/types";
import { fprBars, labelRow, mixAt, shortProfile } from "../lib/mappers";
import type { BarRow } from "../lib/mappers";
import { fmtNum, fmtPct } from "../lib/format";
import { Msg, Select, SkelBlock, SkelRows, ViewFrame, useSize } from "./Common";

type Mark = "circle" | "ring" | "square" | "diamond";
// method name in the results files -> label, marker and colour. Amber = shifted (naive); teal = normal / corrected; grey = reference.
const SERIES: { key: string; label: string; mark: Mark; color: string }[] = [
  { key: "naive", label: "naive", mark: "circle", color: "#ffb000" },
  { key: "naive_app", label: "V_APP", mark: "ring", color: "#7fe3d6" },
  { key: "canon_bs_k120_true", label: "CANON-B", mark: "square", color: "#3fd0bd" },
  { key: "oracle", label: "oracle", mark: "diamond", color: "#8fa3b5" },
];
const MIX_SERIES = [
  { key: "naive", label: "naive", color: "#ffb000", dash: "" },
  { key: "V_APP", label: "V_APP", color: "#8fa3b5", dash: "5 4" },
  { key: "CANON-B split k=120", label: "CANON-B", color: "#3fd0bd", dash: "" },
] as const;

function Marker({ mark, color, left, top }: { mark: Mark; color: string; left: string; top: number }) {
  return <i className={`mk ${mark}`} style={{ left, top, "--c": color } as React.CSSProperties} />;
}

/** Dot plot in HTML/CSS: one row per profile, one marker per method, CI whiskers, a shaded design band. */
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
                <span className="dp-band" style={{ width: pct(design) }} />
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
          <span className="dp-dl" style={{ left: pct(design) }}>design band 0-{fmtPct(design, 0)}</span>
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

/** Mixed-traffic curves drawn at their pixel size; the marker is draggable and reads out both methods live. */
function MixChart({ mix, share, onShare, design }: { mix: MixResponse; share: number; onShare: (pct: number) => void; design: number }) {
  const [ref, { w, h }] = useSize<HTMLDivElement>();
  const ml = 46, mr = 72, mt = 22, mb = 34;
  const pw = Math.max(w - ml - mr, 10), ph = Math.max(h - mt - mb, 10);
  const x = (pi: number) => ml + pi * pw;
  const y = (v: number) => mt + (1 - Math.min(Math.max(v, 0), 1)) * ph;
  const series = MIX_SERIES.filter((s) => s.key in mix.methods);
  const pi = share / 100;
  const set = (clientX: number, el: Element) => {
    const b = el.getBoundingClientRect();
    onShare(Math.round(Math.min(Math.max((clientX - b.left - ml) / pw, 0), 1) * 100));
  };
  const drag = (e: React.PointerEvent<SVGSVGElement>) => { if (e.buttons === 1) set(e.clientX, e.currentTarget); };
  return (
    <div className="mixsvg" ref={ref}>
      {w > 0 ? (
        <svg className="mix" viewBox={`0 0 ${w} ${h}`} role="img" aria-label="mixed-traffic false-positive rate against PQ share"
          onPointerDown={(e) => { e.currentTarget.setPointerCapture(e.pointerId); set(e.clientX, e.currentTarget); }} onPointerMove={drag}>
          <rect x={ml} y={y(design)} width={pw} height={y(0) - y(design)} fill="var(--teal-glow)" opacity={0.55} />
          {[0, 0.25, 0.5, 0.75, 1].map((t) => (
            <g key={t}>
              <line className="gridl" x1={ml} x2={ml + pw} y1={y(t)} y2={y(t)} />
              <text x={ml - 6} y={y(t)} dy="0.34em" textAnchor="end">{Math.round(t * 100)} %</text>
              <text x={x(t)} y={mt + ph + 14} textAnchor="middle">{Math.round(t * 100)}</text>
            </g>
          ))}
          <text x={ml + pw / 2} y={h - 4} textAnchor="middle">share of benign flows on the PQ profile, %</text>
          <line x1={ml} x2={ml + pw} y1={y(design)} y2={y(design)} stroke="var(--teal)" strokeDasharray="3 3" strokeWidth={1} />
          <text x={ml + 6} y={y(design) - 5} style={{ fill: "var(--teal)" }}>design point {fmtPct(design, 0)}</text>
          {series.map((s, si) => {
            const m = mix.methods[s.key]!;
            const lab = y(m.fpr_profile) + (si === 1 ? -9 : si === 2 ? 9 : 0);
            return (
              <g key={`${s.key}-${mix.profile}-${mix.detector}`}>
                <path className="curve" d={`M${x(0)},${y(m.fpr_classical)} L${x(1)},${y(m.fpr_profile)}`} stroke={s.color} style={s.dash ? { strokeDasharray: s.dash, animation: "none" } : undefined} />
                {([[0, m.fpr_classical, m.fpr_classical_ci], [1, m.fpr_profile, m.fpr_profile_ci]] as const).map(([e, v, ci]) => (
                  <g key={e} stroke={s.color} strokeWidth={1}>
                    <line x1={x(e)} x2={x(e)} y1={y(ci[0])} y2={y(ci[1])} />
                    <line x1={x(e) - 3} x2={x(e) + 3} y1={y(ci[0])} y2={y(ci[0])} /><line x1={x(e) - 3} x2={x(e) + 3} y1={y(ci[1])} y2={y(ci[1])} />
                    <circle cx={x(e)} cy={y(v)} r={2.6} fill={s.color} stroke="none" />
                  </g>
                ))}
                <text x={x(1) + 10} y={lab} dy="0.34em" style={{ fill: s.color }}>{s.label}</text>
              </g>
            );
          })}
          <line x1={x(pi)} x2={x(pi)} y1={mt - 6} y2={mt + ph} stroke="var(--ink)" strokeWidth={1} opacity={0.8} />
          {series.map((s) => (
            <g key={`pt-${s.key}`}>
              <circle cx={x(pi)} cy={y(mixAt(pi, mix.methods[s.key]!.fpr_profile, mix.methods[s.key]!.fpr_classical))} r={5.5} fill="var(--s1)" stroke={s.color} strokeWidth={2} />
            </g>
          ))}
          <g className="handle">
            <rect x={x(pi) - 30} y={2} width={60} height={16} rx={2} fill="var(--s3)" stroke="var(--ink)" />
            <text x={x(pi)} y={10} dy="0.34em" textAnchor="middle" style={{ fill: "var(--ink)" }}>{share} %</text>
          </g>
        </svg>
      ) : null}
    </div>
  );
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
  const mix = useApi<MixResponse>(`/api/pqmix?pi=0.5&detector=${detector}&profile=${encodeURIComponent(profile)}`);
  const live = (key: string): number | null => (mix.data && key in mix.data.methods ? mixAt(share / 100, mix.data.methods[key]!.fpr_profile, mix.data.methods[key]!.fpr_classical) : null);

  const controls = (
    <>
      <Select label="detector" value={detector} options={meta.detectors} onChange={setDetector} />
      <Select label="PQ profile for the mix" value={profile} options={pq} onChange={setProfile} format={shortProfile} />
      <label className="field"><span>PQ share of benign flows</span>
        <input type="range" min={0} max={100} step={1} value={share} onChange={(e) => setShare(Number(e.target.value))} aria-label="share of benign flows on the PQ profile, percent" />
      </label>
      <div className="sect">mixed rate at {share} % PQ share</div>
      <div className="figs">
        {MIX_SERIES.filter((s) => live(s.key) !== null && s.key !== "V_APP").map((s) => (
          <div className="fig" key={s.key}><span className="v" style={{ color: s.color }}>{fmtNum((live(s.key) ?? 0) * 100, 1)}<small>%</small></span><span className="l">{s.label}</span></div>
        ))}
      </div>
      <div className="dim">{live("V_APP") !== null ? `V_APP ${fmtPct(live("V_APP"))}. ` : ""}Bars: means over model seeds; whiskers: {ci} flow-bootstrap intervals.</div>
    </>
  );

  const help = (
    <>
      <p>Each detector is set to flag {fmtPct(design, 0)} of benign flows in its training domain; the shaded band and dashed line mark that design point. A marker far to its right means the detector raises alarms on ordinary benign traffic of that profile. Profiles are sorted by the naive detector's rate. Amber marks the shifted state, teal the normal or corrected one.</p>
      <p><em>naive</em>: trained and thresholded on the classical profile only, on whole-connection flow features. <em>V_APP</em>: the same on application-phase features only. <em>CANON-B</em>: naive plus the k-shot split-conformal correction. <em>oracle</em>: trained on the profile itself. Whiskers are flow-bootstrap intervals; they do not include capture-to-capture variation, which the second tab shows for the replicated profiles.</p>
      <p>The mix curve is a weighted average of two measured rates (classical profile and the chosen PQ profile): rate = share × FPR(PQ profile) + (1 − share) × FPR(classical). It is computed from measured per-profile false-positive rates, not a simulation, and carries no interval of its own. Drag the marker or use the slider.</p>
    </>
  );

  return (
    <ViewFrame title="Detectors and mix" help={help} controls={controls} prov={mix.data?.provenance ?? det.data?.provenance}
      status={<span>detector {detector}</span>}>
      <Msg loading={det.loading && !det.data} error={det.error} what="/api/detectors" fallback={<div className="panes2"><SkelBlock height={420} /><SkelBlock height={420} /></div>} />
      {det.data ? (
        <div className="panes2">
          <section className="pane">
            <div className="phead">
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
                          const s = SERIES.find((x) => x.key === r.method)!;
                          return (
                            <tr key={r.profile + r.method} title={r.profile}>
                              <td>{shortProfile(r.profile)}</td><td style={{ color: s.color }}>{s.label}</td>
                              <td className="num">{fmtNum(f?.value != null ? f.value * 100 : null, 1)} ({fmtNum(f?.ci_lo != null ? f.ci_lo * 100 : null, 1)} to {fmtNum(f?.ci_hi != null ? f.ci_hi * 100 : null, 1)})</td>
                              <td className="num">{fmtNum(p.mean_fpr * 100, 1)} ± {fmtNum(p.sd_across_pcaps * 100, 1)} (n = {p.n_capture_sets})</td>
                              <td className={p.flow_ci_understates ? "amber" : "dim"} style={{ paddingLeft: "0.6rem" }}>{p.flow_ci_understates ? "understates" : "covers"}</td>
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
            <div className="phead"><b>mixed traffic</b><span className="grow" /><span>{shortProfile(profile)}</span></div>
            <div className="pbody">
              <p className="one"><span className="teal">Computed from measured per-profile FPR, not a simulation.</span> Drag the marker to change the PQ share.</p>
              <Msg loading={mix.loading && !mix.data} error={mix.error} what="/api/pqmix" fallback={<SkelRows n={6} />} />
              {mix.data ? <MixChart mix={mix.data} share={share} onShare={setShare} design={design} /> : null}
              <div className="readout">{mix.data ? mix.data.formula.split(", using")[0] : ""}</div>
            </div>
          </section>
        </div>
      ) : null}
    </ViewFrame>
  );
}
