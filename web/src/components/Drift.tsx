import { Fragment, useEffect, useMemo, useState } from "react";
import { useApi } from "../lib/api";
import type { DriftResponse } from "../lib/types";
import { cellKey, driftMatrix, heatSummary, intensity, metricsForView, shortFeature, shortProfile } from "../lib/mappers";
import type { DriftMetric, HeatCell } from "../lib/mappers";
import { fmtInt, fmtNum, fmtP } from "../lib/format";
import { Msg, Select, SkelGrid, ViewFrame } from "./Common";

const metricLabel: Record<DriftMetric, string> = {
  psi: "population stability index (PSI)", eta2: "eta squared", mmd2: "MMD squared", partial_eta2: "partial eta squared",
};
const viewLabel: Record<string, string> = { hs: "handshake phase (hs_)", app: "application phase (app_)", flow: "whole connection (flow_)" };

/** Continuous single-hue scale: dark panel tone to amber. Cells inside the noise floor stay neutral. */
function fill(c: HeatCell | undefined, vmax: number, hasFloor: boolean): { cls: string; bg?: string } {
  if (!c || c.value === null) return { cls: "hcell na" };
  if (hasFloor && c.above === false) return { cls: "hcell", bg: "#1a2631" };
  const a = 0.16 + 0.84 * intensity(c.value, vmax);
  return { cls: "hcell", bg: `color-mix(in srgb, var(--amber) ${Math.round(a * 100)}%, #17222d)` };
}

/** Rows are profiles (or model terms in the handshake view), columns are features. */
const rowName = (view: string, c: string): string => (view === "hs" ? c : shortProfile(c));

export function DriftView() {
  const all = useApi<DriftResponse>("/api/drift?limit=5000");
  const rows = all.data?.rows ?? [];
  const workloads = useMemo(() => [...new Set(rows.map((r) => r.workload))], [rows]);
  const views = useMemo(() => [...new Set(rows.map((r) => r.view))], [rows]);
  const [workload, setWorkload] = useState("");
  const [view, setView] = useState("");
  const [metric, setMetric] = useState<DriftMetric>("psi");
  const [sel, setSel] = useState<HeatCell | null>(null);
  const [hov, setHov] = useState<{ r: string; f: string } | null>(null);
  useEffect(() => { if (!workload && workloads.length) setWorkload(workloads.includes("benign_web") ? "benign_web" : workloads[0]!); }, [workloads, workload]);
  useEffect(() => { if (!view && views.length) setView(views.includes("flow") ? "flow" : views[0]!); }, [views, view]);
  const metrics = metricsForView(view);
  const m = metrics.includes(metric) ? metric : metrics[0]!;
  const matrix = useMemo(() => (workload && view ? driftMatrix(rows, workload, view, m) : null), [rows, workload, view, m]);
  useEffect(() => setSel(null), [workload, view, m]);
  const sum = useMemo(() => (matrix ? heatSummary(matrix) : null), [matrix]);
  const cell = sel ? matrix?.cells.get(cellKey(sel.feature, sel.column)) ?? null : null;
  const hovCell = hov && matrix ? matrix.cells.get(cellKey(hov.f, hov.r)) : null;

  const controls = (
    <>
      <Select label="workload" value={workload} options={workloads} onChange={setWorkload} />
      <Select label="feature view" value={view} options={views} onChange={setView} format={(v) => viewLabel[v] ?? v} />
      <Select label="effect size" value={m} options={metrics} onChange={(v) => setMetric(v as DriftMetric)} />
      <div className="sect">scale</div>
      <div className="scale">
        <div className="bar" />
        <div className="ends"><span>0</span><span>{matrix ? fmtNum(matrix.vmax, 2) : "n/a"}</span></div>
        <div className="dim"><span className="swatch" style={{ background: "#1a2631" }} />within the noise floor</div>
        <div className="dim"><span className="swatch" style={{ background: "transparent" }} />n/a, no value from the API</div>
      </div>
      {sum && matrix?.hasFloor ? (
        <div className="fig"><span className="v amber">{fmtInt(sum.above)}<small>of {fmtInt(sum.total - sum.na)} cells</small></span>
          <span className="l">exceed the noise floor{sum.weakest ? `; fewest in ${shortFeature(sum.weakest.feature)} (${fmtInt(sum.weakest.above)} of ${fmtInt(sum.weakest.n)})` : ""}</span></div>
      ) : matrix ? <div className="dim">No noise floor for this view and effect size: n/a.</div> : null}
      <div className="sect">{cell ? "selected cell" : "hover or click a cell"}</div>
      {(cell ?? hovCell) ? (() => {
        const c = (cell ?? hovCell)!;
        return (
          <table className="kv"><tbody>
            <tr><td colSpan={2} style={{ color: "var(--ink)" }}>{shortFeature(c.feature)}</td></tr>
            <tr><td colSpan={2} title={c.column}>{rowName(view, c.column)}</td></tr>
            <tr><td>{metricLabel[m].split(" (")[0]}</td><td className="num" style={{ color: c.above ? "var(--amber)" : undefined }}>{fmtNum(c.value, 4)}</td></tr>
            <tr><td>noise floor</td><td className="num">{fmtNum(c.floor, 4)}</td></tr>
            <tr><td>eta squared</td><td className="num">{fmtNum(c.row.eta2, 4)}</td></tr>
            <tr><td>partial eta sq.</td><td className="num">{fmtNum(c.row.partial_eta2, 4)}</td></tr>
            <tr><td>PSI</td><td className="num">{fmtNum(c.row.psi, 4)}</td></tr>
            <tr><td>MMD squared</td><td className="num">{fmtNum(c.row.mmd2, 4)}</td></tr>
            <tr><td>MMD p-value</td><td className="num">{fmtP(c.row.mmd2_p_value)}</td></tr>
            <tr><td>flows, ref. / compared</td><td className="num">{fmtInt(c.row.n_ref)} / {fmtInt(c.row.n_group)}</td></tr>
          </tbody></table>
        );
      })() : null}
    </>
  );

  const help = (
    <>
      <p>Each cell compares one feature of one profile with the same feature of the classical reference profile, within one workload. The shade is an effect size on a continuous amber scale. Cells within the noise floor are neutral: the noise floor is the 95th percentile of the same statistic when profile labels are shuffled within the workload, so it is a yardstick, not a significance test.</p>
      <p>The API gives point effect sizes and the noise floor, not confidence intervals (n/a). In the handshake view the rows are model terms (key exchange, signature, their interaction) instead of profiles, and there is no noise floor. Hovering a cell highlights its row and column; clicking pins its numbers in the control panel.</p>
    </>
  );

  const cols = matrix?.features ?? [], rws = matrix?.columns ?? [];
  return (
    <ViewFrame title="Feature drift" help={help} controls={controls} prov={all.data?.provenance}
      status={matrix ? <span>{workload} · {viewLabel[view] ?? view} · {metricLabel[m]}</span> : null}>
      <Msg loading={all.loading} error={all.error} what="/api/drift" fallback={<SkelGrid rows={12} cols={22} />} />
      {matrix && cols.length > 0 ? (
        <>
          <p className="one">Effect size of each feature, per profile, against the classical reference.</p>
          <div className="heatwrap" key={`${workload}-${view}-${m}`} role="grid" aria-label="effect size by profile and feature" onMouseLeave={() => setHov(null)}
            style={{ gridTemplateColumns: `17rem repeat(${cols.length}, minmax(0, 1fr))`, gridTemplateRows: `7.8rem repeat(${rws.length}, minmax(0, 1fr))` }}>
            <div />
            {cols.map((f) => <div key={f} className={`hcol${hov?.f === f ? " hov" : ""}`} title={f}><span>{shortFeature(f)}</span></div>)}
            {rws.map((r) => (
              <Fragment key={r}>
                <div className={`hrow${hov?.r === r ? " hov" : ""}`} title={r}>{rowName(view, r)}</div>
                {cols.map((f) => {
                  const x = matrix.cells.get(cellKey(f, r));
                  const st = fill(x, matrix.vmax, matrix.hasFloor);
                  const isSel = sel && sel.feature === f && sel.column === r;
                  const cross = hov && (hov.r === r || hov.f === f) ? " cross" : "";
                  return (
                    <button key={`${r}-${f}`} type="button" className={`${st.cls}${isSel ? " sel" : ""}${cross}`} style={{ background: st.bg }}
                      title={`${rowName(view, r)} | ${f}: ${fmtNum(x?.value, 4)}${x?.floor != null ? ` (noise floor ${fmtNum(x.floor, 4)})` : ""}`}
                      onMouseEnter={() => setHov({ r, f })} onFocus={() => setHov({ r, f })}
                      disabled={!x || x.value === null} onClick={() => x && setSel(x)} aria-label={`${r}, ${f}`} />
                  );
                })}
              </Fragment>
            ))}
          </div>
        </>
      ) : (!all.loading && !all.error ? <div className="empty">No rows for this workload and view.</div> : null)}
    </ViewFrame>
  );
}
