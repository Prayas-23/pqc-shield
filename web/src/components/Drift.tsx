import { Fragment, useEffect, useMemo, useState } from "react";
import { useApi } from "../lib/api";
import type { DriftResponse } from "../lib/types";
import { cellKey, driftMatrix, heatSummary, intensity, metricsForView, shortFeature, shortProfile } from "../lib/mappers";
import type { DriftMetric, HeatCell } from "../lib/mappers";
import { fmtInt, fmtNum, fmtP } from "../lib/format";
import { Msg, Select, ViewFrame } from "./Common";

const metricLabel: Record<DriftMetric, string> = {
  psi: "population stability index (PSI)", eta2: "eta squared", mmd2: "MMD squared", partial_eta2: "partial eta squared",
};
const viewLabel: Record<string, string> = { hs: "handshake phase (hs_)", app: "application phase (app_)", flow: "whole connection (flow_)" };

function fill(c: HeatCell | undefined, vmax: number, hasFloor: boolean): { cls: string; bg?: string } {
  if (!c || c.value === null) return { cls: "hcell na" };
  if (hasFloor && c.above === false) return { cls: "hcell", bg: "#2a2e35" };
  const a = 0.2 + 0.8 * intensity(c.value, vmax);
  return { cls: "hcell", bg: `color-mix(in srgb, var(--signal) ${Math.round(a * 100)}%, #1b1e23)` };
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
  useEffect(() => { if (!workload && workloads.length) setWorkload(workloads.includes("benign_web") ? "benign_web" : workloads[0]!); }, [workloads, workload]);
  useEffect(() => { if (!view && views.length) setView(views.includes("flow") ? "flow" : views[0]!); }, [views, view]);
  const metrics = metricsForView(view);
  const m = metrics.includes(metric) ? metric : metrics[0]!;
  const matrix = useMemo(() => (workload && view ? driftMatrix(rows, workload, view, m) : null), [rows, workload, view, m]);
  useEffect(() => setSel(null), [workload, view, m]);
  const sum = useMemo(() => (matrix ? heatSummary(matrix) : null), [matrix]);
  const cell = sel ? matrix?.cells.get(cellKey(sel.feature, sel.column)) ?? null : null;

  const controls = (
    <>
      <Select label="workload" value={workload} options={workloads} onChange={setWorkload} />
      <Select label="feature view" value={view} options={views} onChange={setView} format={(v) => viewLabel[v] ?? v} />
      <Select label="effect size" value={m} options={metrics} onChange={(v) => setMetric(v as DriftMetric)} />
      <div className="sect">legend</div>
      <div className="dim">
        <div><span className="swatch" style={{ background: "var(--signal)" }} />above the noise floor; brighter = larger</div>
        <div><span className="swatch" style={{ background: "#2a2e35" }} />within the noise floor</div>
        <div><span className="swatch" style={{ boxShadow: "inset 0 0 0 1px var(--line2)" }} />n/a, no value from the API</div>
      </div>
      {sum && matrix?.hasFloor ? (
        <div className="dim"><span style={{ color: "var(--ink)" }}>{fmtInt(sum.above)} of {fmtInt(sum.total - sum.na)}</span> cells exceed the noise floor{sum.weakest ? <>; fewest in <span style={{ color: "var(--ink)" }}>{shortFeature(sum.weakest.feature)}</span> ({fmtInt(sum.weakest.above)} of {fmtInt(sum.weakest.n)})</> : null}.</div>
      ) : matrix ? <div className="dim">no noise floor for this view and effect size: n/a.</div> : null}
      <div className="sect">selected cell</div>
      {cell ? (
        <table className="kv"><tbody>
          <tr><td colSpan={2} style={{ color: "var(--ink)" }}>{shortFeature(cell.feature)}</td></tr>
          <tr><td colSpan={2} title={cell.column}>{rowName(view, cell.column)}</td></tr>
          <tr><td>eta squared</td><td className="num">{fmtNum(cell.row.eta2, 4)}</td></tr>
          <tr><td>partial eta sq.</td><td className="num">{fmtNum(cell.row.partial_eta2, 4)}</td></tr>
          <tr><td>PSI</td><td className="num">{fmtNum(cell.row.psi, 4)}</td></tr>
          <tr><td>MMD squared</td><td className="num">{fmtNum(cell.row.mmd2, 4)}</td></tr>
          <tr><td>MMD p-value</td><td className="num">{fmtP(cell.row.mmd2_p_value)}</td></tr>
          <tr><td>floor, eta sq.</td><td className="num">{fmtNum(cell.row.noise95_eta2, 4)}</td></tr>
          <tr><td>floor, PSI</td><td className="num">{fmtNum(cell.row.noise95_max_psi, 4)}</td></tr>
          <tr><td>flows, ref.</td><td className="num">{fmtInt(cell.row.n_ref)}</td></tr>
          <tr><td>flows, compared</td><td className="num">{fmtInt(cell.row.n_group)}</td></tr>
        </tbody></table>
      ) : <div className="dim">click a cell</div>}
    </>
  );

  const help = (
    <>
      <p>Each cell compares one feature of one profile with the same feature of the classical reference profile, within one workload. The shade is an effect size. Cells within the noise floor are grey: the noise floor is the 95th percentile of the same statistic when profile labels are shuffled within the workload, so it is a yardstick, not a significance test.</p>
      <p>The API gives point effect sizes and the noise floor, not confidence intervals (n/a). In the handshake view the rows are model terms (key exchange, signature, their interaction) instead of profiles, and there is no noise floor.</p>
    </>
  );

  const cols = matrix?.features ?? [], rws = matrix?.columns ?? [];
  return (
    <ViewFrame title="Feature drift" help={help} controls={controls} prov={all.data?.provenance}
      status={matrix ? <span>{workload} · {viewLabel[view] ?? view} · {metricLabel[m]}</span> : null}>
      <Msg loading={all.loading} error={all.error} what="/api/drift" />
      {matrix && cols.length > 0 ? (
        <>
          <p className="one">Effect size of each feature, per profile, against the classical reference.</p>
          <div className="heatwrap" role="grid" aria-label="effect size by profile and feature"
            style={{ gridTemplateColumns: `17rem repeat(${cols.length}, minmax(0, 1fr))`, gridTemplateRows: `6.2rem repeat(${rws.length}, minmax(0, 1fr))` }}>
            <div />
            {cols.map((f) => <div key={f} className="hcol" title={f}><span>{shortFeature(f)}</span></div>)}
            {rws.map((r) => (
              <Fragment key={r}>
                <div className="hrow" title={r}>{rowName(view, r)}</div>
                {cols.map((f) => {
                  const x = matrix.cells.get(cellKey(f, r));
                  const st = fill(x, matrix.vmax, matrix.hasFloor);
                  const isSel = sel && sel.feature === f && sel.column === r;
                  return (
                    <button key={`${r}-${f}`} type="button" className={`${st.cls}${isSel ? " sel" : ""}`} style={{ background: st.bg }}
                      title={`${rowName(view, r)} | ${f}: ${fmtNum(x?.value, 4)}${x?.floor != null ? ` (noise floor ${fmtNum(x.floor, 4)})` : ""}`}
                      disabled={!x || x.value === null} onClick={() => x && setSel(x)} aria-label={`${r}, ${f}`} />
                  );
                })}
              </Fragment>
            ))}
          </div>
        </>
      ) : (!all.loading && !all.error ? <div className="msg">no rows for this workload and view.</div> : null)}
    </ViewFrame>
  );
}
