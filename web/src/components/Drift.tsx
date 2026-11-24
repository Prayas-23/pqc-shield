import { useEffect, useMemo, useState } from "react";
import { useApi } from "../lib/api";
import type { DriftResponse } from "../lib/types";
import { cellKey, driftMatrix, heatSummary, intensity, metricsForView } from "../lib/mappers";
import type { DriftMetric, HeatCell } from "../lib/mappers";
import { fmtInt, fmtNum, fmtP } from "../lib/format";
import { Section, Select, Source, Status } from "./Common";

const metricLabel: Record<DriftMetric, string> = {
  psi: "population stability index (PSI)", eta2: "eta squared", mmd2: "MMD squared", partial_eta2: "partial eta squared",
};
const viewLabel: Record<string, string> = { hs: "handshake phase (hs_)", app: "application phase (app_)", flow: "whole connection (flow_)" };

function cellStyle(c: HeatCell | undefined, vmax: number, hasFloor: boolean): { className: string; background?: string } {
  if (!c || c.value === null) return { className: "cell na" };
  if (hasFloor && c.above === false) return { className: "cell", background: "var(--wash)" };
  const a = 0.18 + 0.82 * intensity(c.value, vmax);
  return { className: "cell", background: `color-mix(in srgb, var(--signal) ${Math.round(a * 100)}%, var(--bg))` };
}

export function DriftScreen() {
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

  return (
    <Section id="drift" no={2} title="Drift of flow features across profiles"
      lede="Each cell compares one feature of one profile with the same feature of the classical reference profile, in the same workload. The shaded value is an effect size; grey means it lies within the noise floor of shuffled profile labels.">
      <div className="controls">
        <Select label="workload" value={workload} options={workloads} onChange={setWorkload} />
        <Select label="feature view" value={view} options={views} onChange={setView} />
        <Select label="effect size" value={m} options={metrics} onChange={(v) => setMetric(v as DriftMetric)} />
      </div>
      <Status loading={all.loading} error={all.error} what="/api/drift" />
      {matrix && matrix.features.length > 0 ? (
        <div className="fig">
          <div className="scroll-x chart">
            <table className="heat" aria-label="effect size by feature and profile">
              <thead>
                <tr>
                  <th style={{ border: 0 }} />
                  {matrix.columns.map((c) => <th key={c} className="col" scope="col"><span>{c}</span></th>)}
                </tr>
              </thead>
              <tbody>
                {matrix.features.map((f) => (
                  <tr key={f}>
                    <th className="rowh" scope="row">{f}</th>
                    {matrix.columns.map((c) => {
                      const x = matrix.cells.get(cellKey(f, c));
                      const st = cellStyle(x, matrix.vmax, matrix.hasFloor);
                      const isSel = sel && sel.feature === f && sel.column === c;
                      return (
                        <td key={c}>
                          <button type="button" className={`${st.className}${isSel ? " sel" : ""}`} style={{ background: st.background }}
                            title={`${f} | ${c}: ${fmtNum(x?.value, 4)}${x?.floor != null ? ` (noise floor ${fmtNum(x.floor, 4)})` : ""}`}
                            disabled={!x || x.value === null} onClick={() => x && setSel(x)} aria-label={`${f}, ${c}`} />
                        </td>
                      );
                    })}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="margin">
            <p><b>{viewLabel[view] ?? view}</b>, {metricLabel[m]}.</p>
            <p>
              <span className="swatch" style={{ background: "var(--signal)" }} />above the noise floor, darker = larger.<br />
              <span className="swatch" style={{ background: "var(--wash)" }} />within the noise floor.<br />
              <span className="swatch" style={{ boxShadow: "inset 0 0 0 1px var(--rule)" }} />n/a: the API gives no value.
            </p>
            {!matrix.hasFloor ? <p>No noise floor is available for this view and effect size (n/a), so no cell is marked as noise.</p> : null}
            {sum && matrix?.hasFloor ? (
              <p><b>{fmtInt(sum.above)} of {fmtInt(sum.total - sum.na)}</b> cells exceed the noise floor.{sum.weakest ? <> Fewest in <span className="mono">{sum.weakest.feature}</span>: {fmtInt(sum.weakest.above)} of {fmtInt(sum.weakest.n)}.</> : null}</p>
            ) : null}
            <p>Largest value in this view: <span className="mono">{fmtNum(matrix.vmax, 3)}</span>. Click a cell for its numbers.</p>
            {cell ? (
              <table>
                <tbody>
                  <tr><td colSpan={2}><b className="mono">{cell.feature}</b><br /><span className="mono small">{cell.column}</span></td></tr>
                  {([["eta squared", cell.row.eta2], ["partial eta squared", cell.row.partial_eta2], ["PSI", cell.row.psi], ["MMD squared", cell.row.mmd2]] as const).map(([k, v]) => (
                    <tr key={k}><td>{k}</td><td className="num">{fmtNum(v, 4)}</td></tr>
                  ))}
                  <tr><td>MMD p-value</td><td className="num">{fmtP(cell.row.mmd2_p_value)}</td></tr>
                  <tr><td>noise floor, eta squared</td><td className="num">{fmtNum(cell.row.noise95_eta2, 4)}</td></tr>
                  <tr><td>noise floor, PSI</td><td className="num">{fmtNum(cell.row.noise95_max_psi, 4)}</td></tr>
                  <tr><td>flows, reference</td><td className="num">{fmtInt(cell.row.n_ref)}</td></tr>
                  <tr><td>flows, compared</td><td className="num">{fmtInt(cell.row.n_group)}</td></tr>
                  {cell.row.note ? <tr><td colSpan={2} className="small">{cell.row.note}</td></tr> : null}
                </tbody>
              </table>
            ) : null}
          </div>
        </div>
      ) : (!all.loading && !all.error ? <div className="status">no rows for this workload and view.</div> : null)}
      <p className="caption">
        Confidence intervals: n/a. The API gives point effect sizes and a permutation noise floor, not intervals.
        Columns of the handshake view are model terms (key exchange, signature, their interaction) instead of profiles.
      </p>
      <Source prov={all.data?.provenance} />
    </Section>
  );
}
