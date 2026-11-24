import type { ApiState } from "../lib/api";
import type { Meta } from "../lib/types";
import { commitLabel, shortSha } from "../lib/format";
import type { Provenance } from "../lib/types";

/** Hover text: the commit recorded for each source file ("unknown" where the file has no sidecar). */
export const commitTitle = (p: Provenance): string =>
  Object.entries(p.results_files).map(([f, m]) => `${f}: ${m ? m.code_commit : "unknown (generated before tracking)"}`).join("; ");

export const VIEWS = [
  ["ladder", "Handshake ladder"],
  ["drift", "Feature drift"],
  ["detectors", "Detectors and mix"],
  ["replay", "Replay"],
  ["caveats", "Caveats"],
] as const;
export type ViewId = (typeof VIEWS)[number][0];

export function TopBar({ meta }: { meta: ApiState<Meta> }) {
  const p = meta.data?.provenance;
  return (
    <header className="top">
      <span className="brand">PQ-DRIFTLAB</span>
      {p ? <span className={p.synthetic ? "chip warn" : "chip"}>{p.synthetic ? "SYNTHETIC test fixture, not lab data" : "real lab captures"}</span> : null}
      {p ? <span className="dim" title={commitTitle(p)}>results commit: <span style={{ color: "var(--ink)" }}>{commitLabel(p.results_code_commit)}</span></span> : null}
      <span className="grow" />
      <span className="dim hide-s">read-only view of stored results</span>
    </header>
  );
}

export function Rail({ view, onPick }: { view: ViewId; onPick: (v: ViewId) => void }) {
  return (
    <nav className="rail" aria-label="views">
      <div className="strip"><b>views</b></div>
      {VIEWS.map(([id, label], i) => (
        <button key={id} type="button" className={view === id ? "tab on" : "tab"} onClick={() => onPick(id)} aria-current={view === id ? "page" : undefined}>
          <kbd>{i + 1}</kbd><span>{label}</span>
        </button>
      ))}
      <p className="note">Nothing here starts a capture, runs a command or writes a file.</p>
    </nav>
  );
}

export function StatusBar({ meta, onCaveats }: { meta: ApiState<Meta>; onCaveats: () => void }) {
  const p = meta.data?.provenance;
  const state = meta.error ? "not reachable" : meta.loading ? "connecting" : "connected";
  return (
    <footer className="status">
      <span>api: <span className={meta.error ? "sig" : ""} style={meta.error ? undefined : { color: "var(--ink)" }}>{state}</span></span>
      {p ? <span>served by: {shortSha(p.served_by_commit)}</span> : null}
      {p ? <span className="hide-s" title={commitTitle(p)}>results commit: {commitLabel(p.results_code_commit)}</span> : null}
      <span className="grow" />
      <span className="hide-s dim">keys 1-5 switch views</span>
      <a href="#caveats" onClick={(e) => { e.preventDefault(); onCaveats(); }}>caveats</a>
    </footer>
  );
}
