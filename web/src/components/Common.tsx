import { useEffect, useRef, useState } from "react";
import type { ReactNode } from "react";
import type { Provenance } from "../lib/types";
import { shortSha } from "../lib/format";

/** One view: workspace on the left (large title, collapsible help, body, source footer) and a docked control panel on the right. */
export function ViewFrame({ title, help, controls, children, prov, status }: {
  title: string; help: ReactNode; controls: ReactNode; children: ReactNode; prov?: Provenance | null; status?: ReactNode;
}) {
  const [open, setOpen] = useState(false);
  return (
    <div className="view">
      <section className="workspace" aria-label={title}>
        <div className="titlebar">
          <h1>{title}</h1>
          {status ? <span className="sub">{status}</span> : null}
          <span className="grow" />
          <button type="button" className={open ? "btn-ghost on" : "btn-ghost"} aria-expanded={open} onClick={() => setOpen(!open)}>{open ? "hide help" : "help"}</button>
        </div>
        {open ? <div className="help prose">{help}</div> : null}
        <div className="wbody">
          {children}
          <Source prov={prov} />
        </div>
      </section>
      <aside className="controls" aria-label={`${title}: controls`}>
        <div className="chead">controls</div>
        <div className="body">{controls}</div>
      </aside>
    </div>
  );
}

export function Source({ prov }: { prov: Provenance | null | undefined }) {
  if (!prov) return <div className="foot">source: n/a</div>;
  return (
    <div className="foot" title={prov.source_files.join(", ")}>
      source: {prov.source_files.join(", ")} | results commit: {shortSha(prov.results_code_commit)}{prov.synthetic ? " | SYNTHETIC fixture, not lab data" : ""}
    </div>
  );
}

export function Field({ label, children }: { label: string; children: ReactNode }) {
  return <label className="field"><span>{label}</span>{children}</label>;
}

export function Select({ label, value, options, onChange, format }: {
  label: string; value: string; options: string[]; onChange: (v: string) => void; format?: (o: string) => string;
}) {
  return (
    <Field label={label}>
      <select value={value} onChange={(e) => onChange(e.target.value)}>
        {options.map((o) => <option key={o} value={o}>{format ? format(o) : o}</option>)}
      </select>
    </Field>
  );
}

// ---------------------------------------------------------------- designed loading / error / empty states
export function SkelRows({ n = 8, widths }: { n?: number; widths?: number[] }) {
  return (
    <div className="skel-rows" aria-busy="true" aria-label="loading">
      {Array.from({ length: n }, (_, i) => <div key={i} className="skel" style={{ height: 14, width: `${widths?.[i % widths.length] ?? 60 + ((i * 17) % 40)}%`, animationDelay: `${i * 90}ms` }} />)}
    </div>
  );
}

export function SkelGrid({ rows = 10, cols = 14 }: { rows?: number; cols?: number }) {
  return (
    <div className="skel-grid" aria-busy="true" aria-label="loading" style={{ gridTemplateColumns: `repeat(${cols}, 1fr)`, gridTemplateRows: `repeat(${rows}, 1fr)` }}>
      {Array.from({ length: rows * cols }, (_, i) => <div key={i} className="skel" style={{ animationDelay: `${((i % cols) + Math.floor(i / cols)) * 40}ms` }} />)}
    </div>
  );
}

export function SkelBlock({ height = 160 }: { height?: number }) {
  return <div className="skel" aria-busy="true" aria-label="loading" style={{ height, width: "100%" }} />;
}

/** Error box, or `fallback` while loading (a skeleton shaped like the content that is coming). */
export function Msg({ loading, error, what, fallback }: { loading: boolean; error: string | null; what: string; fallback?: ReactNode }) {
  if (error) return <div className="err" role="alert">could not read {what}: {error}</div>;
  if (loading) return <>{fallback ?? <SkelRows />}</>;
  return null;
}

/** Observe the pixel size of an element (SVG charts are drawn at their real size so text stays crisp). */
export function useSize<T extends HTMLElement>(): [React.RefObject<T | null>, { w: number; h: number }] {
  const ref = useRef<T | null>(null);
  const [size, setSize] = useState({ w: 0, h: 0 });
  useEffect(() => {
    if (!ref.current) return;
    const el = ref.current;
    const ro = new ResizeObserver(() => setSize({ w: el.clientWidth, h: el.clientHeight }));
    ro.observe(el);
    setSize({ w: el.clientWidth, h: el.clientHeight });
    return () => ro.disconnect();
  }, []);
  return [ref, size];
}
