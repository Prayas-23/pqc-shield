import { useState } from "react";
import type { ReactNode } from "react";
import type { Provenance } from "../lib/types";
import { shortSha } from "../lib/format";

/** One view: workspace on the left (title strip, collapsible help, body, source footer) and a docked control panel on the right. */
export function ViewFrame({ title, help, controls, children, prov, status }: {
  title: string; help: ReactNode; controls: ReactNode; children: ReactNode; prov?: Provenance | null; status?: ReactNode;
}) {
  const [open, setOpen] = useState(false);
  return (
    <div className="view">
      <section className="workspace" aria-label={title}>
        <div className="strip">
          <b>{title}</b>
          {status ? <span>{status}</span> : null}
          <span className="grow" />
          <button type="button" className={open ? "on" : ""} aria-expanded={open} onClick={() => setOpen(!open)}>{open ? "hide help" : "help"}</button>
        </div>
        {open ? <div className="help prose">{help}</div> : null}
        <div className="wbody">
          {children}
          <Source prov={prov} />
        </div>
      </section>
      <aside className="controls" aria-label={`${title}: controls`}>
        <div className="strip"><b>controls</b></div>
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

export function Msg({ loading, error, what }: { loading: boolean; error: string | null; what: string }) {
  if (error) return <div className="err" role="alert">could not read {what}: {error}</div>;
  if (loading) return <div className="msg">loading {what} ...</div>;
  return null;
}
