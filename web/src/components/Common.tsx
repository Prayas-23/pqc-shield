import type { ReactNode } from "react";
import type { Provenance } from "../lib/types";
import { shortSha } from "../lib/format";

export function Status({ loading, error, what }: { loading: boolean; error: string | null; what: string }) {
  if (error) return <div className="status err" role="alert">could not read {what}: {error}</div>;
  if (loading) return <div className="status">loading {what} ...</div>;
  return null;
}

/** Footer of every figure: the files it was drawn from and the commit that produced them. */
export function Source({ prov, note }: { prov: Provenance | null | undefined; note?: string }) {
  if (!prov) return <p className="source">source: n/a</p>;
  return (
    <p className="source">
      source: {prov.source_files.join(", ")} · results produced by: {shortSha(prov.results_code_commit)} · served by: {shortSha(prov.served_by_commit)}
      {prov.synthetic ? " · SYNTHETIC fixture, not lab data" : ""}{note ? ` · ${note}` : ""}
    </p>
  );
}

export function Section({ id, no, title, lede, children }: { id: string; no: number; title: string; lede?: ReactNode; children: ReactNode }) {
  return (
    <section className="sec" id={id}>
      <h2><span className="no">{no}</span>{title}</h2>
      {lede ? <p className="lede">{lede}</p> : null}
      {children}
    </section>
  );
}

export function Select({ label, value, options, onChange }: { label: string; value: string; options: string[]; onChange: (v: string) => void }) {
  return (
    <label>{label}
      <select value={value} onChange={(e) => onChange(e.target.value)}>
        {options.map((o) => <option key={o} value={o}>{o}</option>)}
      </select>
    </label>
  );
}
