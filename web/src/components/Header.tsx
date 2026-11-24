import type { ApiState } from "../lib/api";
import type { Meta } from "../lib/types";
import { caveatTags } from "../lib/mappers";
import { shortSha } from "../lib/format";

const WANTED = /^(Single machine|Scripted workloads|One cipher suite)/;

/** Persistent header: data source, the commit that produced the results, and a link to the caveats. */
export function Header({ meta }: { meta: ApiState<Meta> }) {
  const m = meta.data;
  const p = m?.provenance;
  const tags = m ? caveatTags(m.caveats, m.caveats.length).filter((t) => WANTED.test(t)) : [];
  return (
    <header className="top">
      <div className="top-main">
        <span className="brand">PQ-DRIFTLAB</span>
        <span className="mid small">handshake size, flow-feature drift and intrusion-detector error in post-quantum TLS</span>
      </div>
      <div className="top-meta mono">
        {meta.error ? <span className="warn">API not reachable: {meta.error}</span> : null}
        {meta.loading ? "reading /api/meta ..." : null}
        {p ? (
          <>
            <span>data: <b>{p.synthetic ? "SYNTHETIC test fixture, not lab data" : "real lab captures"}</b></span>
            {tags.map((t) => <span key={t}><span className="sep">·</span>{t.toLowerCase()}</span>)}
            <span className="sep">|</span>
            <span>results from commit: <b>{shortSha(p.results_code_commit)}</b></span>
            <span className="sep">|</span>
            <span>served by: {shortSha(p.served_by_commit)}</span>
            <span className="sep">|</span>
            <a href="#caveats">caveats</a>
          </>
        ) : null}
      </div>
    </header>
  );
}
