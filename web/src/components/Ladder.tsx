import { useMemo, useState } from "react";
import { useApi } from "../lib/api";
import type { Ladder, Meta } from "../lib/types";
import { ladderDelta, parseProfile, profileOptions, profileString, sequenceSteps, shortProfile } from "../lib/mappers";
import type { SequenceStep } from "../lib/mappers";
import { fmtBytes, fmtInt, fmtPct, fmtSigned } from "../lib/format";
import { Msg, Select, ViewFrame } from "./Common";

function Sequence({ steps, shifted }: { steps: SequenceStep[]; shifted: boolean }) {
  const W = 520, top = 46, row = 86, xc = 64, xs = W - 64;
  const H = top + steps.length * row + 8;
  const bar = shifted ? "var(--signal)" : "var(--g1)";
  return (
    <svg className="seq" viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="xMidYMid meet" role="img"
      aria-label="handshake messages between client and server, with bytes and packets">
      <defs>
        <marker id="head" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
          <path d="M0,1 L7,4 L0,7" fill="none" stroke="var(--g2)" strokeWidth="1" />
        </marker>
      </defs>
      <text x={xc} y={16} textAnchor="middle">client</text>
      <text x={xs} y={16} textAnchor="middle">server</text>
      <line className="life" x1={xc} x2={xc} y1={24} y2={H} />
      <line className="life" x1={xs} x2={xs} y1={24} y2={H} />
      {steps.map((s, i) => {
        const y = top + i * row;
        const toServer = s.direction === "C->S";
        const x1 = toServer ? xc : xs, x2 = toServer ? xs : xc;
        const len = xs - xc, w = Math.max(len * s.share, 2);
        return (
          <g key={s.step}>
            <title>{`${s.step}: ${fmtBytes(s.bytes)}, ${s.packets} packet(s) at the lab segment size`}</title>
            <text x={(xc + xs) / 2} y={y - 8} textAnchor="middle">{s.step}</text>
            <line className="arrow" x1={x1} x2={x2} y1={y} y2={y} markerEnd="url(#head)" />
            <rect x={toServer ? xc : xs - w} y={y + 5} width={w} height={3} fill={bar} />
            <text className="m" x={(xc + xs) / 2} y={y + 24} textAnchor="middle">{fmtBytes(s.bytes)} · {fmtInt(s.packets)} pkt</text>
          </g>
        );
      })}
    </svg>
  );
}

export function LadderView({ meta }: { meta: Meta }) {
  const opts = useMemo(() => profileOptions(meta.profiles), [meta.profiles]);
  const start = parseProfile(meta.profiles.find((p) => p !== meta.classical_profile) ?? meta.classical_profile);
  const [kem, setKem] = useState(start.kem);
  const [auth, setAuth] = useState(start.auth);
  const [chain, setChain] = useState(start.chain);
  const [measured, setMeasured] = useState(false);
  const profile = profileString({ kem, auth, chain });
  const exists = meta.profiles.includes(profile);
  const mode = measured ? "measured" : "default";
  const q = (p: { kem: string; auth: string; chain: string }) =>
    `/api/ladder?kem=${encodeURIComponent(p.kem)}&auth=${encodeURIComponent(p.auth)}&chain=${encodeURIComponent(p.chain)}&cert_overhead=${mode}`;
  const sel = useApi<Ladder>(exists ? q({ kem, auth, chain }) : null);
  const ref = useApi<Ladder>(q(parseProfile(meta.classical_profile)));
  const d = sel.data, r = ref.data;
  const deltas = d && r ? ladderDelta(d, r) : null;
  const isRef = profile === meta.classical_profile;

  const controls = (
    <>
      <Select label="key exchange" value={kem} options={opts.kems} onChange={setKem} />
      <Select label="signature" value={auth} options={opts.auths} onChange={setAuth} />
      <Select label="certificate chain" value={chain} options={opts.chains} onChange={setChain} />
      <label className="check"><input type="checkbox" checked={measured} onChange={(e) => setMeasured(e.target.checked)} />measured certificate overhead</label>
      {d ? (
        <table className="kv"><tbody>
          <tr><td>per-certificate overhead</td><td className="num">{fmtBytes(d.model.o_cert_bytes)}</td></tr>
          <tr><td>overhead source</td><td className="num">{d.model.cert_overhead === "measured" ? "lab certificates" : "model default"}</td></tr>
          <tr><td>lab flows, median of</td><td className="num">{fmtInt(d.observed.n_flows)}</td></tr>
          <tr><td>segment size</td><td className="num">{fmtBytes(d.mss)}</td></tr>
        </tbody></table>
      ) : null}
    </>
  );

  const help = (
    <>
      <p>The diagram is the size model's message ladder for one TLS 1.3 handshake. The bar under each arrow is that message's size relative to the largest message of the profile. Packet counts are per message at the lab segment size; a real flight coalesces messages, so they do not add up to the flight.</p>
      <p>Observed values are the median handshake-phase payload of the lab flows. Absolute model and observed sizes differ because the model's fixed overheads are defaults. The second table subtracts the classical reference profile from both, which removes that shared offset; the last column shows how far the model's profile-to-profile difference is from the observed one. The overhead toggle swaps the default per-certificate overhead for the value measured on the lab's own certificate files.</p>
    </>
  );

  return (
    <ViewFrame title="Handshake ladder" help={help} controls={controls} prov={d?.provenance} status={<span>{shortProfile(profile)}</span>}>
      {!exists ? <div className="msg">no lab capture for {shortProfile(profile)}; pick another combination.</div> : null}
      <Msg loading={sel.loading && !d} error={sel.error} what="/api/ladder" />
      {d ? (
        <div className="ladder">
          <div className="seqwrap">
            <p className="one">Messages of one handshake, client to server and back, with bytes and packets.</p>
            <Sequence steps={sequenceSteps(d)} shifted={!isRef} />
          </div>
          <div className="side">
            <div className="sect">server and client flight, bytes</div>
            <table className="dense">
              <thead><tr><th /><th className="num">observed</th><th className="num">model</th><th className="num">obs - model</th><th className="num">%</th></tr></thead>
              <tbody>
                {([["s to c", d.comparison.server_to_client_bytes], ["c to s", d.comparison.client_to_server_bytes]] as const).map(([name, c]) => (
                  <tr key={name}>
                    <td>{name}</td><td className="num">{fmtInt(c.observed)}</td><td className="num">{fmtInt(c.model)}</td>
                    <td className="num">{fmtSigned(c.difference)}</td>
                    <td className="num">{c.difference_pct_of_observed === null ? "n/a" : fmtPct(c.difference_pct_of_observed / 100)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            <div className="sect" style={{ marginTop: "0.9rem" }} title={meta.classical_profile}>minus the classical reference, bytes</div>
            <Msg loading={ref.loading && !r} error={ref.error} what="the reference ladder" />
            {deltas ? (
              <table className="dense">
                <thead><tr><th /><th className="num">observed</th><th className="num">model</th><th className="num">obs - model</th></tr></thead>
                <tbody>
                  {deltas.map((x) => (
                    <tr key={x.direction}>
                      <td>{x.direction === "server to client" ? "s to c" : "c to s"}</td>
                      <td className="num">{fmtSigned(x.observed)}</td><td className="num">{fmtSigned(x.model)}</td><td className="num">{fmtSigned(x.residual)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : null}
            <p className="dim" style={{ marginTop: "0.7rem" }}>reference: {shortProfile(meta.classical_profile)}. Units: bytes; s to c = server to client.</p>
          </div>
        </div>
      ) : null}
    </ViewFrame>
  );
}
