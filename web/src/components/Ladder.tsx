import { useMemo, useState } from "react";
import { useApi } from "../lib/api";
import type { Ladder, Meta } from "../lib/types";
import { arrowThickness, ladderDelta, parseProfile, profileOptions, profileString, sequenceSteps, shortProfile } from "../lib/mappers";
import type { SequenceStep } from "../lib/mappers";
import { fmtBytes, fmtInt, fmtPct, fmtSigned } from "../lib/format";
import { Msg, Select, SkelBlock, SkelRows, ViewFrame } from "./Common";

/** Client and server lanes; arrow thickness is linear in bytes, packets travel along each arrow. Re-mounted (key) to replay. */
function Sequence({ steps, shifted }: { steps: SequenceStep[]; shifted: boolean }) {
  const W = 520, top = 62, row = 84, xc = 70, xs = W - 70;
  const H = top + steps.length * row + 6;
  const color = shifted ? "var(--amber)" : "var(--teal)";
  return (
    <svg className="seq" viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="xMidYMid meet" role="img"
      aria-label="handshake messages between client and server; arrow thickness is proportional to bytes">
      <rect className="lane" x={xc - 38} y={8} width={76} height={H - 14} rx={2} />
      <rect className="lane" x={xs - 38} y={8} width={76} height={H - 14} rx={2} />
      <text x={xc} y={26} textAnchor="middle">client</text>
      <text x={xs} y={26} textAnchor="middle">server</text>
      <line className="rail-l" x1={xc} x2={xc} y1={34} y2={H - 8} />
      <line className="rail-l" x1={xs} x2={xs} y1={34} y2={H - 8} />
      {steps.map((s, i) => {
        const y = top + i * row;
        const toServer = s.direction === "C->S";
        const x1 = toServer ? xc : xs, x2 = toServer ? xs : xc;
        const dir = toServer ? 1 : -1;
        const t = arrowThickness(s.bytes);
        const hh = Math.max(6, t / 2 + 4);
        const len = Math.abs(x2 - x1) - 11;
        const bx = toServer ? x1 : x1 - len;
        const nPkt = Math.min(Math.max(s.packets, 1), 6);
        return (
          <g key={s.step} style={{ "--i": i } as React.CSSProperties}>
            <title>{`${s.step}: ${fmtBytes(s.bytes)}, ${s.packets} packet(s) at the lab segment size`}</title>
            <text className="lab" x={(xc + xs) / 2} y={y - t / 2 - 9} textAnchor="middle">{s.step}</text>
            <rect className={`beam ${toServer ? "from-l" : "from-r"}`} x={bx} y={y - t / 2} width={len} height={t} fill={color} opacity={0.88} />
            <polygon className="head" points={`${x2},${y} ${x2 - dir * 12},${y - hh} ${x2 - dir * 12},${y + hh}`} fill={color} />
            {Array.from({ length: nPkt }, (_, p) => (
              <circle key={p} className="pkt" cx={x1 + dir * 16} cy={y} r={Math.max(2.6, t / 2 + 0.8)} fill="var(--ink)"
                style={{ "--i": i, "--p": p, "--dx": `${dir * (Math.abs(x2 - x1) - 34)}px` } as React.CSSProperties} />
            ))}
            <text className="m bytes lab" x={(xc + xs) / 2} y={y + t / 2 + 17} textAnchor="middle">{fmtBytes(s.bytes)} · {fmtInt(s.packets)} pkt</text>
          </g>
        );
      })}
    </svg>
  );
}

export function LadderView({ meta }: { meta: Meta }) {
  const opts = useMemo(() => profileOptions(meta.profiles), [meta.profiles]);
  const start = parseProfile([...meta.profiles].reverse().find((p) => p !== meta.classical_profile) ?? meta.classical_profile);   // a large-flight profile shows the thickness scale
  const [kem, setKem] = useState(start.kem);
  const [auth, setAuth] = useState(start.auth);
  const [chain, setChain] = useState(start.chain);
  const [measured, setMeasured] = useState(false);
  const [play, setPlay] = useState(0);
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
  const s2c = d?.comparison.server_to_client_bytes;

  const controls = (
    <>
      <Select label="key exchange" value={kem} options={opts.kems} onChange={(v) => { setKem(v); setPlay((n) => n + 1); }} />
      <Select label="signature" value={auth} options={opts.auths} onChange={(v) => { setAuth(v); setPlay((n) => n + 1); }} />
      <Select label="certificate chain" value={chain} options={opts.chains} onChange={(v) => { setChain(v); setPlay((n) => n + 1); }} />
      <label className="check"><input type="checkbox" checked={measured} onChange={(e) => { setMeasured(e.target.checked); setPlay((n) => n + 1); }} />measured certificate overhead</label>
      <div className="btnrow"><button type="button" className="btn primary" onClick={() => setPlay((n) => n + 1)}>replay animation</button></div>
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
      <p>The diagram is the size model's message ladder for one TLS 1.3 handshake. Each arrow's thickness is proportional to the message's bytes (a fixed drawing scale), and the dots are its packets at the lab segment size; a real flight coalesces messages, so packet counts do not add up to the flight.</p>
      <p>Observed values are the median handshake-phase payload of the lab flows. Absolute model and observed sizes differ because the model's fixed overheads are defaults. The second table subtracts the classical reference profile from both, which removes that shared offset; the last column shows how far the model's profile-to-profile difference is from the observed one. The overhead toggle swaps the default per-certificate overhead for the value measured on the lab's own certificate files. The animation plays on selection and with the replay button.</p>
    </>
  );

  return (
    <ViewFrame title="Handshake ladder" help={help} controls={controls} prov={d?.provenance} status={<span>{shortProfile(profile)}</span>}>
      {!exists ? <div className="empty">No lab capture for {shortProfile(profile)}. Pick another combination.</div> : null}
      <Msg loading={sel.loading && !d} error={sel.error} what="/api/ladder" fallback={<div className="ladder"><SkelBlock height={380} /><SkelRows n={6} /></div>} />
      {d ? (
        <div className="ladder">
          <div className="seqwrap">
            <p className="one">Messages of one handshake. Arrow thickness is proportional to bytes.</p>
            <Sequence key={`${profile}-${mode}-${play}`} steps={sequenceSteps(d)} shifted={!isRef} />
          </div>
          <div className="side">
            {s2c ? (
              <div className="figs">
                <div className="fig"><span className="v" style={{ color: isRef ? "var(--teal)" : "var(--amber)" }}>{fmtInt(s2c.observed)}<small>B</small></span><span className="l">server flight, observed</span></div>
                <div className="fig"><span className="v">{fmtInt(s2c.model)}<small>B</small></span><span className="l">server flight, model</span></div>
              </div>
            ) : null}
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
            <div className="sect" title={meta.classical_profile}>minus the classical reference, bytes</div>
            <Msg loading={ref.loading && !r} error={ref.error} what="the reference ladder" fallback={<SkelRows n={3} />} />
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
            <p className="dim">reference: {shortProfile(meta.classical_profile)}. Units: bytes; s to c = server to client.</p>
          </div>
        </div>
      ) : null}
    </ViewFrame>
  );
}
