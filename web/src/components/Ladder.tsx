import { useMemo, useState } from "react";
import { useApi } from "../lib/api";
import type { Ladder as LadderT, Meta } from "../lib/types";
import { ladderDelta, parseProfile, profileOptions, profileString, sequenceSteps } from "../lib/mappers";
import type { SequenceStep } from "../lib/mappers";
import { fmtBytes, fmtInt, fmtPct, fmtSigned } from "../lib/format";
import { Section, Select, Source, Status } from "./Common";

function Sequence({ steps, shifted }: { steps: SequenceStep[]; shifted: boolean }) {
  const W = 640, top = 46, row = 44, xc = 70, xs = W - 70;
  const H = top + steps.length * row + 10;
  const bar = shifted ? "var(--signal)" : "var(--ink)";
  return (
    <svg className="seq" viewBox={`0 0 ${W} ${H}`} width="100%" role="img" aria-label="handshake messages between client and server, with bytes and packets">
      <defs>
        <marker id="head" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
          <path d="M0,1 L7,4 L0,7" fill="none" stroke="var(--ink)" strokeWidth="1" />
        </marker>
      </defs>
      <text x={xc} y={18} textAnchor="middle">client</text>
      <text x={xs} y={18} textAnchor="middle">server</text>
      <line className="life" x1={xc} x2={xc} y1={26} y2={H} />
      <line className="life" x1={xs} x2={xs} y1={26} y2={H} />
      {steps.map((s, i) => {
        const y = top + i * row;
        const toServer = s.direction === "C->S";
        const x1 = toServer ? xc : xs, x2 = toServer ? xs : xc;
        const len = xs - xc, w = Math.max(len * s.share, 2);
        return (
          <g key={s.step}>
            <title>{`${s.step}: ${fmtBytes(s.bytes)}, ${s.packets} packet(s) at the lab segment size`}</title>
            <text x={(xc + xs) / 2} y={y - 7} textAnchor="middle">{s.step}</text>
            <line className="arrow" x1={x1} x2={x2} y1={y} y2={y} markerEnd="url(#head)" />
            <rect x={toServer ? xc : xs - w} y={y + 4} width={w} height={3} fill={bar} />
            <text className="m" x={(xc + xs) / 2} y={y + 19} textAnchor="middle">{fmtBytes(s.bytes)} · {fmtInt(s.packets)} pkt</text>
          </g>
        );
      })}
    </svg>
  );
}

export function LadderScreen({ meta }: { meta: Meta }) {
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
  const sel = useApi<LadderT>(exists ? q({ kem, auth, chain }) : null);
  const ref = useApi<LadderT>(q(parseProfile(meta.classical_profile)));
  const isRef = profile === meta.classical_profile;
  const d = sel.data, r = ref.data;
  const deltas = d && r ? ladderDelta(d, r) : null;

  return (
    <Section id="ladder" no={1} title="Handshake: model and observed sizes"
      lede="One TLS 1.3 handshake per profile. The diagram is the size model's message ladder; the table sets the model's server and client flights against the median of the lab flows.">
      <div className="controls">
        <Select label="key exchange" value={kem} options={opts.kems} onChange={setKem} />
        <Select label="signature" value={auth} options={opts.auths} onChange={setAuth} />
        <Select label="certificate chain" value={chain} options={opts.chains} onChange={setChain} />
        <label><input type="checkbox" checked={measured} onChange={(e) => setMeasured(e.target.checked)} /> measured certificate overhead</label>
      </div>
      {!exists ? <div className="status">no lab capture for {profile}; pick another combination.</div> : null}
      <Status loading={sel.loading} error={sel.error} what="/api/ladder" />
      {d ? (
        <div className="fig">
          <div>
            <Sequence steps={sequenceSteps(d)} shifted={!isRef} />
            <p className="caption">
              Bar under each arrow: message size relative to the largest message of this profile. Packets are per message at the lab
              segment size of {fmtBytes(d.mss)}; a real flight coalesces messages, so packet counts do not add up to the flight.
            </p>
          </div>
          <div className="margin">
            <p><b>{profile}</b></p>
            <p>
              Per-certificate overhead in the model: <span className="mono">{fmtBytes(d.model.o_cert_bytes)}</span>
              {" "}({d.model.cert_overhead === "measured" ? "measured on the lab's certificate files" : "model default, not tuned"}).
            </p>
            <p>Observed values are the median of <span className="mono">{fmtInt(d.observed.n_flows)}</span> lab flows.</p>
          </div>
        </div>
      ) : null}

      {d ? (
        <>
          <h3>Server and client flight, bytes</h3>
          <div className="scroll-x">
            <table>
              <thead><tr><th>direction</th><th className="num">observed, median</th><th className="num">model</th><th className="num">observed - model</th><th className="num">as share of observed</th></tr></thead>
              <tbody>
                {([["server to client", d.comparison.server_to_client_bytes], ["client to server", d.comparison.client_to_server_bytes]] as const).map(([name, c]) => (
                  <tr key={name}>
                    <td>{name}</td><td className="num">{fmtBytes(c.observed)}</td><td className="num">{fmtBytes(c.model)}</td>
                    <td className="num">{fmtSigned(c.difference, " B")}</td>
                    <td className="num">{c.difference_pct_of_observed === null ? "n/a" : fmtPct(c.difference_pct_of_observed / 100)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <h3>Against the classical reference ({meta.classical_profile})</h3>
          <Status loading={ref.loading} error={ref.error} what="the reference ladder" />
          {deltas ? (
            <div className="scroll-x">
              <table>
                <thead><tr><th>direction</th><th className="num">observed difference</th><th className="num">model difference</th><th className="num">observed - model</th></tr></thead>
                <tbody>
                  {deltas.map((x) => (
                    <tr key={x.direction}>
                      <td>{x.direction}</td><td className="num">{fmtSigned(x.observed, " B")}</td>
                      <td className="num">{fmtSigned(x.model, " B")}</td><td className="num">{fmtSigned(x.residual, " B")}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : null}
          <p className="caption">
            Absolute model and observed sizes differ because the model's fixed overheads are defaults. The difference rows subtract the
            reference profile from both, which removes that shared offset; read the last column to see how far the model's
            profile-to-profile difference is from the observed one. The toggle swaps the default certificate overhead for the value
            measured on the lab's certificate files.
          </p>
        </>
      ) : null}
      <Source prov={d?.provenance} />
    </Section>
  );
}
