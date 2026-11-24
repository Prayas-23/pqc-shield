import { useCallback, useEffect, useRef, useState } from "react";
import { streamUrl } from "../lib/api";
import type { Meta, StreamDone, StreamFlow, StreamHello, StreamMessage } from "../lib/types";
import { rate, shortProfile } from "../lib/mappers";
import { fmtInt, fmtNum, fmtPct } from "../lib/format";
import { Select, ViewFrame } from "./Common";

interface Feed {
  hello: StreamHello | null; recent: StreamFlow[]; done: StreamDone | null; error: string | null; open: boolean;
  benign: number; attack: number; falseAlarms: number; detections: number;
}
const EMPTY: Feed = { hello: null, recent: [], done: null, error: null, open: false, benign: 0, attack: 0, falseAlarms: 0, detections: 0 };
const KEEP = 200;                                   // rows kept in the table; the counters cover every flow received
const PANES = [
  { method: "naive", title: "naive", text: "classical-trained" },
  { method: "canon_b", title: "CANON-B", text: "naive + split-conformal correction" },
] as const;

function add(f: Feed, m: StreamMessage): Feed {
  if (m.type === "hello") return { ...f, hello: m };
  if (m.type === "done") return { ...f, done: m, open: false };
  return {
    ...f, recent: [m, ...f.recent].slice(0, KEEP),
    benign: f.benign + (m.label === "benign" ? 1 : 0), attack: f.attack + (m.label === "attack" ? 1 : 0),
    falseAlarms: f.falseAlarms + (m.label === "benign" && m.alert ? 1 : 0), detections: f.detections + (m.label === "attack" && m.alert ? 1 : 0),
  };
}

export function ReplayView({ meta }: { meta: Meta }) {
  const pq = meta.profiles.filter((p) => p !== meta.classical_profile);
  const [detector, setDetector] = useState(meta.detectors.includes("rf") ? "rf" : meta.detectors[0]!);
  const [profile, setProfile] = useState(pq[0] ?? meta.classical_profile);
  const [speed, setSpeed] = useState(50);
  const [feeds, setFeeds] = useState<Record<string, Feed>>({ naive: EMPTY, canon_b: EMPTY });
  const socks = useRef<WebSocket[]>([]);

  const closeAll = useCallback(() => {          // detach the handlers first so closing does not show up as an error
    socks.current.forEach((s) => { s.onmessage = null; s.onerror = null; s.onclose = null; s.close(); });
    socks.current = [];
  }, []);
  const stop = useCallback(() => {
    closeAll();
    setFeeds((f) => Object.fromEntries(Object.entries(f).map(([k, v]) => [k, { ...v, open: false }])));
  }, [closeAll]);
  const start = useCallback(() => {
    closeAll();
    setFeeds({ naive: { ...EMPTY, open: true }, canon_b: { ...EMPTY, open: true } });
    socks.current = PANES.map(({ method }) => {
      const ws = new WebSocket(streamUrl({ detector, method, profile, speed }));
      ws.onmessage = (ev: MessageEvent<string>) => {
        const msg = JSON.parse(ev.data) as StreamMessage;
        setFeeds((f) => ({ ...f, [method]: add(f[method]!, msg) }));
      };
      ws.onerror = () => setFeeds((f) => ({ ...f, [method]: { ...f[method]!, error: "stream connection failed", open: false } }));
      ws.onclose = (ev) => setFeeds((f) => ({ ...f, [method]: { ...f[method]!, open: false, error: f[method]!.error ?? (ev.code === 1008 ? `refused by the API: ${ev.reason || "bad parameters"}` : null) } }));
      return ws;
    });
  }, [detector, profile, speed, closeAll]);

  useEffect(() => {      // ?autostart=1 starts a replay on load (used for the screenshots in docs/screens)
    if (new URLSearchParams(window.location.search).has("autostart")) start();
    return closeAll;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const running = Object.values(feeds).some((f) => f.open);
  const hello = feeds["naive"]!.hello ?? feeds["canon_b"]!.hello;

  const controls = (
    <>
      <Select label="detector" value={detector} options={meta.detectors} onChange={setDetector} />
      <Select label="profile" value={profile} options={pq} onChange={setProfile} format={shortProfile} />
      <label className="field"><span>replay speed: <span style={{ color: "var(--ink)" }}>{speed} flows/s</span></span>
        <input type="range" min={5} max={300} step={5} value={speed} onChange={(e) => setSpeed(Number(e.target.value))} aria-label="replay speed, flows per second" />
      </label>
      <div className="btnrow">
        <button type="button" className="btn" onClick={start} disabled={running}>start</button>
        <button type="button" className="btn" onClick={stop} disabled={!running}>stop</button>
      </div>
      <div className="dim">The same recorded flows go through both detectors, so rows line up. Speed is flows per second, not recorded time.</div>
    </>
  );

  const help = (
    <>
      <p>The test-block flows of one profile are sent through a detector trained once on the classical training block, in recorded start-time order. A flag on a benign flow is a false alarm; a flag on an attack flow is a detection. The attacks are scripted attack-like workloads, not real attacks.</p>
      <p>The counters cover every flow received; the table keeps the latest rows, newest first. The CANON-B pane uses the true context of the profile (the context estimator is exact in this lab).</p>
    </>
  );

  return (
    <ViewFrame title="Replay" help={help} controls={controls} prov={hello?.provenance} status={<span>{shortProfile(profile)} · {detector}</span>}>
      <div className="banner">Replay of recorded lab captures, not live traffic.
        <span>{hello ? hello.notice.split(". ").slice(1).join(". ") : "Read from stored flows; nothing is captured."}</span></div>
      <div className="cols2">
        {PANES.map(({ method, title, text }) => {
          const f = feeds[method]!;
          const fa = rate(f.falseAlarms, f.benign), dr = rate(f.detections, f.attack);
          return (
            <section className="pane" key={method}>
              <div className="strip"><b>{title}</b><span>{text}</span><span className="grow" /><span>{f.open ? "streaming" : f.done ? `finished, ${fmtInt(f.done.n_flows)} flows` : "idle"}</span></div>
              <div className="counts">
                <div className="alert">false alarms <b>{fmtInt(f.falseAlarms)}</b>/{fmtInt(f.benign)} ({fa === null ? "n/a" : fmtPct(fa)})</div>
                <div>detections <b>{fmtInt(f.detections)}</b>/{fmtInt(f.attack)} ({dr === null ? "n/a" : fmtPct(dr)})</div>
              </div>
              {f.error ? <div className="err" role="alert">{f.error}</div> : null}
              <div className="ftable" role="log" aria-label={`${title} flows`}>
                <div className="frow head"><span className="num">#</span><span>workload</span><span>class</span><span className="num">score</span><span className="num thr">thr.</span><span>decision</span></div>
                {f.recent.length === 0 ? <div className="msg" style={{ padding: "0.4rem 0.6rem" }}>no flows yet</div> : null}
                {f.recent.map((r) => (
                  <div className="frow" key={r.index} title={`flow ${r.index}, ${r.workload} (${r.label})`}>
                    <span className="num">{fmtInt(r.index)}</span>
                    <span>{r.workload}</span>
                    <span className="dim">{r.label}</span>
                    <span className="num">{fmtNum(r.score, 4)}</span>
                    <span className="num thr dim">{fmtNum(r.threshold, 4)}</span>
                    <span className={r.alert ? (r.label === "benign" ? "alert" : "hit") : "dim"}>{r.alert ? (r.label === "benign" ? "false alarm" : "detected") : "-"}</span>
                  </div>
                ))}
              </div>
            </section>
          );
        })}
      </div>
    </ViewFrame>
  );
}
