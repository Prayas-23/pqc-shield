import { useCallback, useEffect, useRef, useState } from "react";
import { streamUrl } from "../lib/api";
import type { Meta, StreamDone, StreamFlow, StreamHello, StreamMessage } from "../lib/types";
import { rate } from "../lib/mappers";
import { fmtInt, fmtNum, fmtPct } from "../lib/format";
import { Section, Select, Source } from "./Common";

interface Feed {
  hello: StreamHello | null; recent: StreamFlow[]; done: StreamDone | null; error: string | null; open: boolean;
  benign: number; attack: number; falseAlarms: number; detections: number;
}
const EMPTY: Feed = { hello: null, recent: [], done: null, error: null, open: false, benign: 0, attack: 0, falseAlarms: 0, detections: 0 };
const KEEP = 150;                                   // rows kept in the list; the counters cover every flow received
const PANELS = [
  { method: "naive", title: "naive", text: "trained and thresholded on the classical profile" },
  { method: "canon_b", title: "CANON-B", text: "naive plus the k-shot split-conformal correction" },
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

export function ReplayScreen({ meta }: { meta: Meta }) {
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
    socks.current = PANELS.map(({ method }) => {
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

  return (
    <Section id="replay" no={4} title="Replay of recorded flows through two detectors"
      lede="The test-block flows of one profile are sent through a detector trained once on the classical training block, in recorded start-time order. The same flows go through both detectors, so rows line up.">
      <div className="replay-banner">
        <b>Replay of recorded lab captures, not live traffic.</b>{" "}
        <span className="mid small">{hello ? hello.notice.split(". ").slice(1).join(". ") : "The stream is read from stored flows; nothing is captured."}</span>
      </div>
      <div className="controls">
        <Select label="detector" value={detector} options={meta.detectors} onChange={setDetector} />
        <Select label="profile" value={profile} options={pq} onChange={setProfile} />
        <label>replay speed
          <input type="range" min={5} max={300} step={5} value={speed} onChange={(e) => setSpeed(Number(e.target.value))} aria-label="replay speed, flows per second" />
          <span className="mono">{speed} flows/s</span>
        </label>
        <button type="button" className="plain" onClick={start} disabled={running}>start replay</button>
        <button type="button" className="plain" onClick={stop} disabled={!running}>stop</button>
      </div>
      <div className="cols2">
        {PANELS.map(({ method, title, text }) => {
          const f = feeds[method]!;
          const fa = rate(f.falseAlarms, f.benign), det = rate(f.detections, f.attack);
          return (
            <div key={method}>
              <h3 style={{ marginTop: 0 }}>{title} <span className="mid small" style={{ fontWeight: 400 }}>{text}</span></h3>
              {f.error ? <div className="status err" role="alert">{f.error}</div> : null}
              <div className="counts">
                <div><span>false alarms, benign flows</span><span><b>{fmtInt(f.falseAlarms)}</b> / {fmtInt(f.benign)} ({fa === null ? "n/a" : fmtPct(fa)})</span></div>
                <div><span>detections, attack flows</span><span><b>{fmtInt(f.detections)}</b> / {fmtInt(f.attack)} ({det === null ? "n/a" : fmtPct(det)})</span></div>
                <div><span>status</span><span>{f.open ? "streaming" : f.done ? `finished, ${fmtInt(f.done.n_flows)} flows` : "idle"}</span></div>
              </div>
              <div className="flows" role="log" aria-label={`${title} flows`}>
                {f.recent.length === 0 ? <div className="mid" style={{ padding: "0.4rem 0" }}>no flows yet</div> : null}
                {f.recent.map((r) => (
                  <div className="flowrow" key={r.index} title={`flow ${r.index}, ${r.workload}, score ${fmtNum(r.score, 4)}, threshold ${fmtNum(r.threshold, 4)}`}>
                    <span className="num">{fmtInt(r.index)}</span>
                    <span>{r.workload} <span className="mid">({r.label})</span></span>
                    <span className="num">{fmtNum(r.score, 4)}</span>
                    <span className={r.alert ? (r.label === "benign" ? "alert" : "hit") : "mid"}>{r.alert ? (r.label === "benign" ? "false alarm" : "detected") : "-"}</span>
                  </div>
                ))}
              </div>
            </div>
          );
        })}
      </div>
      <p className="caption">
        Columns: flow index, workload (recorded label), detector score, decision. A flag on a benign flow is a false alarm (signal colour); a flag
        on an attack flow is a detection. The attacks are scripted attack-like workloads, not real attacks. The replay rate is flows per second, not recorded time.
      </p>
      <Source prov={hello?.provenance} />
    </Section>
  );
}
