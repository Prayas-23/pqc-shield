import { useCallback, useEffect, useState } from "react";
import { useApi } from "./lib/api";
import type { Meta } from "./lib/types";
import { Rail, StatusBar, TopBar, VIEWS } from "./components/Shell";
import type { ViewId } from "./components/Shell";
import { Msg, Source } from "./components/Common";
import { LadderView } from "./components/Ladder";
import { DriftView } from "./components/Drift";
import { DetectorsView } from "./components/Detectors";
import { ReplayView } from "./components/Replay";

const fromHash = (): ViewId => {
  const h = window.location.hash.replace("#", "");
  return (VIEWS.find(([id]) => id === h)?.[0] ?? "ladder") as ViewId;
};

export default function App() {
  const meta = useApi<Meta>("/api/meta");
  const m = meta.data;
  const [view, setView] = useState<ViewId>(fromHash);
  const go = useCallback((v: ViewId) => { window.location.hash = v; setView(v); }, []);

  useEffect(() => {
    const onHash = () => setView(fromHash());
    const onKey = (e: KeyboardEvent) => {
      const t = e.target as HTMLElement | null;
      if (t && ["INPUT", "SELECT", "TEXTAREA"].includes(t.tagName)) return;
      if (e.ctrlKey || e.metaKey || e.altKey) return;
      const i = Number(e.key);
      if (Number.isInteger(i) && i >= 1 && i <= VIEWS.length) go(VIEWS[i - 1]![0]);
    };
    window.addEventListener("hashchange", onHash);
    window.addEventListener("keydown", onKey);
    return () => { window.removeEventListener("hashchange", onHash); window.removeEventListener("keydown", onKey); };
  }, [go]);

  return (
    <div className="app">
      <TopBar meta={meta} />
      <div className="mid">
        <Rail view={view} onPick={go} />
        <main style={{ minWidth: 0, minHeight: 0, display: "flex", flexDirection: "column" }}>
          {meta.error || meta.loading ? <div style={{ padding: "0.8rem" }}><Msg loading={meta.loading} error={meta.error} what="/api/meta" /></div> : null}
          {m && view === "ladder" ? <LadderView meta={m} /> : null}
          {m && view === "drift" ? <DriftView /> : null}
          {m && view === "detectors" ? <DetectorsView meta={m} /> : null}
          {m && view === "replay" ? <ReplayView meta={m} /> : null}
          {m && view === "caveats" ? (
            <div className="view" style={{ gridTemplateColumns: "minmax(0, 1fr)" }}>
              <section className="workspace" style={{ borderRight: 0 }} aria-label="Caveats">
                <div className="strip"><b>Caveats</b></div>
                <div className="wbody plain">
                  <ul>{m.caveats.map((c) => <li key={c}>{c}</li>)}</ul>
                  <Source prov={m.provenance} />
                </div>
              </section>
            </div>
          ) : null}
        </main>
      </div>
      <StatusBar meta={meta} onCaveats={() => go("caveats")} />
    </div>
  );
}
