import { useEffect, useState } from "react";
import { useApi } from "./lib/api";
import type { Meta } from "./lib/types";
import { Header } from "./components/Header";
import { Source, Status } from "./components/Common";
import { LadderScreen } from "./components/Ladder";
import { DriftScreen } from "./components/Drift";
import { DetectorsScreen } from "./components/Detectors";
import { ReplayScreen } from "./components/Replay";

const SCREENS = [
  ["ladder", "Handshake sizes"],
  ["drift", "Feature drift"],
  ["detectors", "Detectors and mixed traffic"],
  ["replay", "Replay"],
  ["caveats", "Caveats"],
] as const;
type ScreenId = (typeof SCREENS)[number][0];

const fromHash = (): ScreenId => {
  const h = window.location.hash.replace("#", "");
  return (SCREENS.find(([id]) => id === h)?.[0] ?? "ladder") as ScreenId;
};

export default function App() {
  const meta = useApi<Meta>("/api/meta");
  const m = meta.data;
  const [screen, setScreen] = useState<ScreenId>(fromHash);
  useEffect(() => {
    const on = () => setScreen(fromHash());
    window.addEventListener("hashchange", on);
    return () => window.removeEventListener("hashchange", on);
  }, []);
  return (
    <>
      <Header meta={meta} />
      <div className="page">
        <nav className="rail" aria-label="screens">
          <ol>
            {SCREENS.map(([id, text], i) => (
              <li key={id}><span className="no">{i + 1}</span>
                {screen === id ? <b>{text}</b> : <a href={`#${id}`}>{text}</a>}
              </li>
            ))}
          </ol>
          <p>Read-only view of the stored lab results. Nothing on this page starts a capture, runs a command or writes a file.</p>
        </nav>
        <main>
          <Status loading={meta.loading} error={meta.error} what="/api/meta" />
          {m && screen === "ladder" ? <LadderScreen meta={m} /> : null}
          {m && screen === "drift" ? <DriftScreen /> : null}
          {m && screen === "detectors" ? <DetectorsScreen meta={m} /> : null}
          {m && screen === "replay" ? <ReplayScreen meta={m} /> : null}
          {m && screen === "caveats" ? (
            <section className="sec" id="caveats">
              <h2><span className="no">5</span>Caveats</h2>
              <ul style={{ maxWidth: "46rem", paddingLeft: "1.1rem" }}>
                {m.caveats.map((c) => <li key={c}>{c}</li>)}
              </ul>
              <Source prov={m.provenance} />
            </section>
          ) : null}
        </main>
      </div>
    </>
  );
}
