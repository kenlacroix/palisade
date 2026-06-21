import { useState } from "react";
import { fetchAgents, relativeTime, useApi } from "./api.ts";
import Dashboard from "./screens/Dashboard.tsx";
import Assets from "./screens/Assets.tsx";
import FindingDetail from "./screens/FindingDetail.tsx";
import Detections from "./screens/Detections.tsx";
import AddAgent from "./screens/AddAgent.tsx";

export type View = "dashboard" | "assets" | "detections" | "agent";

const NAV: { key: View; label: string; icon: string }[] = [
  { key: "dashboard", label: "Dashboard", icon: "▤" },
  { key: "assets", label: "Assets", icon: "▦" },
  { key: "detections", label: "Detections", icon: "⌖" },
  { key: "agent", label: "Add agent", icon: "＋" },
];

export default function App() {
  const [view, setView] = useState<View>("dashboard");
  const [findingId, setFindingId] = useState<string | null>(null);
  const { data: agentsData } = useApi(fetchAgents, []);
  const agents = agentsData?.agents ?? [];

  const openFinding = (id: string) => setFindingId(id);
  const closeFinding = () => setFindingId(null);

  return (
    <div className="flex h-full">
      <aside className="flex w-56 shrink-0 flex-col border-r border-ink-700 bg-ink-800 p-3">
        <div className="mb-6 flex items-center gap-2 px-2 pt-2">
          <span className="text-accent text-xl">⬡</span>
          <span className="text-lg font-semibold tracking-tight">Palisade</span>
        </div>
        <nav className="flex flex-col gap-1">
          {NAV.map((n) => (
            <button
              key={n.key}
              onClick={() => {
                setView(n.key);
                closeFinding();
              }}
              className={`flex items-center gap-3 rounded-lg px-3 py-2 text-left text-sm transition ${
                view === n.key && !findingId
                  ? "bg-accent/15 text-white"
                  : "text-slate-400 hover:bg-ink-700 hover:text-slate-200"
              }`}
            >
              <span className="w-4 text-center">{n.icon}</span>
              {n.label}
            </button>
          ))}
        </nav>
        <div className="mt-auto space-y-2 px-2 pb-2 text-xs text-slate-500">
          <div className="font-medium text-slate-400">Agents</div>
          {agents.length === 0 ? (
            <div className="text-slate-600">none enrolled</div>
          ) : (
            agents.map((a) => (
              <div key={a.id} className="flex items-center gap-2">
                <span className={a.online ? "text-emerald-400" : "text-slate-600"}>●</span>
                <span className="text-slate-300">{a.name}</span>
                <span className="ml-auto">{relativeTime(a.last_seen)}</span>
              </div>
            ))
          )}
        </div>
      </aside>

      <main className="flex-1 overflow-y-auto">
        <div className="mx-auto max-w-5xl px-8 py-8">
          {findingId ? (
            <FindingDetail findingId={findingId} onBack={closeFinding} />
          ) : view === "dashboard" ? (
            <Dashboard onOpenFinding={openFinding} />
          ) : view === "assets" ? (
            <Assets />
          ) : view === "detections" ? (
            <Detections />
          ) : (
            <AddAgent />
          )}
        </div>
      </main>
    </div>
  );
}
