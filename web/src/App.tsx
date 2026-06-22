import { useEffect, useState } from "react";
import {
  clearToken,
  fetchAgents,
  fetchMe,
  logout,
  relativeTime,
  switchOrg,
  useApi,
  type Session,
} from "./api.ts";
import Dashboard from "./screens/Dashboard.tsx";
import Assets from "./screens/Assets.tsx";
import FindingDetail from "./screens/FindingDetail.tsx";
import Detections from "./screens/Detections.tsx";
import AddAgent from "./screens/AddAgent.tsx";
import Alerts from "./screens/Alerts.tsx";
import Audit from "./screens/Audit.tsx";
import Members from "./screens/Members.tsx";
import Login from "./screens/Login.tsx";

export type View = "dashboard" | "assets" | "detections" | "alerts" | "audit" | "members" | "agent";

const NAV: { key: View; label: string; icon: string; adminOnly?: boolean }[] = [
  { key: "dashboard", label: "Dashboard", icon: "▤" },
  { key: "assets", label: "Assets", icon: "▦" },
  { key: "detections", label: "Detections", icon: "⌖" },
  { key: "alerts", label: "Alerts", icon: "✦" },
  { key: "audit", label: "Audit", icon: "☰", adminOnly: true },
  { key: "members", label: "Members", icon: "◍", adminOnly: true },
  { key: "agent", label: "Add agent", icon: "＋" },
];

type AuthState = "checking" | "out" | "in";

export default function App() {
  // Always probe on load: the session lives in the httpOnly cookie, so a
  // refresh rehydrates via fetchMe() rather than a JS-readable token.
  const [auth, setAuth] = useState<AuthState>("checking");
  const [session, setSession] = useState<Session | null>(null);

  useEffect(() => {
    const drop = () => {
      setSession(null);
      setAuth("out");
    };
    window.addEventListener("palisade-unauthorized", drop);
    return () => window.removeEventListener("palisade-unauthorized", drop);
  }, []);

  useEffect(() => {
    if (auth !== "checking") return;
    fetchMe()
      .then((s) => {
        setSession(s);
        setAuth("in");
      })
      .catch(() => setAuth("out"));
  }, [auth]);

  if (auth === "checking") return <div className="flex h-full items-center justify-center text-slate-500">Loading…</div>;
  if (auth === "out" || !session) {
    return (
      <Login
        onAuthed={(s) => {
          setSession(s);
          setAuth("in");
        }}
      />
    );
  }

  return (
    <Shell
      session={session}
      onSession={setSession}
      onSignOut={() => {
        setSession(null);
        setAuth("out");
      }}
    />
  );
}

function Shell({
  session,
  onSession,
  onSignOut,
}: {
  session: Session;
  onSession: (s: Session) => void;
  onSignOut: () => void;
}) {
  const [view, setView] = useState<View>("dashboard");
  const [findingId, setFindingId] = useState<string | null>(null);
  const { data: agentsData } = useApi(fetchAgents, []);
  const agents = agentsData?.agents ?? [];

  const openFinding = (id: string) => setFindingId(id);
  const closeFinding = () => setFindingId(null);

  const onSignOut_ = async () => {
    try {
      await logout();
    } catch {
      // ignore — clearing the token is enough to drop to login
    }
    clearToken();
    onSignOut();
  };

  const onSwitchOrg = async (org_id: string) => {
    onSession(await switchOrg(org_id));
  };

  const isAdmin = session.role === "owner" || session.role === "admin";
  const nav = NAV.filter((n) => !n.adminOnly || isAdmin);

  return (
    <div className="flex h-full">
      <aside className="flex w-56 shrink-0 flex-col border-r border-ink-700 bg-ink-800 p-3">
        <div className="mb-6 flex items-center gap-2 px-2 pt-2">
          <span className="text-accent text-xl">⬡</span>
          <span className="text-lg font-semibold tracking-tight">Palisade</span>
        </div>
        <nav className="flex flex-col gap-1">
          {nav.map((n) => (
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

        <div className="mt-auto space-y-4 px-2 pb-2">
          <div className="space-y-2 text-xs text-slate-500">
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

          <div className="space-y-2 border-t border-ink-700 pt-3 text-xs">
            {session.memberships.length > 1 ? (
              <select
                value={session.org_id}
                onChange={(e) => onSwitchOrg(e.target.value)}
                className="w-full rounded-lg border border-ink-600 bg-ink-800 px-2 py-1 text-xs text-slate-300 outline-none focus:border-accent"
              >
                {session.memberships.map((m) => (
                  <option key={m.org_id} value={m.org_id}>
                    {m.org_name}
                  </option>
                ))}
              </select>
            ) : (
              <div className="font-medium text-slate-300">{session.org_name}</div>
            )}
            <div className="text-slate-500">
              {session.user.email} · <span className="text-slate-400">{session.role}</span>
            </div>
            <button
              onClick={onSignOut_}
              className="text-slate-500 hover:text-slate-300"
            >
              Sign out
            </button>
          </div>
        </div>
      </aside>

      <main className="flex-1 overflow-y-auto">
        {session.demo_mode && <DemoBanner />}
        <div className="mx-auto max-w-5xl px-8 py-8">
          {findingId ? (
            <FindingDetail findingId={findingId} onBack={closeFinding} />
          ) : view === "dashboard" ? (
            <Dashboard onOpenFinding={openFinding} demoMode={session.demo_mode ?? false} />
          ) : view === "assets" ? (
            <Assets role={session.role} />
          ) : view === "detections" ? (
            <Detections />
          ) : view === "alerts" ? (
            <Alerts role={session.role} />
          ) : view === "audit" ? (
            <Audit />
          ) : view === "members" ? (
            <Members />
          ) : (
            <AddAgent demoMode={session.demo_mode ?? false} />
          )}
        </div>
      </main>
    </div>
  );
}

function DemoBanner() {
  const [dismissed, setDismissed] = useState(false);
  if (dismissed) return null;
  return (
    <div className="flex items-center gap-3 border-b border-accent/30 bg-accent/10 px-8 py-2 text-xs text-slate-300">
      <span className="rounded bg-accent/20 px-1.5 py-0.5 font-medium uppercase tracking-wide text-accent">
        Live demo
      </span>
      <span>
        Sample data, read-only. This is a portfolio demonstration of Palisade.{" "}
        <a
          href="https://trypalisade.dev"
          target="_blank"
          rel="noreferrer"
          className="text-accent hover:underline"
        >
          How it works ›
        </a>
      </span>
      <button
        onClick={() => setDismissed(true)}
        className="ml-auto text-slate-500 hover:text-slate-300"
        aria-label="Dismiss demo banner"
      >
        ✕
      </button>
    </div>
  );
}
