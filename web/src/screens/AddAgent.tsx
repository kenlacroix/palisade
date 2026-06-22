import { mintEnrollToken, useApi } from "../api.ts";
import { Card } from "../ui.tsx";

// Non-runnable placeholder shown in the read-only demo preview — a copied demo
// command can't half-work (401) against the hosted API.
const DEMO_TOKEN = "<your-enroll-token>";
const REPO_URL = "https://github.com/kenlacroix/palisade";

function expiryNote(expiresAt: string | null): string {
  if (!expiresAt) return "single use";
  const mins = Math.max(0, Math.round((new Date(expiresAt).getTime() - Date.now()) / 60000));
  return `expires in ${mins} min · single use`;
}

// Read-only demo: enrolling is blocked on the demo org, so instead of a dead
// form we preview the onboarding command and route to the self-contained
// `make demo`, which runs the real enroll/scan/finding loop on the user's own
// machine against a bundled target.
function DemoAddAgent() {
  return (
    <div className="space-y-5">
      <h1 className="text-2xl font-semibold tracking-tight">Add an agent</h1>

      <Card className="space-y-4 p-6 text-sm">
        <p className="text-slate-300">
          Onboarding is one command — install the agent on a host and enroll it against your control
          plane:
        </p>
        <pre className="overflow-x-auto rounded-lg bg-ink-900 p-4 font-mono text-xs text-slate-400">
          <span className="text-slate-500">
            # preview — enrolling is disabled in the read-only demo
          </span>
          {"\n"}
          curl -fsSL https://trypalisade.dev/install | sh \{"\n"}
          {"  "}&amp;&amp; palisade enroll --token{" "}
          <span className="text-slate-300">{DEMO_TOKEN}</span> --server https://api.trypalisade.dev
        </pre>

        <div className="rounded-lg border border-ink-700 bg-ink-900/50 p-4">
          <p className="text-slate-400">
            <span className="font-medium text-slate-300">Want to run it for real?</span> Spin up the
            whole stack — control plane, web UI, and a live agent that discovers and scans a bundled
            vulnerable target — on your own machine. Nothing leaves your host.
          </p>
          <pre className="mt-3 overflow-x-auto rounded-lg bg-ink-900 p-3 font-mono text-xs text-slate-200">
            <span className="text-slate-500">$ </span>make demo
            {"   "}
            <span className="text-slate-500"># http://localhost:8080</span>
          </pre>
          <a
            href={REPO_URL}
            target="_blank"
            rel="noopener"
            className="mt-3 inline-block rounded-md border border-ink-700 px-3 py-1.5 text-slate-300 hover:border-ink-500"
          >
            Get it on GitHub →
          </a>
        </div>
      </Card>

      <Card className="p-4 text-sm text-slate-400">
        <span className="font-medium text-slate-300">No-exfil by default.</span> Detections run on
        the agent; only normalized findings leave your network. Raw responses stay local unless you
        opt in.
      </Card>
    </div>
  );
}

function RealAddAgent() {
  const { data, error, loading, refetch } = useApi(() => mintEnrollToken(), []);
  const token = data?.token;

  return (
    <div className="space-y-5">
      <h1 className="text-2xl font-semibold tracking-tight">Add an agent</h1>

      <Card className="p-6">
        <ol className="space-y-5 text-sm">
          <li>
            <div className="mb-2 text-slate-300">1. Run on the host you want to monitor:</div>
            <pre className="overflow-x-auto rounded-lg bg-ink-900 p-4 font-mono text-xs text-slate-200">
              <span className="text-slate-500">$ </span>curl -fsSL https://trypalisade.dev/install |
              sh \{"\n"}
              {"    "}&amp;&amp; palisade enroll --token{" "}
              <span className="text-accent">{loading ? "generating…" : error ? "—" : token}</span>{" "}
              --server https://api.trypalisade.dev
            </pre>
            <div className="mt-2 flex items-center gap-3 text-xs text-slate-500">
              {error ? (
                <span className="text-rose-400">Could not mint a token: {error}</span>
              ) : (
                <span>{expiryNote(data?.expires_at ?? null)}</span>
              )}
              <button
                onClick={refetch}
                disabled={loading}
                className="rounded-md border border-ink-700 px-2 py-1 text-slate-300 hover:border-ink-500 disabled:opacity-50"
              >
                Regenerate
              </button>
            </div>
          </li>
          <li className="flex items-center gap-3 text-slate-400">
            <span className="text-slate-300">2. Waiting for first heartbeat…</span>
            <span className="flex items-center gap-1.5 text-accent">
              <span className="h-2 w-2 animate-pulse rounded-full bg-accent" /> listening
            </span>
          </li>
        </ol>

        <div className="mt-6 border-t border-ink-700 pt-4 text-xs text-slate-500">
          Supports: Linux x86_64 / arm64 · macOS · Synology · Raspberry Pi
        </div>
      </Card>

      <Card className="p-4 text-sm text-slate-400">
        <span className="font-medium text-slate-300">No-exfil by default.</span> Detections run on
        the agent; only normalized findings leave your network. Raw responses stay local unless you
        opt in.
      </Card>
    </div>
  );
}

export default function AddAgent({ demoMode = false }: { demoMode?: boolean }) {
  return demoMode ? <DemoAddAgent /> : <RealAddAgent />;
}
