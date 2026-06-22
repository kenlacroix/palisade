import { mintEnrollToken, useApi } from "../api.ts";
import { Card } from "../ui.tsx";

// Read-only demo can't mint a token (POST is blocked on the demo org), so we
// show a non-runnable placeholder rather than a real-looking token — a copied
// demo command then can't half-work (401) against the hosted API.
const DEMO_TOKEN = "<your-enroll-token>";

function expiryNote(expiresAt: string | null): string {
  if (!expiresAt) return "single use";
  const mins = Math.max(0, Math.round((new Date(expiresAt).getTime() - Date.now()) / 60000));
  return `expires in ${mins} min · single use`;
}

export default function AddAgent({ demoMode = false }: { demoMode?: boolean }) {
  const { data, error, loading, refetch } = useApi(
    () => (demoMode ? Promise.resolve(null) : mintEnrollToken()),
    [demoMode],
  );
  const token = demoMode ? DEMO_TOKEN : data?.token;

  return (
    <div className="space-y-5">
      <h1 className="text-2xl font-semibold tracking-tight">Add an agent</h1>

      <Card className="p-6">
        <ol className="space-y-5 text-sm">
          <li>
            <div className="mb-2 text-slate-300">1. Run on the host you want to monitor:</div>
            <pre className="overflow-x-auto rounded-lg bg-ink-900 p-4 font-mono text-xs text-slate-200">
              <span className="text-slate-500">$ </span>curl -fsSL https://trypalisade.dev/install | sh \{"\n"}
              {"    "}&amp;&amp; palisade enroll --token{" "}
              <span className="text-accent">
                {demoMode ? token : loading ? "generating…" : error ? "—" : token}
              </span>
              {" "}--server https://api.trypalisade.dev
            </pre>
            <div className="mt-2 flex items-center gap-3 text-xs text-slate-500">
              {demoMode ? (
                <span>Read-only demo — enrolling is disabled. Deploy your own Palisade (or sign in to a workspace) and mint a real token under <span className="text-slate-300">Add agent</span>.</span>
              ) : error ? (
                <span className="text-rose-400">Could not mint a token: {error}</span>
              ) : (
                <span>{expiryNote(data?.expires_at ?? null)}</span>
              )}
              {!demoMode && (
                <button
                  onClick={refetch}
                  disabled={loading}
                  className="rounded-md border border-ink-700 px-2 py-1 text-slate-300 hover:border-ink-500 disabled:opacity-50"
                >
                  Regenerate
                </button>
              )}
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
        <span className="font-medium text-slate-300">No-exfil by default.</span> Detections run on the
        agent; only normalized findings leave your network. Raw responses stay local unless you opt in.
      </Card>
    </div>
  );
}
