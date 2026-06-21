import { Card } from "../ui.tsx";

export default function AddAgent() {
  return (
    <div className="space-y-5">
      <h1 className="text-2xl font-semibold tracking-tight">Add an agent</h1>

      <Card className="p-6">
        <ol className="space-y-5 text-sm">
          <li>
            <div className="mb-2 text-slate-300">1. Run on the host you want to monitor:</div>
            <pre className="overflow-x-auto rounded-lg bg-ink-900 p-4 font-mono text-xs text-slate-200">
              <span className="text-slate-500">$ </span>curl -fsSL https://palisade.sh/install | sh \{"\n"}
              {"    "}&amp;&amp; palisade enroll --token{" "}
              <span className="text-accent">PLS-7F3A-9C21-LK48</span>
            </pre>
            <div className="mt-2 text-xs text-slate-500">token expires in 15 min · single use</div>
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
