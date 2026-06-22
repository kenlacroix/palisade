import { fetchFindings, fetchPostureSummary, relativeTime, useApi } from "../api.ts";
import { Card, Dot } from "../ui.tsx";

const ACTIVE = new Set(["open", "regressed"]);

function Sparkline({ data }: { data: number[] }) {
  const max = Math.max(...data, 1);
  const w = 320;
  const h = 48;
  const step = w / (data.length - 1);
  const points = data
    .map((v, i) => `${i * step},${h - (v / max) * (h - 4) - 2}`)
    .join(" ");
  return (
    <svg width={w} height={h} className="overflow-visible">
      <polyline points={points} fill="none" stroke="#f59e0b" strokeWidth="1.5" />
    </svg>
  );
}

export default function Dashboard({
  onOpenFinding,
  demoMode = false,
}: {
  onOpenFinding: (id: string) => void;
  demoMode?: boolean;
}) {
  const posture = useApi(fetchPostureSummary, [], { pollMs: 10000 });
  const findings = useApi(fetchFindings, [], { pollMs: 10000 });

  if (posture.error) return <div className="text-red-400">Failed to load posture: {posture.error}</div>;
  if (!posture.data) return <div className="text-slate-500">Loading posture…</div>;

  const p = posture.data;
  const attention = (findings.data?.findings ?? []).filter((f) => ACTIVE.has(f.status));

  return (
    <div className="space-y-6">
      <div className="flex items-baseline justify-between">
        <h1 className="text-2xl font-semibold tracking-tight">Posture</h1>
        <div className="text-sm text-slate-400">
          Score <span className="text-2xl font-semibold text-emerald-400">{p.score}</span>
          <span className="text-slate-500">/100</span>
        </div>
      </div>

      {demoMode && (
        <p className="text-sm text-slate-500">
          Agents enroll on each host, discover listening services, run CVE detections locally, and
          report only normalized findings — what you see below is that pipeline's output.
        </p>
      )}

      <div className="grid grid-cols-4 gap-4">
        {[
          { label: "Critical", value: p.counts.critical, color: "text-red-400" },
          { label: "High", value: p.counts.high, color: "text-amber-400" },
          { label: "Medium", value: p.counts.medium, color: "text-yellow-400" },
          { label: "Assets", value: p.counts.assets, color: "text-slate-200" },
        ].map((c) => (
          <Card key={c.label} className="p-4">
            <div className={`text-3xl font-semibold ${c.color}`}>{c.value}</div>
            <div className="mt-1 text-xs uppercase tracking-wide text-slate-500">{c.label}</div>
          </Card>
        ))}
      </div>

      <Card className="p-5">
        <div className="mb-3 text-sm font-medium text-slate-300">Posture score (30d)</div>
        <Sparkline data={p.trend30d} />
      </Card>

      <div>
        <div className="mb-3 flex items-center justify-between">
          <h2 className="text-sm font-medium text-slate-300">Needs attention</h2>
          <span className="text-xs text-slate-500">view all ▸</span>
        </div>
        <Card>
          {findings.error ? (
            <div className="px-4 py-3 text-sm text-red-400">Failed to load findings: {findings.error}</div>
          ) : attention.length === 0 ? (
            <div className="px-4 py-6 text-center text-sm text-slate-500">
              {findings.loading ? "Loading findings…" : "Nothing open. Clean."}
            </div>
          ) : (
            <ul className="divide-y divide-ink-700">
              {attention.map((f) => (
                <li key={f.id}>
                  <button
                    onClick={() => onOpenFinding(f.id)}
                    className="flex w-full items-center gap-3 px-4 py-3 text-left text-sm hover:bg-ink-700"
                  >
                    <Dot severity={f.severity} />
                    <span className="font-medium text-slate-100">{f.title}</span>
                    <span className="font-mono text-xs text-slate-500">{f.host}:{f.port}</span>
                    <span className="ml-auto text-xs text-slate-500">{relativeTime(f.first_seen)}</span>
                    <span className="text-slate-600">›</span>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>
    </div>
  );
}
