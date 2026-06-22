import { fetchAudit, relativeTime, useApi } from "../api.ts";
import { Card } from "../ui.tsx";

export default function Audit() {
  const { data, error, loading } = useApi(fetchAudit, []);
  const rows = data?.entries ?? [];

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Audit log</h1>
        <p className="text-sm text-slate-500">One row per privileged action in this org.</p>
      </div>

      <Card>
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-ink-700 text-left text-xs uppercase tracking-wide text-slate-500">
              <th className="px-4 py-3 font-medium">When</th>
              <th className="px-4 py-3 font-medium">Actor</th>
              <th className="px-4 py-3 font-medium">Action</th>
              <th className="px-4 py-3 font-medium">Target</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-ink-700">
            {rows.map((e) => (
              <tr key={e.id} className="hover:bg-ink-700/50">
                <td className="px-4 py-3 text-slate-300" title={e.at}>
                  {relativeTime(e.at)}
                </td>
                <td className="px-4 py-3 text-slate-300">{e.actor}</td>
                <td className="px-4 py-3 font-mono text-slate-200">{e.action}</td>
                <td className="px-4 py-3 font-mono text-slate-500">{e.target ?? "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {error ? (
          <div className="px-4 py-6 text-center text-sm text-red-400">Failed to load audit log: {error}</div>
        ) : rows.length === 0 ? (
          <div className="px-4 py-6 text-center text-sm text-slate-500">
            {loading ? "Loading audit log…" : "No audited actions yet."}
          </div>
        ) : null}
      </Card>
    </div>
  );
}
