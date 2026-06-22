import { useState } from "react";
import { fetchAssets, relativeTime, triggerExternalScan, useApi, type Role } from "../api.ts";
import { Card } from "../ui.tsx";

type Filter = "all" | "internal" | "external";

export default function Assets({ role }: { role: Role }) {
  const canScan = role !== "viewer";
  const [filter, setFilter] = useState<Filter>("all");
  const [q, setQ] = useState("");
  const { data, error, loading } = useApi(fetchAssets, [], { pollMs: 10000 });

  const [scanBusy, setScanBusy] = useState(false);
  const [scanStatus, setScanStatus] = useState<string | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);

  const onExternalScan = async () => {
    setScanBusy(true);
    setScanStatus(null);
    setScanError(null);
    try {
      const res = await triggerExternalScan();
      setScanStatus(
        res.enqueued
          ? `Perimeter scan enqueued — ${res.external_assets} external asset${res.external_assets === 1 ? "" : "s"}.`
          : "No external assets to scan.",
      );
    } catch (err) {
      setScanError(err instanceof Error ? err.message : String(err));
    } finally {
      setScanBusy(false);
    }
  };

  const rows = (data?.assets ?? []).filter(
    (a) =>
      (filter === "all" || a.exposure === filter) &&
      (q === "" || `${a.host} ${a.service}`.toLowerCase().includes(q.toLowerCase())),
  );

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-semibold tracking-tight">Assets</h1>
        <div className="flex items-center gap-2">
          {canScan && (
            <button
              onClick={onExternalScan}
              disabled={scanBusy}
              title="Run a control-plane perimeter scan (attacker's-eye view) against external assets"
              className="rounded-lg bg-accent px-3 py-1.5 text-sm font-medium text-white hover:bg-accent/90 disabled:opacity-50"
            >
              {scanBusy ? "Scanning…" : "External scan"}
            </button>
          )}
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="search…"
            className="rounded-lg border border-ink-600 bg-ink-800 px-3 py-1.5 text-sm outline-none placeholder:text-slate-600 focus:border-accent"
          />
          <select
            value={filter}
            onChange={(e) => setFilter(e.target.value as Filter)}
            className="rounded-lg border border-ink-600 bg-ink-800 px-3 py-1.5 text-sm outline-none focus:border-accent"
          >
            <option value="all">all exposure</option>
            <option value="external">external</option>
            <option value="internal">internal</option>
          </select>
        </div>
      </div>

      {scanError ? (
        <div className="text-sm text-red-400">External scan failed: {scanError}</div>
      ) : scanStatus ? (
        <div className="text-sm text-emerald-400">{scanStatus}</div>
      ) : null}

      <Card>
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-ink-700 text-left text-xs uppercase tracking-wide text-slate-500">
              <th className="px-4 py-3 font-medium">Host</th>
              <th className="px-4 py-3 font-medium">Service</th>
              <th className="px-4 py-3 font-medium">Version</th>
              <th className="px-4 py-3 font-medium">Exposure</th>
              <th className="px-4 py-3 font-medium">Findings</th>
              <th className="px-4 py-3 font-medium">Seen</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-ink-700">
            {rows.map((a) => (
              <tr key={a.id} className="hover:bg-ink-700/50">
                <td className="px-4 py-3 font-mono text-slate-200">
                  {a.scheme ? `${a.scheme}://` : ""}
                  {a.host}:{a.port}
                </td>
                <td className="px-4 py-3 text-slate-300">{a.service}</td>
                <td className="px-4 py-3 text-slate-400">{a.version ?? "—"}</td>
                <td className="px-4 py-3">
                  <span
                    className={`rounded px-2 py-0.5 text-xs ${
                      a.exposure === "external"
                        ? "bg-red-500/10 text-red-300"
                        : "bg-slate-500/10 text-slate-400"
                    }`}
                  >
                    {a.exposure}
                  </span>
                </td>
                <td className="px-4 py-3">
                  {a.findings_critical > 0 && <span className="mr-2 text-red-400">⛔ {a.findings_critical}</span>}
                  {a.findings_high > 0 && <span className="text-amber-400">⚠ {a.findings_high}</span>}
                  {a.findings_critical === 0 && a.findings_high === 0 && (
                    <span className="text-emerald-400">✓ clean</span>
                  )}
                </td>
                <td className="px-4 py-3 text-slate-500">{relativeTime(a.last_seen)}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {error ? (
          <div className="px-4 py-6 text-center text-sm text-red-400">Failed to load assets: {error}</div>
        ) : rows.length === 0 ? (
          <div className="px-4 py-6 text-center text-sm text-slate-500">
            {loading ? "Loading assets…" : "No assets yet — enroll an agent to start discovery."}
          </div>
        ) : null}
      </Card>
    </div>
  );
}
