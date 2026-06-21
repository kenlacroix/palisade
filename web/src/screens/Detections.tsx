import { useState } from "react";
import { acceptDetection, draftDetection, fetchDetections, useApi, type DraftResponse } from "../api.ts";
import { Card, SevBadge } from "../ui.tsx";

export default function Detections() {
  const { data, error, loading, refetch } = useApi(fetchDetections, []);
  const rows = data?.detections ?? [];

  const [drafting, setDrafting] = useState(false);
  const [draft, setDraft] = useState<DraftResponse | null>(null);
  const [draftError, setDraftError] = useState<string | null>(null);
  const [accepting, setAccepting] = useState(false);

  const onNewFromCve = async () => {
    const url = window.prompt("CVE advisory URL");
    if (!url) return;
    setDrafting(true);
    setDraftError(null);
    setDraft(null);
    try {
      setDraft(await draftDetection(url));
    } catch (e) {
      setDraftError(e instanceof Error ? e.message : String(e));
    } finally {
      setDrafting(false);
    }
  };

  const onAccept = async () => {
    if (!draft) return;
    setAccepting(true);
    setDraftError(null);
    try {
      await acceptDetection(draft.detection);
      setDraft(null);
      refetch();
    } catch (e) {
      setDraftError(e instanceof Error ? e.message : String(e));
    } finally {
      setAccepting(false);
    }
  };

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-semibold tracking-tight">Detections</h1>
        <button
          onClick={onNewFromCve}
          disabled={drafting}
          className="rounded-lg bg-accent px-3 py-1.5 text-sm font-medium text-white hover:bg-accent/90 disabled:opacity-50"
        >
          {drafting ? "Drafting…" : "+ New from CVE URL"}
        </button>
      </div>

      {draftError && <div className="text-sm text-red-400">{draftError}</div>}

      {draft && (
        <Card className="p-5">
          <div className="mb-3 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <span className="text-xs font-semibold uppercase tracking-wide text-slate-400">
                AI draft — review &amp; sign
              </span>
              <SevBadge severity={draft.detection.severity} />
            </div>
            <div className="flex items-center gap-3">
              <button
                onClick={onAccept}
                disabled={accepting}
                className="rounded-lg bg-accent px-3 py-1.5 text-sm font-medium text-white hover:bg-accent/90 disabled:opacity-50"
              >
                {accepting ? "Shipping…" : "Accept & ship"}
              </button>
              <button
                onClick={() => setDraft(null)}
                disabled={accepting}
                className="text-sm text-slate-400 hover:text-slate-200 disabled:opacity-50"
              >
                dismiss
              </button>
            </div>
          </div>
          <div className="mb-3 text-sm">
            <span className="font-medium text-slate-100">{draft.detection.title}</span>{" "}
            <span className="font-mono text-slate-500">{draft.detection.id}</span>
            {draft.detection.cve && (
              <span className="ml-2 font-mono text-slate-500">{draft.detection.cve}</span>
            )}
          </div>
          <pre className="overflow-x-auto rounded-lg bg-ink-900 p-3 font-mono text-xs text-slate-300">
            {JSON.stringify(draft.detection, null, 2)}
          </pre>
          <div className="mt-2 text-xs text-slate-500">
            {draft.signature} · drafted by {draft.model} from{" "}
            <a href={draft.source_url} target="_blank" rel="noreferrer" className="text-accent hover:underline">
              source
            </a>
          </div>
        </Card>
      )}

      <Card>
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-ink-700 text-left text-xs uppercase tracking-wide text-slate-500">
              <th className="px-4 py-3 font-medium">Slug</th>
              <th className="px-4 py-3 font-medium">Severity</th>
              <th className="px-4 py-3 font-medium">CVSS</th>
              <th className="px-4 py-3 font-medium">Category</th>
              <th className="px-4 py-3 font-medium">Tenants hit</th>
              <th className="px-4 py-3 font-medium">Ver</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-ink-700">
            {rows.map((d) => (
              <tr key={d.slug} className="hover:bg-ink-700/50">
                <td className="px-4 py-3 font-mono text-slate-200">{d.slug}</td>
                <td className="px-4 py-3">
                  <SevBadge severity={d.severity} />
                </td>
                <td className="px-4 py-3 font-mono text-slate-500">{d.cvss ?? "—"}</td>
                <td className="px-4 py-3 text-slate-400">{d.category}</td>
                <td className="px-4 py-3 text-slate-300">
                  {d.tenants_hit} / {d.tenants_total}
                </td>
                <td className="px-4 py-3 font-mono text-slate-500">v{d.version}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {error ? (
          <div className="px-4 py-6 text-center text-sm text-red-400">Failed to load detections: {error}</div>
        ) : rows.length === 0 ? (
          <div className="px-4 py-6 text-center text-sm text-slate-500">
            {loading ? "Loading detections…" : "No detections in the catalog."}
          </div>
        ) : null}
      </Card>

      <p className="text-sm text-slate-500">
        <span className="text-accent">+ New from CVE URL</span> → AI drafts a template → you review → <span className="text-accent">Accept &amp; ship</span> pushes it to the signed catalog (agents pull it next bundle).
      </p>
    </div>
  );
}
