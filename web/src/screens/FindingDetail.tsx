import { useState } from "react";
import {
  fetchAssets,
  fetchFindings,
  muteFinding,
  relativeTime,
  triggerRescan,
  useApi,
} from "../api.ts";
import { Card, SevBadge } from "../ui.tsx";

export default function FindingDetail({ findingId, onBack }: { findingId: string; onBack: () => void }) {
  const findings = useApi(fetchFindings, [], { pollMs: 10000 });
  const assets = useApi(fetchAssets, []);
  const [busy, setBusy] = useState<"mute" | "rescan" | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const back = (
    <button onClick={onBack} className="text-sm text-slate-400 hover:text-slate-200">
      ‹ back
    </button>
  );

  if (findings.error) return <div className="space-y-5">{back}<div className="text-red-400">{findings.error}</div></div>;
  if (!findings.data) return <div className="space-y-5">{back}<div className="text-slate-500">Loading…</div></div>;

  const f = findings.data.findings.find((x) => x.id === findingId);
  if (!f) return <div className="space-y-5">{back}<div>Finding not found.</div></div>;
  const asset = assets.data?.assets.find((a) => a.id === f.asset_id);

  const onMute = async () => {
    setBusy("mute");
    setNotice(null);
    try {
      await muteFinding(f.id, "muted from console");
      findings.refetch();
      setNotice("Finding muted.");
    } catch (e) {
      setNotice(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(null);
    }
  };

  const onRescan = async () => {
    setBusy("rescan");
    setNotice(null);
    try {
      const { agents_nudged } = await triggerRescan();
      setNotice(`Rescan queued — ${agents_nudged} agent(s) will re-scan on next heartbeat.`);
    } catch (e) {
      setNotice(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className="space-y-5">
      {back}

      <div className="flex items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-xl font-semibold tracking-tight text-slate-100">{f.title}</h1>
            <SevBadge severity={f.severity} />
          </div>
          {f.cve && <div className="mt-1 font-mono text-sm text-slate-500">{f.cve}</div>}
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={onMute}
            disabled={busy !== null || f.status === "muted"}
            className="rounded-lg border border-ink-600 px-3 py-1.5 text-sm hover:bg-ink-700 disabled:opacity-50"
          >
            {f.status === "muted" ? "Muted" : busy === "mute" ? "Muting…" : "Mute"}
          </button>
          <button
            onClick={onRescan}
            disabled={busy !== null}
            className="rounded-lg bg-accent px-3 py-1.5 text-sm font-medium text-white hover:bg-accent/90 disabled:opacity-50"
          >
            {busy === "rescan" ? "Queuing…" : "Rescan"}
          </button>
        </div>
      </div>

      {notice && <div className="text-sm text-slate-400">{notice}</div>}

      <Card className="p-4">
        <div className="flex flex-wrap gap-x-8 gap-y-2 text-sm">
          <span>
            <span className="text-slate-500">Asset</span>{" "}
            <span className="font-mono text-slate-200">{f.host}:{f.port}</span>{" "}
            {asset && <span className="text-slate-500">({asset.exposure})</span>}
          </span>
          <span>
            <span className="text-slate-500">Status</span>{" "}
            <span className="text-slate-200">{f.status}</span>
          </span>
          <span>
            <span className="text-slate-500">First seen</span>{" "}
            <span className="text-slate-200">{relativeTime(f.first_seen)}</span>
          </span>
          <span>
            <span className="text-slate-500">Last seen</span>{" "}
            <span className="text-slate-200">{relativeTime(f.last_seen)}</span>
          </span>
        </div>
      </Card>

      <Card className="p-5">
        <div className="mb-3 text-xs font-semibold uppercase tracking-wide text-slate-400">Evidence</div>
        <div className="rounded-lg bg-ink-900 p-3 font-mono text-sm">
          <div className="text-slate-300">{f.evidence.request ?? "—"}</div>
          {f.evidence.note && <div className="mt-1 text-emerald-400">→ {f.evidence.note}</div>}
        </div>
        <div className="mt-3 text-xs text-slate-500">
          fingerprint <span className="font-mono">{f.fingerprint}</span>
        </div>
      </Card>

      {f.remediation && (
        <Card className="p-5">
          <div className="mb-3 text-xs font-semibold uppercase tracking-wide text-slate-400">Remediation</div>
          <p className="whitespace-pre-line text-sm text-slate-300">{f.remediation}</p>
        </Card>
      )}

      {f.references.length > 0 && (
        <Card className="p-5">
          <div className="mb-3 text-xs font-semibold uppercase tracking-wide text-slate-400">References</div>
          <ul className="space-y-1 text-sm">
            {f.references.map((url) => (
              <li key={url}>
                <a
                  href={url}
                  target="_blank"
                  rel="noreferrer"
                  className="font-mono text-accent hover:underline"
                >
                  {url}
                </a>
              </li>
            ))}
          </ul>
        </Card>
      )}
    </div>
  );
}
