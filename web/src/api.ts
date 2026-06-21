import { useEffect, useState, type DependencyList } from "react";
import type { Severity, Exposure } from "./data.ts";

// Same-origin by default; vite dev proxies /v1 to the control plane. Override
// with VITE_API_BASE (e.g. http://nas.lab:8000) when serving the built UI.
const BASE = import.meta.env.VITE_API_BASE ?? "";

async function get<T>(path: string): Promise<T> {
  const res = await fetch(`${BASE}${path}`);
  if (!res.ok) throw new Error(`${path} → ${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

async function post<T>(path: string, body?: unknown): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`${path} → ${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

export interface ApiAsset {
  id: string;
  host: string;
  port: number;
  service: string;
  product: string | null;
  version: string | null;
  exposure: Exposure;
  findings_critical: number;
  findings_high: number;
  findings_open: number;
  last_seen: string | null;
}

export interface ApiFinding {
  id: string;
  detection_id: string;
  asset_id: string;
  host: string;
  port: number;
  title: string;
  cve: string | null;
  severity: Severity;
  status: "open" | "resolved" | "muted" | "regressed";
  fingerprint: string;
  evidence: { request?: string; note?: string };
  remediation: string | null;
  references: string[];
  first_seen: string | null;
  last_seen: string | null;
}

export interface ApiDetection {
  slug: string;
  title: string;
  severity: Severity;
  category: string;
  cvss: number | null;
  tenants_hit: number;
  tenants_total: number;
  version: number;
}

export interface ApiAgent {
  id: string;
  name: string;
  status: string;
  online: boolean;
  last_seen: string | null;
}

export interface PostureSummary {
  score: number;
  counts: { critical: number; high: number; medium: number; assets: number };
  trend30d: number[];
}

export const fetchAssets = () => get<{ assets: ApiAsset[] }>("/v1/assets");

export function fetchFindings(params?: { status?: string; severity?: string }) {
  const qs = new URLSearchParams(params as Record<string, string>).toString();
  return get<{ findings: ApiFinding[] }>(`/v1/findings${qs ? `?${qs}` : ""}`);
}

export const fetchPostureSummary = () => get<PostureSummary>("/v1/posture/summary");

export const fetchDetections = () => get<{ detections: ApiDetection[] }>("/v1/detections");

export const fetchAgents = () => get<{ agents: ApiAgent[] }>("/v1/agents");

export const muteFinding = (id: string, reason: string, ttl_s = 3600) =>
  post<ApiFinding>(`/v1/findings/${id}/mute`, { reason, ttl_s });

export const triggerRescan = () => post<{ agents_nudged: number }>("/v1/rescan");

export interface DraftDetection {
  id: string;
  title: string;
  cve: string | null;
  severity: Severity;
  category: string;
  engine: string;
  match: { service: string; versions: string };
  http: Array<{ method: string; path: string; body?: string | null; matchers: unknown[] }>;
  remediation: string;
  references: string[];
}

export interface DraftResponse {
  detection: DraftDetection;
  source_url: string;
  model: string;
  signature: "unsigned-draft";
}

export const draftDetection = (cveUrl: string) =>
  post<DraftResponse>("/v1/detections/draft", { cve_url: cveUrl });

export const acceptDetection = (detection: DraftDetection) =>
  post<{ id: string; version: number }>("/v1/detections", detection);

export function relativeTime(iso: string | null): string {
  if (!iso) return "never";
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return `${Math.floor(s)}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

export function useApi<T>(
  loader: () => Promise<T>,
  deps: DependencyList,
  options?: { pollMs?: number },
) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [nonce, setNonce] = useState(0);
  const pollMs = options?.pollMs;
  const refetch = () => setNonce((n) => n + 1);
  useEffect(() => {
    let cancelled = false;
    // Only show the loading state on the first/dep-driven fetch, not on each
    // poll tick, so the UI refreshes in place without flicker.
    if (nonce === 0) setLoading(true);
    setError(null);
    const run = () =>
      loader()
        .then((d) => !cancelled && setData(d))
        .catch((e) => !cancelled && setError(e instanceof Error ? e.message : String(e)))
        .finally(() => !cancelled && setLoading(false));
    run();
    const timer = pollMs ? setInterval(run, pollMs) : undefined;
    return () => {
      cancelled = true;
      if (timer) clearInterval(timer);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, pollMs, nonce]);
  return { data, error, loading, refetch };
}
