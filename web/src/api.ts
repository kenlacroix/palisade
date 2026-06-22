import { useEffect, useState, type DependencyList } from "react";
import type { Severity, Exposure } from "./data.ts";

// Same-origin by default; vite dev proxies /v1 to the control plane. Override
// with VITE_API_BASE (e.g. http://nas.lab:8000) when serving the built UI.
const BASE = import.meta.env.VITE_API_BASE ?? "";

const TOKEN_KEY = "palisade_token";
let token: string | null = localStorage.getItem(TOKEN_KEY);

export function getToken(): string | null {
  return token;
}

export function setToken(t: string): void {
  token = t;
  localStorage.setItem(TOKEN_KEY, t);
}

export function clearToken(): void {
  token = null;
  localStorage.removeItem(TOKEN_KEY);
}

type Method = "GET" | "POST" | "PUT" | "PATCH" | "DELETE";

async function request<T>(method: Method, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = {};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (token) headers["Authorization"] = `Bearer ${token}`;
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (res.status === 401) {
    clearToken();
    window.dispatchEvent(new Event("palisade-unauthorized"));
    throw new Error(`${path} → 401 Unauthorized`);
  }
  if (!res.ok) throw new Error(`${path} → ${res.status} ${res.statusText}`);
  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}

const get = <T>(path: string) => request<T>("GET", path);
const post = <T>(path: string, body?: unknown) => request<T>("POST", path, body);
const patch = <T>(path: string, body?: unknown) => request<T>("PATCH", path, body);
const del = <T>(path: string) => request<T>("DELETE", path);

export interface ApiAsset {
  id: string;
  host: string;
  port: number;
  service: string;
  product: string | null;
  version: string | null;
  exposure: Exposure;
  scheme?: "http" | "https" | null;
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

export interface EnrollToken {
  token: string;
  label: string;
  expires_at: string | null;
  used_at: string | null;
  created_at: string | null;
}

export const mintEnrollToken = (label = "") =>
  post<EnrollToken>("/v1/agents/enroll-tokens", { label });

export const triggerExternalScan = () =>
  post<{ enqueued: boolean; external_assets: number }>("/v1/scans/external");

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

export type Role = "owner" | "admin" | "member" | "viewer";

export interface Membership {
  org_id: string;
  org_name: string;
  role: Role;
}

export interface AuthUser {
  id: string;
  email: string;
  name: string;
}

export interface Session {
  user: AuthUser;
  org_id: string;
  org_name: string;
  role: Role;
  memberships: Membership[];
}

export interface LoginResponse extends Session {
  token: string;
}

export const login = (email: string, password: string) =>
  post<LoginResponse>("/v1/auth/login", { email, password });

export const logout = () => post<void>("/v1/auth/logout");

export const fetchMe = () => get<Session>("/v1/auth/me");

export const switchOrg = (org_id: string) => post<Session>("/v1/auth/switch-org", { org_id });

export interface AlertChannel {
  id: string;
  type: "telegram" | "email" | "webhook";
  name: string;
  config: Record<string, string>;
  enabled: boolean;
  created_at: string;
}

export type QuietHoursMode = "defer" | "suppress";

export interface AlertRule {
  id: string;
  name: string;
  min_severity: Severity;
  on_events: ("new" | "regressed")[];
  channel_id: string;
  channel_name: string;
  enabled: boolean;
  quiet_hours_start: string | null;
  quiet_hours_end: string | null;
  quiet_hours_tz: string;
  quiet_hours_mode: QuietHoursMode;
  created_at: string;
}

export interface Alert {
  id: string;
  finding_id: string;
  title: string;
  host: string;
  severity: Severity;
  event: string;
  status: "sent" | "failed" | "pending";
  error: string | null;
  channel_name: string;
  created_at: string;
  sent_at: string | null;
}

export const fetchAlerts = () => get<{ alerts: Alert[] }>("/v1/alerts");

export const fetchChannels = () => get<{ channels: AlertChannel[] }>("/v1/alert-channels");

export const createChannel = (body: {
  type: AlertChannel["type"];
  name: string;
  config: Record<string, string>;
  enabled: boolean;
}) => post<AlertChannel>("/v1/alert-channels", body);

export const updateChannel = (
  id: string,
  body: Partial<{ name: string; config: Record<string, string>; enabled: boolean }>,
) => patch<AlertChannel>(`/v1/alert-channels/${id}`, body);

export const deleteChannel = (id: string) => del<void>(`/v1/alert-channels/${id}`);

export const testChannel = (id: string) =>
  post<{ ok: boolean; error: string | null }>(`/v1/alert-channels/${id}/test`);

export const fetchRules = () => get<{ rules: AlertRule[] }>("/v1/alert-rules");

export const createRule = (body: {
  name: string;
  min_severity: Severity;
  on_events: ("new" | "regressed")[];
  channel_id: string;
  enabled: boolean;
  quiet_hours_start?: string | null;
  quiet_hours_end?: string | null;
  quiet_hours_tz?: string;
  quiet_hours_mode?: QuietHoursMode;
}) => post<AlertRule>("/v1/alert-rules", body);

export const updateRule = (
  id: string,
  body: Partial<{
    name: string;
    min_severity: Severity;
    on_events: ("new" | "regressed")[];
    channel_id: string;
    enabled: boolean;
    quiet_hours_start: string | null;
    quiet_hours_end: string | null;
    quiet_hours_tz: string;
    quiet_hours_mode: QuietHoursMode;
  }>,
) => patch<AlertRule>(`/v1/alert-rules/${id}`, body);

export const deleteRule = (id: string) => del<void>(`/v1/alert-rules/${id}`);

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
