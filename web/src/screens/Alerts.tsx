import { useState } from "react";
import {
  createChannel,
  createRule,
  deleteChannel,
  deleteRule,
  fetchAlerts,
  fetchChannels,
  fetchRules,
  relativeTime,
  testChannel,
  updateChannel,
  updateRule,
  useApi,
  type AlertChannel,
  type QuietHoursMode,
  type Role,
} from "../api.ts";
import type { Severity } from "../data.ts";
import { Card, SevBadge } from "../ui.tsx";

type ChannelType = AlertChannel["type"];

const CHANNEL_FIELDS: Record<ChannelType, string[]> = {
  telegram: ["bot_token", "chat_id"],
  email: ["smtp_host", "smtp_port", "username", "password", "from", "to"],
  webhook: ["url"],
};

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];
const EVENTS: ("new" | "regressed")[] = ["new", "regressed"];

const STATUS_COLOR: Record<string, string> = {
  sent: "text-emerald-400",
  failed: "text-red-400",
  pending: "text-slate-400",
};

export default function Alerts({ role }: { role: Role }) {
  const canEdit = role !== "viewer";
  const channels = useApi(fetchChannels, []);
  const rules = useApi(fetchRules, []);
  const alerts = useApi(fetchAlerts, [], { pollMs: 10000 });

  const channelRows = channels.data?.channels ?? [];
  const ruleRows = rules.data?.rules ?? [];
  const alertRows = alerts.data?.alerts ?? [];

  const [testResult, setTestResult] = useState<
    Record<string, { ok: boolean; error: string | null }>
  >({});

  const [chType, setChType] = useState<ChannelType>("telegram");
  const [chName, setChName] = useState("");
  const [chConfig, setChConfig] = useState<Record<string, string>>({});
  const [chBusy, setChBusy] = useState(false);
  const [chError, setChError] = useState<string | null>(null);

  const [ruleName, setRuleName] = useState("");
  const [ruleSev, setRuleSev] = useState<Severity>("high");
  const [ruleEvents, setRuleEvents] = useState<("new" | "regressed")[]>(["new"]);
  const [ruleChannel, setRuleChannel] = useState("");
  const [ruleBusy, setRuleBusy] = useState(false);
  const [ruleError, setRuleError] = useState<string | null>(null);

  const [quietEnabled, setQuietEnabled] = useState(false);
  const [quietStart, setQuietStart] = useState("22:00");
  const [quietEnd, setQuietEnd] = useState("07:00");
  const [quietTz, setQuietTz] = useState("UTC");
  const [quietMode, setQuietMode] = useState<QuietHoursMode>("defer");

  const onTest = async (id: string) => {
    try {
      const res = await testChannel(id);
      setTestResult((r) => ({ ...r, [id]: res }));
    } catch (e) {
      setTestResult((r) => ({
        ...r,
        [id]: { ok: false, error: e instanceof Error ? e.message : String(e) },
      }));
    }
  };

  const onAddChannel = async (e: React.FormEvent) => {
    e.preventDefault();
    setChBusy(true);
    setChError(null);
    try {
      await createChannel({ type: chType, name: chName, config: chConfig, enabled: true });
      setChName("");
      setChConfig({});
      channels.refetch();
    } catch (err) {
      setChError(err instanceof Error ? err.message : String(err));
    } finally {
      setChBusy(false);
    }
  };

  const onAddRule = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!ruleChannel) {
      setRuleError("Pick a channel.");
      return;
    }
    setRuleBusy(true);
    setRuleError(null);
    try {
      await createRule({
        name: ruleName,
        min_severity: ruleSev,
        on_events: ruleEvents,
        channel_id: ruleChannel,
        enabled: true,
        quiet_hours_start: quietEnabled ? quietStart : null,
        quiet_hours_end: quietEnabled ? quietEnd : null,
        quiet_hours_tz: quietTz,
        quiet_hours_mode: quietMode,
      });
      setRuleName("");
      rules.refetch();
    } catch (err) {
      setRuleError(err instanceof Error ? err.message : String(err));
    } finally {
      setRuleBusy(false);
    }
  };

  return (
    <div className="space-y-8">
      <h1 className="text-2xl font-semibold tracking-tight">Alerts</h1>

      <section className="space-y-5">
        <h2 className="text-sm font-medium text-slate-300">Channels &amp; rules</h2>

        <Card>
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-ink-700 text-left text-xs uppercase tracking-wide text-slate-500">
                <th className="px-4 py-3 font-medium">Type</th>
                <th className="px-4 py-3 font-medium">Name</th>
                <th className="px-4 py-3 font-medium">Enabled</th>
                <th className="px-4 py-3 font-medium">Test</th>
                {canEdit && <th className="px-4 py-3 font-medium" />}
              </tr>
            </thead>
            <tbody className="divide-y divide-ink-700">
              {channelRows.map((c) => (
                <tr key={c.id} className="hover:bg-ink-700/50">
                  <td className="px-4 py-3 text-slate-400">{c.type}</td>
                  <td className="px-4 py-3 text-slate-200">{c.name}</td>
                  <td className="px-4 py-3">
                    <button
                      disabled={!canEdit}
                      onClick={() =>
                        updateChannel(c.id, { enabled: !c.enabled }).then(channels.refetch)
                      }
                      className={c.enabled ? "text-emerald-400" : "text-slate-600"}
                    >
                      {c.enabled ? "on" : "off"}
                    </button>
                  </td>
                  <td className="px-4 py-3">
                    <button onClick={() => onTest(c.id)} className="text-accent hover:underline">
                      test
                    </button>
                    {testResult[c.id] && (
                      <span
                        className={`ml-2 ${testResult[c.id].ok ? "text-emerald-400" : "text-red-400"}`}
                        title={testResult[c.id].error ?? undefined}
                      >
                        {testResult[c.id].ok ? "✓" : `✗ ${testResult[c.id].error ?? "failed"}`}
                      </span>
                    )}
                  </td>
                  {canEdit && (
                    <td className="px-4 py-3 text-right">
                      <button
                        onClick={() => deleteChannel(c.id).then(channels.refetch)}
                        className="text-slate-500 hover:text-red-400"
                      >
                        delete
                      </button>
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
          {channels.error ? (
            <div className="px-4 py-6 text-center text-sm text-red-400">
              Failed to load channels: {channels.error}
            </div>
          ) : channelRows.length === 0 ? (
            <div className="px-4 py-6 text-center text-sm text-slate-500">
              {channels.loading ? "Loading channels…" : "No channels yet."}
            </div>
          ) : null}
        </Card>

        {canEdit && (
          <Card className="p-5">
            <div className="mb-3 text-xs font-semibold uppercase tracking-wide text-slate-400">
              Add channel
            </div>
            <form onSubmit={onAddChannel} className="space-y-3">
              <div className="flex items-center gap-2">
                <select
                  value={chType}
                  onChange={(e) => {
                    setChType(e.target.value as ChannelType);
                    setChConfig({});
                  }}
                  className="rounded-lg border border-ink-600 bg-ink-800 px-3 py-1.5 text-sm outline-none focus:border-accent"
                >
                  <option value="telegram">telegram</option>
                  <option value="email">email</option>
                  <option value="webhook">webhook</option>
                </select>
                <input
                  value={chName}
                  onChange={(e) => setChName(e.target.value)}
                  placeholder="name"
                  required
                  className="flex-1 rounded-lg border border-ink-600 bg-ink-800 px-3 py-1.5 text-sm outline-none placeholder:text-slate-600 focus:border-accent"
                />
              </div>
              <div className="grid grid-cols-2 gap-2">
                {CHANNEL_FIELDS[chType].map((field) => (
                  <input
                    key={field}
                    value={chConfig[field] ?? ""}
                    onChange={(e) => setChConfig((c) => ({ ...c, [field]: e.target.value }))}
                    placeholder={field}
                    className="rounded-lg border border-ink-600 bg-ink-800 px-3 py-1.5 text-sm outline-none placeholder:text-slate-600 focus:border-accent"
                  />
                ))}
              </div>
              {chError && <div className="text-sm text-red-400">{chError}</div>}
              <button
                type="submit"
                disabled={chBusy}
                className="rounded-lg bg-accent px-3 py-1.5 text-sm font-medium text-white hover:bg-accent/90 disabled:opacity-50"
              >
                {chBusy ? "Saving…" : "Add channel"}
              </button>
            </form>
          </Card>
        )}

        <Card>
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-ink-700 text-left text-xs uppercase tracking-wide text-slate-500">
                <th className="px-4 py-3 font-medium">Rule</th>
                <th className="px-4 py-3 font-medium">Min severity</th>
                <th className="px-4 py-3 font-medium">Events</th>
                <th className="px-4 py-3 font-medium">Channel</th>
                <th className="px-4 py-3 font-medium">Quiet hours</th>
                <th className="px-4 py-3 font-medium">Enabled</th>
                {canEdit && <th className="px-4 py-3 font-medium" />}
              </tr>
            </thead>
            <tbody className="divide-y divide-ink-700">
              {ruleRows.map((r) => (
                <tr key={r.id} className="hover:bg-ink-700/50">
                  <td className="px-4 py-3 text-slate-200">{r.name}</td>
                  <td className="px-4 py-3">
                    <SevBadge severity={r.min_severity} />
                  </td>
                  <td className="px-4 py-3 text-slate-400">{r.on_events.join(", ")}</td>
                  <td className="px-4 py-3 text-slate-400">{r.channel_name}</td>
                  <td className="px-4 py-3 text-slate-400">
                    {r.quiet_hours_start && r.quiet_hours_end ? (
                      <span title={`${r.quiet_hours_mode} · ${r.quiet_hours_tz}`}>
                        {r.quiet_hours_start}–{r.quiet_hours_end} ({r.quiet_hours_mode})
                      </span>
                    ) : (
                      <span className="text-slate-600">—</span>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <button
                      disabled={!canEdit}
                      onClick={() => updateRule(r.id, { enabled: !r.enabled }).then(rules.refetch)}
                      className={r.enabled ? "text-emerald-400" : "text-slate-600"}
                    >
                      {r.enabled ? "on" : "off"}
                    </button>
                  </td>
                  {canEdit && (
                    <td className="px-4 py-3 text-right">
                      <button
                        onClick={() => deleteRule(r.id).then(rules.refetch)}
                        className="text-slate-500 hover:text-red-400"
                      >
                        delete
                      </button>
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
          {rules.error ? (
            <div className="px-4 py-6 text-center text-sm text-red-400">
              Failed to load rules: {rules.error}
            </div>
          ) : ruleRows.length === 0 ? (
            <div className="px-4 py-6 text-center text-sm text-slate-500">
              {rules.loading ? "Loading rules…" : "No rules yet."}
            </div>
          ) : null}
        </Card>

        {canEdit && (
          <Card className="p-5">
            <div className="mb-3 text-xs font-semibold uppercase tracking-wide text-slate-400">
              Add rule
            </div>
            <form onSubmit={onAddRule} className="space-y-3">
              <div className="flex flex-wrap items-center gap-2">
                <input
                  value={ruleName}
                  onChange={(e) => setRuleName(e.target.value)}
                  placeholder="name"
                  required
                  className="flex-1 rounded-lg border border-ink-600 bg-ink-800 px-3 py-1.5 text-sm outline-none placeholder:text-slate-600 focus:border-accent"
                />
                <select
                  value={ruleSev}
                  onChange={(e) => setRuleSev(e.target.value as Severity)}
                  className="rounded-lg border border-ink-600 bg-ink-800 px-3 py-1.5 text-sm outline-none focus:border-accent"
                >
                  {SEVERITIES.map((s) => (
                    <option key={s} value={s}>
                      {s}
                    </option>
                  ))}
                </select>
                <select
                  value={ruleChannel}
                  onChange={(e) => setRuleChannel(e.target.value)}
                  className="rounded-lg border border-ink-600 bg-ink-800 px-3 py-1.5 text-sm outline-none focus:border-accent"
                >
                  <option value="">channel…</option>
                  {channelRows.map((c) => (
                    <option key={c.id} value={c.id}>
                      {c.name}
                    </option>
                  ))}
                </select>
              </div>
              <div className="flex items-center gap-4 text-sm text-slate-400">
                {EVENTS.map((ev) => (
                  <label key={ev} className="flex items-center gap-1.5">
                    <input
                      type="checkbox"
                      checked={ruleEvents.includes(ev)}
                      onChange={(e) =>
                        setRuleEvents((evs) =>
                          e.target.checked ? [...evs, ev] : evs.filter((x) => x !== ev),
                        )
                      }
                    />
                    {ev}
                  </label>
                ))}
              </div>
              <div className="space-y-2 border-t border-ink-700 pt-3">
                <label className="flex items-center gap-1.5 text-sm text-slate-400">
                  <input
                    type="checkbox"
                    checked={quietEnabled}
                    onChange={(e) => setQuietEnabled(e.target.checked)}
                  />
                  Quiet hours
                </label>
                {quietEnabled && (
                  <div className="flex flex-wrap items-center gap-2 text-sm text-slate-400">
                    <input
                      type="time"
                      value={quietStart}
                      onChange={(e) => setQuietStart(e.target.value)}
                      aria-label="quiet hours start"
                      className="rounded-lg border border-ink-600 bg-ink-800 px-3 py-1.5 text-sm outline-none focus:border-accent"
                    />
                    <span className="text-slate-500">to</span>
                    <input
                      type="time"
                      value={quietEnd}
                      onChange={(e) => setQuietEnd(e.target.value)}
                      aria-label="quiet hours end"
                      className="rounded-lg border border-ink-600 bg-ink-800 px-3 py-1.5 text-sm outline-none focus:border-accent"
                    />
                    <input
                      value={quietTz}
                      onChange={(e) => setQuietTz(e.target.value)}
                      placeholder="timezone (e.g. UTC)"
                      aria-label="quiet hours timezone"
                      className="rounded-lg border border-ink-600 bg-ink-800 px-3 py-1.5 text-sm outline-none placeholder:text-slate-600 focus:border-accent"
                    />
                    <select
                      value={quietMode}
                      onChange={(e) => setQuietMode(e.target.value as QuietHoursMode)}
                      aria-label="quiet hours mode"
                      className="rounded-lg border border-ink-600 bg-ink-800 px-3 py-1.5 text-sm outline-none focus:border-accent"
                    >
                      <option value="defer">defer</option>
                      <option value="suppress">suppress</option>
                    </select>
                  </div>
                )}
              </div>
              {ruleError && <div className="text-sm text-red-400">{ruleError}</div>}
              <button
                type="submit"
                disabled={ruleBusy}
                className="rounded-lg bg-accent px-3 py-1.5 text-sm font-medium text-white hover:bg-accent/90 disabled:opacity-50"
              >
                {ruleBusy ? "Saving…" : "Add rule"}
              </button>
            </form>
          </Card>
        )}
      </section>

      <section className="space-y-3">
        <h2 className="text-sm font-medium text-slate-300">Recent alerts</h2>
        <Card>
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-ink-700 text-left text-xs uppercase tracking-wide text-slate-500">
                <th className="px-4 py-3 font-medium">Severity</th>
                <th className="px-4 py-3 font-medium">Finding</th>
                <th className="px-4 py-3 font-medium">Host</th>
                <th className="px-4 py-3 font-medium">Event</th>
                <th className="px-4 py-3 font-medium">Status</th>
                <th className="px-4 py-3 font-medium">When</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-ink-700">
              {alertRows.map((a) => (
                <tr key={a.id} className="hover:bg-ink-700/50">
                  <td className="px-4 py-3">
                    <SevBadge severity={a.severity} />
                  </td>
                  <td className="px-4 py-3 text-slate-200">{a.title}</td>
                  <td className="px-4 py-3 font-mono text-slate-400">{a.host}</td>
                  <td className="px-4 py-3 text-slate-400">{a.event}</td>
                  <td className="px-4 py-3">
                    <span
                      className={STATUS_COLOR[a.status] ?? "text-slate-400"}
                      title={a.error ?? undefined}
                    >
                      {a.status}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-slate-500">{relativeTime(a.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {alerts.error ? (
            <div className="px-4 py-6 text-center text-sm text-red-400">
              Failed to load alerts: {alerts.error}
            </div>
          ) : alertRows.length === 0 ? (
            <div className="px-4 py-6 text-center text-sm text-slate-500">
              {alerts.loading ? "Loading alerts…" : "No alerts yet."}
            </div>
          ) : null}
        </Card>
      </section>
    </div>
  );
}
