import { render, screen, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import Alerts from "./Alerts.tsx";
import {
  fetchAlerts,
  fetchChannels,
  fetchRules,
  type Alert,
  type AlertChannel,
  type AlertRule,
} from "../api.ts";

vi.mock("../api.ts", async () => {
  const actual = await vi.importActual<typeof import("../api.ts")>("../api.ts");
  return {
    ...actual,
    fetchAlerts: vi.fn(),
    fetchChannels: vi.fn(),
    fetchRules: vi.fn(),
  };
});

const channel = (over: Partial<AlertChannel> = {}): AlertChannel => ({
  id: "c1",
  type: "telegram",
  name: "ops-telegram",
  config: {},
  enabled: true,
  created_at: new Date().toISOString(),
  ...over,
});

const rule = (over: Partial<AlertRule> = {}): AlertRule => ({
  id: "r1",
  name: "criticals",
  min_severity: "high",
  on_events: ["new", "regressed"],
  channel_id: "c1",
  channel_name: "ops-telegram",
  enabled: true,
  quiet_hours_start: null,
  quiet_hours_end: null,
  quiet_hours_tz: "UTC",
  quiet_hours_mode: "defer",
  created_at: new Date().toISOString(),
  ...over,
});

const alert = (over: Partial<Alert> = {}): Alert => ({
  id: "al1",
  finding_id: "f1",
  title: "Exposed admin panel",
  host: "10.0.0.5",
  severity: "critical",
  event: "new",
  status: "sent",
  error: null,
  channel_name: "ops-telegram",
  created_at: new Date().toISOString(),
  sent_at: new Date().toISOString(),
  ...over,
});

const mockFetchAlerts = vi.mocked(fetchAlerts);
const mockFetchChannels = vi.mocked(fetchChannels);
const mockFetchRules = vi.mocked(fetchRules);

describe("Alerts", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockFetchChannels.mockResolvedValue({ channels: [channel()] });
    mockFetchRules.mockResolvedValue({ rules: [rule()] });
  });

  it("renders alert rows reflecting severity, host, event, and status", async () => {
    mockFetchAlerts.mockResolvedValue({
      alerts: [
        alert(),
        alert({ id: "al2", title: "TLS weak cipher", severity: "medium", status: "failed", event: "regressed" }),
      ],
    });

    render(<Alerts role="admin" />);

    const row = (await screen.findByText("Exposed admin panel")).closest("tr");
    expect(row).not.toBeNull();
    const scoped = within(row as HTMLElement);
    expect(scoped.getByText("critical")).toBeInTheDocument();
    expect(scoped.getByText("10.0.0.5")).toBeInTheDocument();
    expect(scoped.getByText("new")).toBeInTheDocument();
    expect(scoped.getByText("sent")).toBeInTheDocument();

    const failedRow = screen.getByText("TLS weak cipher").closest("tr");
    expect(within(failedRow as HTMLElement).getByText("failed")).toBeInTheDocument();
  });

  it("renders the rule and channel rows", async () => {
    mockFetchAlerts.mockResolvedValue({ alerts: [] });

    render(<Alerts role="admin" />);

    expect(await screen.findByText("criticals")).toBeInTheDocument();
    expect(screen.getAllByText("ops-telegram").length).toBeGreaterThan(0);
    expect(screen.getByText("new, regressed")).toBeInTheDocument();
  });

  it("renders the empty state when there are no alerts", async () => {
    mockFetchAlerts.mockResolvedValue({ alerts: [] });

    render(<Alerts role="admin" />);

    expect(await screen.findByText("No alerts yet.")).toBeInTheDocument();
  });
});
