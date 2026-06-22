import { render, screen, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import Audit from "./Audit.tsx";
import { fetchAudit, type AuditEntry } from "../api.ts";

vi.mock("../api.ts", async () => {
  const actual = await vi.importActual<typeof import("../api.ts")>("../api.ts");
  return {
    ...actual,
    fetchAudit: vi.fn(),
  };
});

const entry = (over: Partial<AuditEntry> = {}): AuditEntry => ({
  id: "a1",
  actor: "alice@acme.test",
  action: "agent.enroll-token.mint",
  target: "label:nas",
  at: new Date().toISOString(),
  ...over,
});

const mockFetchAudit = vi.mocked(fetchAudit);

describe("Audit", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("renders an audit row with actor, action, and target", async () => {
    mockFetchAudit.mockResolvedValue({ entries: [entry()] });

    render(<Audit />);

    const row = (await screen.findByText("alice@acme.test")).closest("tr");
    expect(row).not.toBeNull();
    const scoped = within(row as HTMLElement);
    expect(scoped.getByText("agent.enroll-token.mint")).toBeInTheDocument();
    expect(scoped.getByText("label:nas")).toBeInTheDocument();
  });

  it("renders the empty state when there are no entries", async () => {
    mockFetchAudit.mockResolvedValue({ entries: [] });

    render(<Audit />);

    expect(await screen.findByText("No audited actions yet.")).toBeInTheDocument();
  });
});
