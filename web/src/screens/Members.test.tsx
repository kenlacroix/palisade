import { render, screen, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import Members from "./Members.tsx";
import { fetchMembers, type MemberRow } from "../api.ts";

vi.mock("../api.ts", async () => {
  const actual = await vi.importActual<typeof import("../api.ts")>("../api.ts");
  return {
    ...actual,
    fetchMembers: vi.fn(),
    addMember: vi.fn(),
    updateMemberRole: vi.fn(),
    removeMember: vi.fn(),
  };
});

const member = (over: Partial<MemberRow> = {}): MemberRow => ({
  user_id: "u1",
  email: "alice@acme.test",
  name: "Alice",
  role: "admin",
  created_at: new Date().toISOString(),
  ...over,
});

const mockFetchMembers = vi.mocked(fetchMembers);

describe("Members", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("renders a member row with email, name, and role", async () => {
    mockFetchMembers.mockResolvedValue({ members: [member()] });

    render(<Members />);

    const row = (await screen.findByText("alice@acme.test")).closest("tr");
    expect(row).not.toBeNull();
    const scoped = within(row as HTMLElement);
    expect(scoped.getByText("Alice")).toBeInTheDocument();
    expect(scoped.getByLabelText("role for alice@acme.test")).toHaveValue("admin");
  });

  it("renders the empty state when there are no members", async () => {
    mockFetchMembers.mockResolvedValue({ members: [] });

    render(<Members />);

    expect(await screen.findByText("No members yet.")).toBeInTheDocument();
  });
});
