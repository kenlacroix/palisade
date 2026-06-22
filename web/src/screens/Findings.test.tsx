import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import Dashboard from "./Dashboard.tsx";
import FindingDetail from "./FindingDetail.tsx";
import {
  fetchAssets,
  fetchFindings,
  fetchPostureSummary,
  type ApiAsset,
  type ApiFinding,
  type PostureSummary,
} from "../api.ts";

vi.mock("../api.ts", async () => {
  const actual = await vi.importActual<typeof import("../api.ts")>("../api.ts");
  return {
    ...actual,
    fetchFindings: vi.fn(),
    fetchPostureSummary: vi.fn(),
    fetchAssets: vi.fn(),
  };
});

const finding = (over: Partial<ApiFinding> = {}): ApiFinding => ({
  id: "f1",
  detection_id: "d-cve-2024-1234",
  asset_id: "a1",
  host: "10.0.0.5",
  port: 443,
  title: "Apache path traversal",
  cve: "CVE-2024-1234",
  severity: "critical",
  status: "open",
  fingerprint: "abc123",
  evidence: { request: "GET /../../etc/passwd", note: "root:x:0:0 leaked" },
  remediation: "Upgrade to 2.4.59.",
  references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-1234"],
  first_seen: new Date().toISOString(),
  last_seen: new Date().toISOString(),
  ...over,
});

const posture = (): PostureSummary => ({
  score: 72,
  counts: { critical: 1, high: 2, medium: 3, assets: 5 },
  trend30d: [70, 71, 72],
});

const asset = (): ApiAsset => ({
  id: "a1",
  host: "10.0.0.5",
  port: 443,
  service: "apache",
  product: "apache",
  version: "2.4.58",
  exposure: "external",
  findings_critical: 1,
  findings_high: 0,
  findings_open: 1,
  last_seen: new Date().toISOString(),
});

const mockFetchFindings = vi.mocked(fetchFindings);
const mockFetchPosture = vi.mocked(fetchPostureSummary);
const mockFetchAssets = vi.mocked(fetchAssets);

describe("Findings list (Dashboard)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockFetchPosture.mockResolvedValue(posture());
  });

  it("renders open findings with title, host, and severity", async () => {
    mockFetchFindings.mockResolvedValue({ findings: [finding()] });

    render(<Dashboard onOpenFinding={() => {}} />);

    expect(await screen.findByText("Apache path traversal")).toBeInTheDocument();
    expect(screen.getByText("10.0.0.5:443")).toBeInTheDocument();
  });

  it("omits resolved findings from the attention list", async () => {
    mockFetchFindings.mockResolvedValue({
      findings: [finding({ id: "f2", title: "Resolved one", status: "resolved" })],
    });

    render(<Dashboard onOpenFinding={() => {}} />);

    expect(await screen.findByText("Nothing open. Clean.")).toBeInTheDocument();
    expect(screen.queryByText("Resolved one")).not.toBeInTheDocument();
  });

  it("calls onOpenFinding with the finding id when a row is clicked", async () => {
    mockFetchFindings.mockResolvedValue({ findings: [finding()] });
    const onOpenFinding = vi.fn();

    render(<Dashboard onOpenFinding={onOpenFinding} />);

    await userEvent.click(await screen.findByText("Apache path traversal"));
    expect(onOpenFinding).toHaveBeenCalledWith("f1");
  });
});

describe("Finding detail", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockFetchAssets.mockResolvedValue({ assets: [asset()] });
  });

  it("renders severity, evidence, and detection metadata for a finding", async () => {
    mockFetchFindings.mockResolvedValue({ findings: [finding()] });

    render(<FindingDetail findingId="f1" onBack={() => {}} />);

    expect(await screen.findByText("Apache path traversal")).toBeInTheDocument();
    expect(screen.getByText("critical")).toBeInTheDocument();
    expect(screen.getByText("CVE-2024-1234")).toBeInTheDocument();
    expect(screen.getByText("GET /../../etc/passwd")).toBeInTheDocument();
    expect(screen.getByText("→ root:x:0:0 leaked")).toBeInTheDocument();
    expect(screen.getByText("abc123")).toBeInTheDocument();
    expect(screen.getByText("Upgrade to 2.4.59.")).toBeInTheDocument();
  });

  it("shows a not-found message for an unknown finding id", async () => {
    mockFetchFindings.mockResolvedValue({ findings: [finding()] });

    render(<FindingDetail findingId="missing" onBack={() => {}} />);

    expect(await screen.findByText("Finding not found.")).toBeInTheDocument();
  });

  it("invokes onBack when the back control is clicked", async () => {
    mockFetchFindings.mockResolvedValue({ findings: [finding()] });
    const onBack = vi.fn();

    render(<FindingDetail findingId="f1" onBack={onBack} />);

    await userEvent.click(await screen.findByText("‹ back"));
    expect(onBack).toHaveBeenCalledTimes(1);
  });
});
