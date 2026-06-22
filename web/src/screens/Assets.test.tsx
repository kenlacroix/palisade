import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import Assets from "./Assets.tsx";
import { fetchAssets, type ApiAsset } from "../api.ts";

vi.mock("../api.ts", async () => {
  const actual = await vi.importActual<typeof import("../api.ts")>("../api.ts");
  return {
    ...actual,
    fetchAssets: vi.fn(),
    triggerExternalScan: vi.fn(),
  };
});

const asset = (over: Partial<ApiAsset> = {}): ApiAsset => ({
  id: "a1",
  host: "10.0.0.5",
  port: 443,
  service: "nginx",
  product: "nginx",
  version: "1.25.3",
  exposure: "external",
  findings_critical: 2,
  findings_high: 1,
  findings_open: 3,
  last_seen: new Date().toISOString(),
  ...over,
});

const mockFetchAssets = vi.mocked(fetchAssets);

describe("Assets", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("renders assets with host/port, service, version, and exposure", async () => {
    mockFetchAssets.mockResolvedValue({
      assets: [
        asset(),
        asset({
          id: "a2",
          host: "10.0.0.6",
          port: 22,
          service: "openssh",
          version: null,
          exposure: "internal",
          findings_critical: 0,
          findings_high: 0,
        }),
      ],
    });

    render(<Assets role="admin" />);

    expect(await screen.findByText("10.0.0.5:443")).toBeInTheDocument();
    expect(screen.getByText("nginx")).toBeInTheDocument();
    expect(screen.getByText("1.25.3")).toBeInTheDocument();
    expect(screen.getAllByText("external").length).toBeGreaterThan(0);

    expect(screen.getByText("10.0.0.6:22")).toBeInTheDocument();
    expect(screen.getByText("openssh")).toBeInTheDocument();
    expect(screen.getByText("—")).toBeInTheDocument();
    expect(screen.getByText("✓ clean")).toBeInTheDocument();
  });

  it("renders the scheme prefix for an https asset and omits it when absent", async () => {
    mockFetchAssets.mockResolvedValue({
      assets: [
        asset({ id: "s1", host: "10.0.0.7", port: 443, scheme: "https" }),
        asset({ id: "s2", host: "10.0.0.8", port: 80, scheme: null }),
      ],
    });

    render(<Assets role="admin" />);

    expect(await screen.findByText("https://10.0.0.7:443")).toBeInTheDocument();
    expect(screen.getByText("10.0.0.8:80")).toBeInTheDocument();
  });

  it("shows critical and high finding counts", async () => {
    mockFetchAssets.mockResolvedValue({ assets: [asset()] });

    render(<Assets role="admin" />);

    expect(await screen.findByText("⛔ 2")).toBeInTheDocument();
    expect(screen.getByText("⚠ 1")).toBeInTheDocument();
  });

  it("renders the empty state when there are no assets", async () => {
    mockFetchAssets.mockResolvedValue({ assets: [] });

    render(<Assets role="admin" />);

    expect(
      await screen.findByText("No assets yet — enroll an agent to start discovery."),
    ).toBeInTheDocument();
  });

  it("hides the external scan button for viewers", async () => {
    mockFetchAssets.mockResolvedValue({ assets: [] });

    render(<Assets role="viewer" />);

    await screen.findByText(/No assets yet/);
    expect(screen.queryByRole("button", { name: "External scan" })).not.toBeInTheDocument();
  });
});
