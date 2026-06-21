from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

Severity = Literal["critical", "high", "medium", "low", "info"]
Exposure = Literal["internal", "external"]


# --- enroll ---
class HostInfo(BaseModel):
    hostname: str
    os: str
    arch: str
    agent_version: str


class EnrollRequest(BaseModel):
    enroll_token: str
    host: HostInfo


class EnrollResponse(BaseModel):
    agent_id: str
    agent_secret: str
    heartbeat_interval_s: int = 30
    # mTLS material issued at enroll. The agent presents client_cert_pem on every
    # request once enrolled; bearer (agent_secret) remains the dev/plaintext path.
    client_cert_pem: str | None = None
    client_key_pem: str | None = None
    ca_cert_pem: str | None = None


# --- heartbeat ---
class HeartbeatRequest(BaseModel):
    agent_version: str
    status: Literal["idle", "busy"]


class Job(BaseModel):
    job_id: str
    type: Literal["discover", "scan"]
    payload: dict[str, Any]


class HeartbeatResponse(BaseModel):
    jobs: list[Job]


# --- assets ---
class AssetIn(BaseModel):
    host: str
    port: int
    service: str
    product: str | None = None
    version: str | None = None
    exposure: Exposure


class AssetsRequest(BaseModel):
    assets: list[AssetIn]


class AssetsResponse(BaseModel):
    asset_ids: dict[str, str]


# --- catalog ---
class DetectionMatch(BaseModel):
    service: str
    versions: str


class Detection(BaseModel):
    id: str
    title: str
    cve: str | None = None
    severity: Severity
    category: Literal["ai-infra", "self-hosted", "web", "backup", "observability"]
    engine: Literal["nuclei", "module"]
    match: DetectionMatch
    http: list[dict[str, Any]] | None = None
    spec_ref: str | None = None
    remediation: str
    references: list[str]
    signature: str
    cvss: float | None = None


class CatalogBundle(BaseModel):
    version: int
    detections: list[Detection]
    signature: str


# --- AI detection drafting ("New from CVE URL") ---
class DraftMatcher(BaseModel):
    type: Literal["status", "word", "dsl"]
    status: list[int] | None = None
    words: list[str] | None = None
    dsl: list[str] | None = None


class DraftHttpStep(BaseModel):
    method: Literal["GET", "POST", "PUT", "DELETE", "HEAD"]
    path: str
    body: str | None = None
    matchers: list[DraftMatcher]


class DraftDetection(BaseModel):
    id: str
    title: str
    cve: str | None = None
    severity: Severity
    category: Literal["ai-infra", "self-hosted", "web", "backup", "observability"]
    engine: Literal["nuclei", "module"]
    match: DetectionMatch
    http: list[DraftHttpStep]
    remediation: str
    references: list[str]
    cvss: float | None = None


class AcceptDetectionRequest(BaseModel):
    id: str
    title: str
    cve: str | None = None
    severity: Severity
    category: Literal["ai-infra", "self-hosted", "web", "backup", "observability"]
    engine: Literal["nuclei", "module"]
    match: DetectionMatch
    http: list[DraftHttpStep] | None = None
    spec_ref: str | None = None
    remediation: str
    references: list[str]
    cvss: float | None = None


class AcceptDetectionResponse(BaseModel):
    id: str
    version: int


class DraftRequest(BaseModel):
    cve_url: str


class DraftResponse(BaseModel):
    detection: DraftDetection
    source_url: str
    model: str
    # Drafts are never auto-shipped — a human reviews and signs before tenants get it.
    signature: Literal["unsigned-draft"] = "unsigned-draft"


# --- findings ingest ---
class Evidence(BaseModel):
    request: str
    note: str


class FindingReport(BaseModel):
    detection_id: str
    asset_id: str
    severity: str
    fingerprint: str
    evidence: Evidence


class FindingsRequest(BaseModel):
    findings: list[FindingReport]


# --- read APIs ---
class AssetRow(BaseModel):
    id: str
    host: str
    port: int
    service: str
    product: str | None
    version: str | None
    exposure: str
    findings_critical: int
    findings_high: int
    findings_open: int
    last_seen: str | None


class AssetsList(BaseModel):
    assets: list[AssetRow]


class FindingRow(BaseModel):
    id: str
    detection_id: str
    asset_id: str
    host: str
    port: int
    title: str
    cve: str | None
    severity: str
    status: str
    fingerprint: str
    evidence: dict[str, Any]
    remediation: str | None
    references: list[str]
    first_seen: str | None
    last_seen: str | None
    triage_priority: str | None = None
    triage_score: int | None = None
    triage_rationale: str | None = None


class FindingsList(BaseModel):
    findings: list[FindingRow]


class MuteRequest(BaseModel):
    reason: str
    ttl_s: int = Field(default=3600, ge=0)


class RescanResponse(BaseModel):
    agents_nudged: int


class DetectionRow(BaseModel):
    slug: str
    title: str
    severity: str
    category: str
    tenants_hit: int
    tenants_total: int
    version: int
    cvss: float | None = None


class DetectionsList(BaseModel):
    detections: list[DetectionRow]


class AgentRow(BaseModel):
    id: str
    name: str
    status: str
    online: bool
    last_seen: str | None


class AgentsList(BaseModel):
    agents: list[AgentRow]


class PostureCounts(BaseModel):
    critical: int
    high: int
    medium: int
    assets: int


class PostureSummary(BaseModel):
    score: int
    counts: PostureCounts
    trend30d: list[int]


# --- auth / multi-tenancy ---
Role = Literal["owner", "admin", "member", "viewer"]


class LoginRequest(BaseModel):
    email: str
    password: str


class UserInfo(BaseModel):
    id: str
    email: str
    name: str


class MembershipRow(BaseModel):
    org_id: str
    org_name: str
    role: Role


class SessionInfo(BaseModel):
    token: str
    user: UserInfo
    org_id: str
    org_name: str
    role: Role
    memberships: list[MembershipRow]


class MeResponse(BaseModel):
    user: UserInfo
    org_id: str
    org_name: str
    role: Role
    memberships: list[MembershipRow]


class SwitchOrgRequest(BaseModel):
    org_id: str


# --- alerting ---
class AlertChannelCreate(BaseModel):
    type: Literal["telegram", "email", "webhook"]
    name: str
    config: dict[str, Any] = Field(default_factory=dict)
    enabled: bool = True


class AlertChannelRow(BaseModel):
    id: str
    type: str
    name: str
    # Secret-bearing keys are redacted on read; see alerts router.
    config: dict[str, Any]
    enabled: bool
    created_at: str | None


class AlertChannelsList(BaseModel):
    channels: list[AlertChannelRow]


class AlertRuleCreate(BaseModel):
    name: str
    min_severity: Severity = "high"
    on_events: list[Literal["new", "regressed"]] = Field(default_factory=lambda: ["new", "regressed"])
    channel_id: str
    enabled: bool = True


class AlertRuleRow(BaseModel):
    id: str
    name: str
    min_severity: str
    on_events: list[str]
    channel_id: str
    channel_name: str
    enabled: bool
    created_at: str | None


class AlertRulesList(BaseModel):
    rules: list[AlertRuleRow]


class AlertRow(BaseModel):
    id: str
    finding_id: str
    title: str
    host: str
    severity: str
    event: str
    status: str
    error: str | None
    channel_name: str | None
    created_at: str | None
    sent_at: str | None


class AlertsList(BaseModel):
    alerts: list[AlertRow]


class ChannelTestResponse(BaseModel):
    ok: bool
    error: str | None = None
