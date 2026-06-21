// Package catalog defines the shared wire types exchanged with the control
// plane and helpers for working with the detection catalog. These types are
// the source-of-truth contract; they must match the API and UI exactly.
package catalog

// ---- enrollment ----

// HostInfo describes the enrolling host.
type HostInfo struct {
	Hostname     string `json:"hostname"`
	OS           string `json:"os"`
	Arch         string `json:"arch"`
	AgentVersion string `json:"agent_version"`
}

// EnrollRequest is POST /v1/agents/enroll.
type EnrollRequest struct {
	EnrollToken string   `json:"enroll_token"`
	Host        HostInfo `json:"host"`
}

// EnrollResponse is the enroll reply containing the agent secret. When the
// control plane issues a client certificate, the PEM fields are populated and
// the agent presents them for mutual TLS on subsequent https calls.
type EnrollResponse struct {
	AgentID            string `json:"agent_id"`
	AgentSecret        string `json:"agent_secret"`
	HeartbeatIntervalS int    `json:"heartbeat_interval_s"`
	ClientCertPEM      string `json:"client_cert_pem,omitempty"`
	ClientKeyPEM       string `json:"client_key_pem,omitempty"`
	CACertPEM          string `json:"ca_cert_pem,omitempty"`
}

// ---- heartbeat / jobs ----

// HeartbeatRequest is POST /v1/agents/{id}/heartbeat.
type HeartbeatRequest struct {
	AgentVersion string `json:"agent_version"`
	Status       string `json:"status"` // "idle" | "busy"
}

// HeartbeatResponse carries jobs the agent must run.
type HeartbeatResponse struct {
	Jobs []Job `json:"jobs"`
}

// Job is a unit of work. Payload is decoded per Type.
type Job struct {
	JobID   string `json:"job_id"`
	Type    string `json:"type"` // "discover" | "scan"
	Payload Job_   `json:"payload"`
}

// Job_ is the union payload for discover and scan jobs.
type Job_ struct {
	// discover
	Scope *Scope `json:"scope,omitempty"`
	// scan
	ScanID  string       `json:"scan_id,omitempty"`
	Targets []ScanTarget `json:"targets,omitempty"`
}

// Scope is the discover payload scope.
type Scope struct {
	Subnets []string `json:"subnets"`
}

// ScanTarget pairs an asset with the detections to run against it.
type ScanTarget struct {
	AssetID      string   `json:"asset_id"`
	DetectionIDs []string `json:"detection_ids"`
}

// ---- assets ----

// Asset is a discovered listening service.
type Asset struct {
	Host     string  `json:"host"`
	Port     int     `json:"port"`
	Service  string  `json:"service"`
	Product  *string `json:"product"`
	Version  *string `json:"version"`
	Exposure string  `json:"exposure"` // "internal" | "external"
}

// AssetsRequest is POST /v1/agents/{id}/assets.
type AssetsRequest struct {
	Assets []Asset `json:"assets"`
}

// AssetsResponse maps "<host>:<port>" -> server-assigned asset id.
type AssetsResponse struct {
	AssetIDs map[string]string `json:"asset_ids"`
}

// ---- catalog bundle ----

// Bundle is GET /v1/catalog/bundle.
type Bundle struct {
	Version    int         `json:"version"`
	Detections []Detection `json:"detections"`
	Signature  string      `json:"signature"`
}

// Detection is one catalog entry (also the YAML format, SPEC section 7).
type Detection struct {
	ID          string     `json:"id"`
	Title       string     `json:"title"`
	CVE         string     `json:"cve"`
	Severity    string     `json:"severity"` // critical|high|medium|low|info
	Category    string     `json:"category"` // ai-infra|self-hosted|web|backup|observability
	Engine      string     `json:"engine"`   // nuclei|module
	Match       Match      `json:"match"`
	HTTP        []HTTPStep `json:"http,omitempty"`     // when engine=nuclei
	SpecRef     string     `json:"spec_ref,omitempty"` // when engine=module
	Remediation string     `json:"remediation"`
	References  []string   `json:"references"`
	Signature   string     `json:"signature"`
}

// Match selects which assets a detection applies to.
type Match struct {
	Service  string `json:"service"`
	Versions string `json:"versions"`
}

// HTTPStep is one request + matcher set for the nuclei engine.
type HTTPStep struct {
	Method string `json:"method"`
	Path   string `json:"path"`
	Body   string `json:"body,omitempty"`
	// MatchersCondition combines the step's matchers: "and" (default) | "or".
	MatchersCondition string    `json:"matchers-condition,omitempty"`
	Matchers          []Matcher `json:"matchers"`
}

// Matcher evaluates a response. Type is "dsl" | "word" | "status" | "regex" |
// "binary". Part selects "body" (default) or "header"; Negative inverts the
// result.
type Matcher struct {
	Type     string   `json:"type"`
	DSL      []string `json:"dsl,omitempty"`
	Words    []string `json:"words,omitempty"`
	Status   []int    `json:"status,omitempty"`
	Regex    []string `json:"regex,omitempty"`
	Binary   []string `json:"binary,omitempty"`
	Part     string   `json:"part,omitempty"`
	Negative bool     `json:"negative,omitempty"`
}

// ---- findings ----

// Evidence is the per-finding evidence blob. Raw bodies stay local; only the
// normalized request line and a short note cross the wire.
type Evidence struct {
	Request string `json:"request"`
	Note    string `json:"note"`
}

// FindingReport is POST /v1/scans/{scan_id}/findings.
type FindingReport struct {
	DetectionID string   `json:"detection_id"`
	AssetID     string   `json:"asset_id"`
	Severity    string   `json:"severity"`
	Fingerprint string   `json:"fingerprint"`
	Evidence    Evidence `json:"evidence"`
}

// FindingsRequest wraps a batch of findings.
type FindingsRequest struct {
	Findings []FindingReport `json:"findings"`
}
