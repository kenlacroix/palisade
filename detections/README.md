# Palisade Detection Catalog

Git-backed, versioned detections authored in YAML. Each file describes one CVE
detection. The control plane compiles these into signed bundles and serves them
to agents via `GET /v1/catalog/bundle`. Agents verify the signature, then run the
detection locally so raw internal traffic never leaves the network.

## Files

- `detection.schema.json` — JSON Schema (draft 2020-12) for the detection format.
- `<id>.yaml` — one detection per file.
- `validate.py` — validates every `*.yaml` here against the schema.
- `requirements.txt` — Python deps for the validator.

## Format

Every detection is an object with these fields:

| Field         | Type   | Required | Notes |
|---------------|--------|----------|-------|
| `id`          | string | yes | Stable slug, `kebab-case`. Matches the filename. |
| `title`       | string | yes | Human-readable name. |
| `cve`         | string | yes | `CVE-YYYY-NNNN+`. |
| `severity`    | enum   | yes | `critical` \| `high` \| `medium` \| `low` \| `info`. |
| `category`    | enum   | yes | `ai-infra` \| `self-hosted` \| `web` \| `backup` \| `observability`. |
| `engine`      | enum   | yes | `nuclei` \| `module`. Selects how the detection executes (see below). |
| `match`       | object | yes | `{ service, versions }` — used server-side to match assets to this detection. `versions` is a version range string (e.g. `<1.40.2`). |
| `http`        | array  | nuclei only | Inline HTTP probes. Required when `engine: nuclei`; forbidden otherwise. |
| `spec_ref`    | string | module only | Reference to a compiled Go module (e.g. `modules/nextjs_middleware_bypass`). Required when `engine: module`; forbidden otherwise. |
| `remediation` | string | yes | Fix guidance. |
| `references`  | array  | yes | One or more URIs (advisory, NVD, etc.). |
| `signature`   | string | yes | Minisign signature over the detection. Currently stubbed as `"stub"`. |

### `http[]` (nuclei engine)

Each entry is one request:

| Field      | Type   | Required | Notes |
|------------|--------|----------|-------|
| `method`   | enum   | yes | `GET` / `POST` / `PUT` / `PATCH` / `DELETE` / `HEAD` / `OPTIONS`. |
| `path`     | string | yes | Request path. |
| `body`     | string | no  | Request body. |
| `matchers` | array  | yes | One or more matchers; all must be present to flag (see types). |

Matcher types:

- `dsl` — requires `dsl: [str]`, Nuclei DSL expressions (e.g. `["duration>=5"]` for time-based detection).
- `word` — requires `words: [str]`, substrings expected in the response.
- `status` — requires `status: [int]`, acceptable HTTP status codes.

## nuclei vs module

- **`engine: nuclei`** — declarative HTTP detection expressed inline via `http`.
  The agent's embedded Nuclei engine runs the probes and evaluates matchers. Use
  for anything expressible as request + response matching.
- **`engine: module`** — a compiled Go module referenced by `spec_ref` (no inline
  `http`). Use for detection logic too stateful or complex for declarative
  matchers (multi-step, header-injection bypasses, protocol-level checks). The
  agent dispatches to the named module instead of the Nuclei engine.

The schema enforces this: `nuclei` requires `http` and forbids `spec_ref`;
`module` requires `spec_ref` and forbids `http`.

## How the control plane serves these

1. Author merges/signs a detection YAML; the catalog version increments.
2. The control plane bundles all detections into the wire `Detection` shape and
   exposes them at `GET /v1/catalog/bundle?since=<int>`:
   ```json
   { "version": 1, "detections": [ ...Detection ], "signature": "stub" }
   ```
   The wire `Detection` mirrors this YAML 1:1 (same fields, same enums).
3. Agents poll the bundle, verify `signature` (minisign — stubbed for now),
   match assets to detections by `match.service` + `match.versions`, and execute
   each detection locally, reporting normalized findings to
   `POST /v1/scans/{scan_id}/findings`.

A reported finding's `fingerprint` is
`sha256_hex("<asset_id>|<detection_id>|<short_evidence_key>")`.

## Adding a new detection

1. Create `detections/<id>.yaml` with `id` matching the filename slug.
2. Fill required fields. Pick `engine`:
   - `nuclei` → add an `http` block with matchers.
   - `module` → add `spec_ref` pointing at the Go module.
3. Add `remediation` and at least one `references` URI.
4. Leave `signature: stub` (signing is wired later).
5. Validate:
   ```sh
   python -m venv .venv && . .venv/bin/activate
   pip install -r requirements.txt
   python validate.py
   ```
   Every file must print `PASS`.

## TODO

- Production auth is **mTLS** for agent calls; the current scaffold uses a bearer
  `agent_secret`. Migrate to client-cert auth before GA.
- `signature` is stubbed (`"stub"`). Implement minisign signing + agent-side
  verification of the bundle before execution.
