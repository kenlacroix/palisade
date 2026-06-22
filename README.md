# Palisade

Attack-surface monitoring for self-hosted and AI-infra services. A pull-only
agent enrolls once, discovers listening services on-host, and runs CVE
detections locally — only normalized findings ever leave the host. A FastAPI
control plane serves a signed detection catalog, ingests findings, scores
posture (with real 30-day trends), alerts on new/regressed findings, and drafts
new detections from CVE advisories with an LLM. Multi-tenant: users, orgs,
session auth, role-based access, and Postgres row-level isolation.

## Architecture

| Component | Path | Stack |
|-----------|------|-------|
| **Control plane** | `control-plane/` | FastAPI + SQLAlchemy + Alembic (sqlite by default, Postgres in compose) |
| **Agent** | `agent/` | Go 1.22, stdlib-only, runs on each monitored host |
| **Web UI** | `web/` | React + TypeScript + Vite + Tailwind |
| **Detections** | `detections/` | YAML specs validated against `detection.schema.json` |

The loop: agent **enroll** → **heartbeat** → control plane issues a **discover**
job → agent reports **assets** → heartbeat issues a **scan** job (detections
matched by service **and** version range) → agent pulls the **signed catalog
bundle**, verifies it, runs detections on-host → reports **findings** →
control plane scores **posture**, evaluates **alert rules** (delivering matching
alerts in the background), and (optionally) **AI-triages** each finding off the
request path.

The web UI is multi-tenant: log in (`demo@palisade.local` / `palisade` in the
demo), and all `/v1` read endpoints are scoped to your active org with role-based
access (owner/admin/member/viewer).

## Quickstart (zero infra, sqlite)

Requires Go 1.22+, Python 3.12, Node 18+.

```bash
# 1. control plane
make venv                       # create control-plane/.venv + install deps
make migrate                    # apply migrations (sqlite:///./palisade.db)
cd control-plane && PALISADE_ENROLL_TOKENS=PLS-DEMO \
  ./.venv/bin/uvicorn app.main:app --reload     # http://127.0.0.1:8000/docs

# 2. web UI (separate terminal) — vite proxies /v1 to the control plane
cd web && npm install && npm run dev            # http://127.0.0.1:5173
```

Or run the whole stack (FastAPI + Postgres) in Docker:

```bash
cd control-plane && cp .env.example .env && docker compose up --build
```

## End-to-end demo

`DEMO.md` walks the full on-host loop: start the control plane, expose a
fake-vulnerable LiteLLM target on port 4000, enroll + run the agent, and watch a
real critical finding (`litellm-proxy-preauth-sqli`, CVE-2026-42208) appear via
the read APIs, then mute it and watch posture recover.

```bash
make smoke        # enroll → discover → assets → scan → findings → posture (temp DB)
```

## Signed catalog bundles

The control plane signs the detection bundle with Ed25519 over a canonical
manifest; the agent rebuilds the same manifest and verifies it against a pinned
public key before running **any** detection — integrity over an untrusted
channel. A demo keypair ships in `.env.example`.

```bash
# control plane: enable signing with the demo key
cd control-plane
PALISADE_SIGNING_KEY=70kJtI1NajTd1yQXFHVRuBVQfc6P2CAtRroaLCmYYbY= \
  ./.venv/bin/uvicorn app.main:app --reload
```

The agent pins the matching public key (override with `PALISADE_CATALOG_PUBKEY`);
the bundled default matches the demo seed. Verification policy:

- empty signature → refuse to scan;
- `"stub"` (no signing key set) → proceed in dev mode with a warning;
- otherwise → verify, and refuse to run detections if it fails.

Generate your own keypair:

```bash
cd control-plane && ./.venv/bin/python -c "import os,base64;from app import _ed25519 as e;s=os.urandom(32);print('PALISADE_SIGNING_KEY=',base64.b64encode(s).decode());print('pubkey         =',base64.b64encode(e.publickey(s)).decode())"
```

Set the printed seed as `PALISADE_SIGNING_KEY` on the control plane and the
pubkey as `PALISADE_CATALOG_PUBKEY` on the agent.

## Draft → review → accept (close the loop)

In the **Detections** screen, **+ New from CVE URL** drafts a detection from an
advisory with an LLM (requires `ANTHROPIC_API_KEY` on the control plane;
otherwise the endpoint returns 503). Review the draft, then **Accept & ship** to
persist it — this bumps the catalog version so agents pull it on their next
bundle. Equivalent API call (admin+ session bearer required; see DEMO.md for
`$TOKEN`):

```bash
curl -s -X POST http://127.0.0.1:8000/v1/detections \
  -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' -d '{
  "id":"acme-rce","title":"ACME RCE","cve":"CVE-2026-9999","severity":"high",
  "category":"web","engine":"nuclei","match":{"service":"acme","versions":"<2.0.0"},
  "http":[{"method":"GET","path":"/x","matchers":[{"type":"status","status":[200]}]}],
  "remediation":"upgrade to >=2.0.0","references":["https://example.com"],"cvss":7.5
}'   # -> {"id":"acme-rce","version":<bumped>}
```

## Version-aware scan matching

Detections target assets by service **and** version range. `match.versions`
accepts comma/space-separated constraints (`<1.40.2`, `>=11.1.4 <15.2.3`); a
`litellm <1.40.2` detection fires on `1.39.0` but not `1.41.0`. Unknown/missing
asset versions fail **open** (scanned anyway) so a vuln is never silently
skipped.

## AI triage

When `ANTHROPIC_API_KEY` is set, new findings are scored after ingest
(`triage_priority` / `triage_score` / `triage_rationale`, surfaced on the
finding read API). Best-effort and run in a background task off the ingest
request path — it never blocks or fails ingestion, and no-ops without a key.
`PALISADE_TRIAGE_MODEL` overrides the model (default
`claude-haiku-4-5-20251001`).

## Alerting

Define **channels** (telegram / email / webhook) and **rules** (`min_severity` +
`on_events` `[new|regressed]` → channel) from the **Alerts** screen or the API.
On finding ingest, matching rules fire and alerts are delivered in a background
task; an alert history is kept and surfaced at `GET /v1/alerts`. Channel secrets
are redacted on read.

```bash
BASE=http://127.0.0.1:8000; UAUTH="Authorization: Bearer $TOKEN"   # see DEMO.md for $TOKEN
# webhook channel + a rule that fires on any high+ new/regressed finding
CH=$(curl -s -X POST $BASE/v1/alert-channels -H "$UAUTH" -H 'content-type: application/json' \
  -d '{"type":"webhook","name":"local","config":{"url":"http://127.0.0.1:9000/hook"}}' \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['id'])")
curl -s -X POST $BASE/v1/alert-rules -H "$UAUTH" -H 'content-type: application/json' \
  -d "{\"name\":\"high+\",\"min_severity\":\"high\",\"on_events\":[\"new\",\"regressed\"],\"channel_id\":\"$CH\"}"
```

## Tests

```bash
make test                                         # Go agent tests + smoke + detection validation
cd control-plane && ./.venv/bin/python -m app.api_test          # new endpoint coverage (signed path)
cd control-plane && ./.venv/bin/python -m app.smoke_test        # full loop (unsigned path)
cd agent && go test ./...                                       # agent unit tests incl. manifest verify
```

`pytest` is optional; both Python test modules run as plain scripts via
`python -m`.

## Configuration

All knobs live in `control-plane/app/config.py`, read from env — see
`control-plane/.env.example` and `control-plane/README.md` for the full table.
Key vars:

| Var | Default | Notes |
|-----|---------|-------|
| `DATABASE_URL` | `sqlite:///./palisade.db` | Compose sets the Postgres URL. |
| `PALISADE_ENROLL_TOKENS` | `PLS-DEMO` | Comma-separated, single-use enroll tokens (each mints one agent into the token's org). |
| `PALISADE_DEMO_USER_EMAIL` | `demo@palisade.local` | Demo org owner seeded at bootstrap. |
| `PALISADE_DEMO_USER_PASSWORD` | `palisade` | Demo user password. |
| `PALISADE_SESSION_TTL_S` | `604800` (7d) | Web UI bearer-session lifetime, seconds. |
| `PALISADE_SIGNING_KEY` | unset (demo key) | Ed25519 seed (base64) for bundle signing. Unset signs with the **public** demo key and warns — set it in production. |
| `PALISADE_CATALOG_PUBKEY` | demo key | Agent-side pinned bundle pubkey (base64); must match the signing key. |
| `PALISADE_ALLOW_UNSIGNED` | unset | Agent dev escape hatch — if set, runs unsigned/`stub` bundles instead of refusing. Never set in production. |
| `ANTHROPIC_API_KEY` | unset | Enables AI drafting + finding triage. |
| `PALISADE_DETECTIONS_DIR` | repo `detections/` | Source of seeded detection YAMLs. |

## Status

Implemented: enroll/heartbeat/scan loop, **Ed25519-signed catalog bundles**
(agent verifies before running any detection and fails closed; `detections/README.md`
covers keygen/rotation), version-aware
matching, AI drafting + accept loop, CVSS, background AI triage, posture scoring
with real 30-day trends, multi-tenancy (users/sessions/orgs + RBAC, single-use
enroll tokens, Postgres row-level security per `org_id`), alerting
(channels/rules/history), agent **mTLS** (enroll issues a client cert from an
internal CA; verified at a TLS-terminating proxy, with the bearer `agent_secret`
as the plaintext-demo fallback), and a `SECURITY DEFINER` path so the
cross-tenant catalog aggregate (`tenants_hit` / `tenants_total`) is correct under
RLS on Postgres, a durable **Arq + Redis** queue/worker for AI triage and
alert delivery (with an in-process `BackgroundTasks` fallback when `REDIS_URL`
is unset), and a pluggable **`module` detection engine** (a compiled `spec_ref`
registry in the agent; first module is the Next.js middleware bypass,
CVE-2025-29927). Production TODOs (see `SPEC.md` and inline `TODO(prod)`
markers): per-org encryption of evidence at rest and alert quiet hours.
</content>
</invoke>
