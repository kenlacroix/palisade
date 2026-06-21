# Palisade

Attack-surface monitoring for self-hosted and AI-infra services. A pull-only
agent enrolls once, discovers listening services on-host, and runs CVE
detections locally — only normalized findings ever leave the host. A FastAPI
control plane serves a signed detection catalog, ingests findings, scores
posture, and drafts new detections from CVE advisories with an LLM.

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
control plane scores **posture** and (optionally) **AI-triages** each finding.

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
bundle. Equivalent API call:

```bash
curl -s -X POST http://127.0.0.1:8000/v1/detections -H 'content-type: application/json' -d '{
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

When `ANTHROPIC_API_KEY` is set, new findings are scored on ingest
(`triage_priority` / `triage_score` / `triage_rationale`, surfaced on the
finding read API). Best-effort and inline — it never blocks or fails ingestion,
and no-ops without a key. `PALISADE_TRIAGE_MODEL` overrides the model
(default `claude-haiku-4-5-20251001`).

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
| `PALISADE_ENROLL_TOKENS` | `PLS-DEMO` | Comma-separated accepted enroll tokens. |
| `PALISADE_SIGNING_KEY` | unset (`"stub"`) | Ed25519 seed (base64) for bundle signing. |
| `PALISADE_CATALOG_PUBKEY` | demo key | Agent-side pinned bundle pubkey (base64). |
| `ANTHROPIC_API_KEY` | unset | Enables AI drafting + finding triage. |
| `PALISADE_DETECTIONS_DIR` | repo `detections/` | Source of seeded detection YAMLs. |

## Status

Scaffold (M0). Implemented: enroll/heartbeat/scan loop, signed catalog bundles,
version-aware matching, AI drafting + accept loop, CVSS, AI triage, posture
scoring. Production TODOs (see `SPEC.md` and inline `TODO(prod)` markers): mTLS
client certs in place of bearer secrets, single-use enroll tokens, Postgres
row-level security per `org_id`, the `module` detection engine, and offloading
triage to a queue/worker.
</content>
</invoke>
