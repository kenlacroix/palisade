# Palisade Control Plane

FastAPI control plane for Palisade. Implements the agent enroll/heartbeat/scan
loop, a detection catalog, finding ingestion + triage state, and UI BFF read
APIs. Runs with **zero infra** on sqlite by default.

## Run — Docker (primary path)

The whole stack (FastAPI + Postgres) from one command. Same image on laptop,
Proxmox, and VPS — only `.env` changes.

```bash
cp .env.example .env
docker compose up --build
```

API docs at http://127.0.0.1:8000/docs. On startup the app runs
`alembic upgrade head` (migrations are the schema source of truth, idempotent),
then loads the demo org + seeded detections.

## Migrations

```bash
make migrate                      # apply to head (sqlite default, or DATABASE_URL)
make revision m="add users table" # autogenerate after changing models.py
make check                        # fail if models drift from migrations
```

Startup auto-migrates, so local/sqlite and the compose api just work. For
multi-replica prod, run `alembic upgrade head` as a one-shot step before the
app instead (see `app/db.py` TODO).

## Run — bare Python (zero infra, sqlite)

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload   # DATABASE_URL unset -> sqlite:///./palisade.db
```

## Environment

All knobs live in `app/config.py` and are read from env. See `.env.example`.

| Var | Default | Notes |
|-----|---------|-------|
| `DATABASE_URL` | `sqlite:///./palisade.db` | Compose sets the Postgres URL. |
| `PALISADE_ENROLL_TOKENS` | `PLS-DEMO` | Comma-separated accepted enroll tokens. Rotate for prod. |
| `PALISADE_CORS_ORIGINS` | localhost:5173/3000 | Set to your UI domain on the VPS. |
| `PALISADE_DETECTIONS_DIR` | repo `detections/` | Container sets `/app/detections`. |
| `PALISADE_SIGNING_KEY` | unset (`"stub"`) | Ed25519 seed (base64) for catalog bundle signing. |
| `ANTHROPIC_API_KEY` | unset | Enables AI drafting (`/v1/detections/draft`) + finding triage. |
| `PALISADE_DRAFT_MODEL` | `claude-opus-4-8` | Model for CVE-URL drafting. |
| `PALISADE_TRIAGE_MODEL` | `claude-haiku-4-5-20251001` | Model for finding triage. |

Detections are seeded from every `*.yaml` in `PALISADE_DETECTIONS_DIR` if it
exists, otherwise from two inline fallbacks (`litellm-proxy-preauth-sqli`,
`audiobookshelf-authbypass`).

## Smoke test

```bash
python -m app.smoke_test     # full loop, unsigned path (or: pytest app/smoke_test.py)
python -m app.api_test       # signed bundle, draft/accept, version match, cvss, mute, triage
```

Smoke runs enroll -> heartbeat(discover) -> assets -> heartbeat(scan) ->
findings -> posture against an isolated temp DB. Both run as plain scripts
(no pytest required).

## Curl walkthrough

```bash
BASE=http://127.0.0.1:8000

# 1) enroll -> capture agent_id + agent_secret
curl -s $BASE/v1/agents/enroll -H 'content-type: application/json' -d '{
  "enroll_token":"PLS-DEMO",
  "host":{"hostname":"nas","os":"linux","arch":"amd64","agent_version":"0.1.0"}
}'

AGENT=<agent_id>; SECRET=<agent_secret>
AUTH="Authorization: Bearer $SECRET"

# 2) heartbeat -> discover job
curl -s $BASE/v1/agents/$AGENT/heartbeat -H "$AUTH" -H 'content-type: application/json' \
  -d '{"agent_version":"0.1.0","status":"idle"}'

# 3) report assets
curl -s $BASE/v1/agents/$AGENT/assets -H "$AUTH" -H 'content-type: application/json' -d '{
  "assets":[{"host":"ai.lab","port":4000,"service":"litellm","product":"litellm","version":"1.39.0","exposure":"external"}]
}'

# 4) catalog bundle
curl -s "$BASE/v1/catalog/bundle?since=0" -H "$AUTH"

# 5) heartbeat -> scan job (note the scan_id + asset_id)
curl -s $BASE/v1/agents/$AGENT/heartbeat -H "$AUTH" -H 'content-type: application/json' \
  -d '{"agent_version":"0.1.0","status":"idle"}'

# 6) report a finding (fingerprint = sha256("<asset_id>|<detection_id>|<short_evidence_key>"))
SCAN=<scan_id>; ASSET=<asset_id>
FP=$(python -c "from app.fingerprint import finding_fingerprint as f;print(f('$ASSET','litellm-proxy-preauth-sqli','sleep5'))")
curl -s $BASE/v1/scans/$SCAN/findings -H "$AUTH" -H 'content-type: application/json' -d "{
  \"findings\":[{\"detection_id\":\"litellm-proxy-preauth-sqli\",\"asset_id\":\"$ASSET\",\"severity\":\"critical\",\"fingerprint\":\"$FP\",\"evidence\":{\"request\":\"POST /key/info\",\"note\":\"delayed >=5s\"}}]
}"

# 7) read APIs
curl -s "$BASE/v1/assets"
curl -s "$BASE/v1/findings?status=open&severity=critical"
curl -s "$BASE/v1/posture/summary"
```

## Auth / production TODOs

- **mTLS:** this scaffold uses a bearer `agent_secret` returned by enroll.
  Production target is mTLS client certs (SPEC section 8). Not implemented here.
- **Single-use enroll tokens:** currently repeated enrollment is accepted.
- **Row-Level Security:** prod uses Postgres RLS keyed on `org_id`; the scaffold
  uses a single hardcoded demo org and app-layer scoping only.
- **Triage queue:** finding triage runs inline/best-effort on ingest; prod
  should offload it to a queue/worker.

## Implemented

- **Version range matching:** scan targeting matches on `match.service` **and**
  `match.versions` (comma/space-separated constraints; unknown asset versions
  fail open). See `app/version_match.py`.
- **Bundle signing:** when `PALISADE_SIGNING_KEY` is set the catalog bundle is
  Ed25519-signed over a canonical manifest; the agent verifies it against a
  pinned pubkey before running detections. Unset → `signature` stays `"stub"`
  (dev mode). See `app/signing.py`.
- **Draft → accept loop:** `POST /v1/detections/draft` drafts from a CVE URL
  (needs `ANTHROPIC_API_KEY`); `POST /v1/detections` persists a reviewed draft
  and bumps the catalog version.
- **CVSS + AI triage:** detections carry a `cvss` score; new findings are
  AI-triaged on ingest when `ANTHROPIC_API_KEY` is set (`app/triage.py`).
