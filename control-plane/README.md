# Palisade Control Plane

FastAPI control plane for Palisade. Implements the agent enroll/heartbeat/scan
loop, a detection catalog, finding ingestion + triage state, multi-tenant auth
(users/sessions/orgs + RBAC), alerting (channels/rules/history), and UI BFF read
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
then seeds the demo org, the demo user (`demo@palisade.local` / `palisade`, org
owner), a single-use `PLS-DEMO` enroll token, and the seeded detections.

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
| `PALISADE_ENROLL_TOKENS` | `PLS-DEMO` | Comma-separated, single-use enroll tokens. Each mints one agent into the token's org. Rotate for prod. |
| `PALISADE_DEMO_USER_EMAIL` | `demo@palisade.local` | Demo user seeded into the demo org (owner). |
| `PALISADE_DEMO_USER_PASSWORD` | `palisade` | Demo user password. Change/remove before exposing. |
| `PALISADE_SESSION_TTL_S` | `604800` (7d) | Web UI bearer-session lifetime, seconds. |
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

# 7) log in (UI/BFF reads require a user session, distinct from agent secrets)
TOKEN=$(curl -s $BASE/v1/auth/login -H 'content-type: application/json' \
  -d '{"email":"demo@palisade.local","password":"palisade"}' \
  | python -c "import sys,json;print(json.load(sys.stdin)['token'])")
UAUTH="Authorization: Bearer $TOKEN"

# 8) read APIs — scoped to the session's active org (current_org)
curl -s "$BASE/v1/assets" -H "$UAUTH"
curl -s "$BASE/v1/findings?status=open&severity=critical" -H "$UAUTH"
curl -s "$BASE/v1/posture/summary" -H "$UAUTH"
```

## Auth & multi-tenancy (M1)

Two distinct credentials: **agent secrets** (`Authorization: Bearer <agent_secret>`
on `/v1/agents`, `/v1/scans`, and `/v1/catalog`) and **user sessions** (`Authorization: Bearer
<session-token>` on every `/v1` BFF read/mutation). Sessions are minted by
`POST /v1/auth/login`; the rest of the auth surface is `POST /v1/auth/logout`,
`GET /v1/auth/me`, and `POST /v1/auth/switch-org`.

- **Org scoping** is per-request via `app/tenancy.py:current_org` (resolved from
  the session's active org; no longer a hardcoded demo org). On Postgres it also
  `SET LOCAL app.current_org_id`, which migration 0003 ties to Row-Level Security
  policies on the tenant tables (agent, asset, scan, finding, alert_channel,
  alert_rule, alert, posture_snapshot). RLS DDL is skipped on SQLite.
- **Roles** (`models.ROLES`, most→least privileged): owner, admin, member, viewer.
  Reads need any role; mute/rescan need member+; accept-detection and alert
  channel/rule mutations need admin+ (`tenancy.require_role`).
- **Enroll tokens** (`enroll_token` table) are single-use: a token mints one agent,
  binds it to the token's org, and is marked used. Seeded from
  `PALISADE_ENROLL_TOKENS` at bootstrap.
- **Postgres RLS:** run the app as a **non-owner** role in prod — the table owner
  bypasses RLS. Bootstrap relies on owner-bypass to seed cross-org rows. Known
  limitation: the `/v1/detections` catalog `tenants_hit` / `tenants_total`
  cross-tenant aggregate is RLS-scoped on Postgres and needs a
  security-definer/unscoped path to be a true platform metric (prod follow-up).

## Alerting (M3)

Channels (telegram / email / webhook), rules (`min_severity` + `on_events`
[`new` | `regressed`] → channel), and an alert history table. Endpoints:

```
GET    /v1/alerts
GET    /v1/alert-channels
POST   /v1/alert-channels
PATCH  /v1/alert-channels/{id}
DELETE /v1/alert-channels/{id}
POST   /v1/alert-channels/{id}/test
GET    /v1/alert-rules
POST   /v1/alert-rules
PATCH  /v1/alert-rules/{id}
DELETE /v1/alert-rules/{id}
```

Channel config shapes: telegram `{bot_token, chat_id}`; email `{smtp_host,
smtp_port, username, password, from, to}`; webhook `{url}`. Secret keys
(`bot_token`, `password`, `username`) are redacted on read. On finding ingest,
matching rules are evaluated inside the request transaction and matching alerts
are delivered in a FastAPI `BackgroundTask` (`app/alerting.py:deliver_pending` +
`app/notify.py` senders) so network I/O never blocks the agent. AI triage was
moved off the request path into the same background mechanism.

## Production TODOs

- **mTLS:** agent calls authenticate with a bearer `agent_secret` returned by
  enroll. Production target is mTLS client certs (SPEC section 8). Not yet done.
- **Catalog aggregate under RLS:** the `/v1/detections` cross-tenant
  `tenants_hit` / `tenants_total` metric is RLS-scoped on Postgres and needs a
  security-definer/unscoped path to count across all orgs.
- **Detection engine:** only the `nuclei` engine runs; `module` detections are
  not yet executable.
- **Queue/worker:** alerting delivery and AI triage run in FastAPI
  `BackgroundTasks`; prod should offload to a real queue/worker (SPEC: Arq + Redis).

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
  AI-triaged when `ANTHROPIC_API_KEY` is set, in a background task off the
  ingest request path (`app/triage.py`, scheduled from `app/routers/scans.py`).
- **Multi-tenancy (M1):** users/sessions/memberships, org-scoped RBAC, single-use
  enroll tokens, and Postgres Row-Level Security per `org_id` (migration 0003,
  `app/tenancy.py`).
- **Alerting (M3):** channels/rules/history with telegram/email/webhook delivery
  (`app/alerting.py`, `app/notify.py`).
- **Real posture trends:** `posture/summary.trend30d` is computed from daily
  `posture_snapshot` upserts, reconstructing pre-feature days from finding
  `first_seen`/`last_seen` (`app/snapshots.py`).
