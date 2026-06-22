# Palisade — Security Model

Palisade is a multi-tenant attack-surface monitor: a FastAPI **control plane**
(Postgres + Redis), a React **web** UI, and a Go **agent** that scans hosts and
reports findings. The control plane holds every tenant's assets, findings, the
internal mTLS CA private key, and the catalog-signing key, so it is the asset
that matters most.

This document is the threat model and the operator hardening checklist. The
controls below were added in the security-hardening pass; see
`control-plane/app/preflight.py` for the startup gate that enforces several of
them.

## Trust boundaries

- **Internet → API.** A Cloudflare Tunnel publishes `api.trypalisade.dev →
  api:8000` (`control-plane/deploy/cloudflared/config.yml`). The entire `/v1/*`
  surface — including agent enroll/heartbeat/ingest — is internet-reachable.
  Postgres and Redis are not tunneled.
- **Web → API.** Session bearer token, now also delivered as an httpOnly cookie
  (see below).
- **Agent → API.** mTLS client cert (preferred) or a bearer `agent_secret`.
- **API → Postgres.** The app connects as the database role and is bound by
  Row-Level Security (see below). DB credentials never leave the control plane.

## What an attacker could try, and what stops them

| Surface | Risk | Control |
| --- | --- | --- |
| `POST /v1/detections/draft` (`cve_url`) | Authenticated SSRF to cloud metadata / internal services; prompt injection | `app/netguard.py`: scheme allowlist, resolve + reject private/loopback/link-local/reserved IPs, **validated-IP pinning** into the connection, no redirect following. Returns empty on any block. |
| Agent findings ingest (`POST /v1/scans/{id}/findings`) | A compromised agent attaches findings to another tenant's scan/assets, or overwrites another tenant's finding via a shared fingerprint | `scan_id` and every `asset_id` are bound to the agent's org at the boundary (`routers/scans.py`); dedupe is org-scoped (`ingest.py`); fingerprints are unique **per org** (`uq_finding_org_fingerprint`). |
| Cross-tenant DB access via an app-layer bug | RLS was only `ENABLE`d, which Postgres does not apply to the table owner — and the app connects as the owner, so isolation rode entirely on Python `WHERE org_id` filters | Migration `0011` adds **`FORCE ROW LEVEL SECURITY`** on all tenant tables, making the `app.current_org_id` GUC a real DB-level backstop. Proven in CI (`app/rls_postgres_test.py`). |
| Catalog bundle forgery | With no signing key set, the server signed with the **public demo seed**; agents pin the matching public key, so anyone could forge a trusted bundle | The startup preflight refuses to boot a production deployment whose `PALISADE_SIGNING_KEY` is unset or the demo seed. |
| Stolen DB dump | The internal CA private key was stored unencrypted, letting an attacker mint trusted agent certs; evidence was plaintext | CA key and evidence are sealed with AES-256-GCM under `PALISADE_EVIDENCE_KEK` (`app/encryption.py`, `enc:v1:` format), with transparent plaintext fallback for keyless dev. |
| Stolen bearer `agent_secret` | Authenticates as the agent over plaintext | `PALISADE_REQUIRE_MTLS` defaults **on** in production; the bearer fallback is rejected when a client cert is required. |
| Default credentials | `palisade:palisade`, demo login `palisade`, demo agent secret | The preflight refuses to boot production while any public default is in place. |
| XSS stealing the session token | Token in `localStorage` was exfiltratable | Token is delivered as an **httpOnly, Secure, SameSite=Lax cookie**; the web app keeps it in memory only and relies on the cookie across reloads. Header bearer still works for agents/tests. |
| Unbounded perimeter scanning | Empty scope allowlist meant scan-all | Empty allowlist is **deny-all in production**, allow-all only for dev/demo (`perimeter.py`). |

## The startup security gate

On a **Postgres** deployment that has not set `PALISADE_ALLOW_INSECURE_DEFAULTS`,
the control plane **refuses to start** while any of these public defaults remain
(`app/preflight.py`):

- `DATABASE_URL` using `palisade:palisade`
- `PALISADE_SIGNING_KEY` unset or equal to the public demo seed
- `PALISADE_DEMO_USER_PASSWORD` still `palisade`
- `PALISADE_EVIDENCE_KEK` unset

SQLite (dev/test) and the public demo (which sets
`PALISADE_ALLOW_INSECURE_DEFAULTS=1`) downgrade these to logged warnings so the
one-command local workflow and the live demo keep working.

> **The public demo is intentionally insecure.** It runs on default credentials
> and the public signing key by design. Never point a real tenant at it.

## Production hardening checklist

Set these before exposing an instance (see `control-plane/.env.example`):

1. **Unset `PALISADE_ALLOW_INSECURE_DEFAULTS`** (or set it to `0`).
2. **`DATABASE_URL`** — unique DB password (`openssl rand -hex 24`).
3. **`PALISADE_SIGNING_KEY`** — fresh Ed25519 seed
   (`python -c "import os,base64;print(base64.b64encode(os.urandom(32)).decode())"`)
   and pin its public key on agents via `PALISADE_CATALOG_PUBKEY`.
4. **`PALISADE_EVIDENCE_KEK`** — base64 32-byte key; seals evidence and the CA key.
5. **`PALISADE_DEMO_USER_PASSWORD`** — change it, or remove the demo user.
6. **`PALISADE_REQUIRE_MTLS`** — left on by default in production; keep it on and
   terminate TLS at a proxy that verifies the client cert against the CA.
7. **`PALISADE_PERIMETER_SCOPE_ALLOWLIST`** — confirm in-scope hosts before any
   control-plane probe leaves the box.

## Residual risks / future work

- **Run the app as a non-owner Postgres role.** `FORCE` makes RLS real today;
  connecting as a dedicated non-owner role (the architecture the worker docs
  already assume) would be defense-in-depth on top of it.
- **CSRF.** With cookie auth, `SameSite=Lax` + header-precedence cover the common
  cases; an explicit CSRF token on mutating endpoints would harden it further.
- **SSRF TOCTOU.** Mitigated by pinning the validated IP into the connection;
  the narrow residual is resolver behavior between validation and connect.
