from __future__ import annotations

import os
from pathlib import Path

# Single place every deploy knob is read. Local, Proxmox, and VPS are the same
# image with different values here. No host-specific paths baked into code.

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./palisade.db")


def allow_insecure_defaults() -> bool:
    # Escape hatch for local dev and the public demo: when set, the startup
    # preflight (app/preflight.py) downgrades insecure-default findings from a
    # hard boot failure to a logged warning. NEVER set this on an exposed deploy.
    return os.environ.get("PALISADE_ALLOW_INSECURE_DEFAULTS", "").lower() in ("1", "true", "yes")


def is_production() -> bool:
    # A real (internet-exposed) deployment. True when the operator declares it
    # via PALISADE_ENV=production, or when it's inferred from infrastructure:
    # Postgres-backed and not explicitly opting into insecure defaults. Dev/test
    # runs on SQLite and the public demo sets PALISADE_ALLOW_INSECURE_DEFAULTS=1,
    # so neither is treated as prod. Drives fail-closed defaults (mTLS required,
    # perimeter scope deny-by-default, preflight enforcement, and refusing the
    # well-known demo enroll token/password at boot).
    if os.environ.get("PALISADE_ENV", "dev").lower() in ("prod", "production"):
        return True
    return DATABASE_URL.startswith("postgresql") and not allow_insecure_defaults()


# Durable job queue (Arq + Redis). Unset -> triage/alert delivery fall back to
# in-process FastAPI BackgroundTasks (the dev/SQLite path; no Redis required).
# Set in production so background work survives restarts and the API can scale.
REDIS_URL = os.environ.get("REDIS_URL", "")

# Detections are seeded from this dir at startup; falls back to inline seeds in
# catalog.py if the dir is absent. Default resolves to the repo's detections/.
_DEFAULT_DETECTIONS = Path(__file__).resolve().parents[2] / "detections"
DETECTIONS_DIR = os.environ.get("PALISADE_DETECTIONS_DIR", str(_DEFAULT_DETECTIONS))


# AI drafting for "New from CVE URL". Absent key -> the endpoint returns 503.
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
DRAFT_MODEL = os.environ.get("PALISADE_DRAFT_MODEL", "claude-opus-4-8")
TRIAGE_MODEL = os.environ.get("PALISADE_TRIAGE_MODEL", "claude-haiku-4-5-20251001")

# Ed25519 secret seed (base64) used to sign the catalog bundle. Unset -> "stub".
SIGNING_KEY = os.environ.get("PALISADE_SIGNING_KEY", "")

# Master key-encryption key (base64, 32 bytes) for evidence-at-rest. Wraps a
# per-org data key; finding evidence is sealed with AES-256-GCM under that key.
# Unset -> encryption disabled and evidence is stored as plaintext JSON (dev).
EVIDENCE_KEK = os.environ.get("PALISADE_EVIDENCE_KEK", "")


def enroll_tokens() -> set[str]:
    raw = os.environ.get("PALISADE_ENROLL_TOKENS", "PLS-DEMO")
    return {t.strip() for t in raw.split(",") if t.strip()}


# Lifetime of an admin-minted enroll token (default 15 min, matching the
# onboarding UI). Env-seeded bootstrap tokens never expire (expires_at is null).
ENROLL_TOKEN_TTL_S = int(os.environ.get("PALISADE_ENROLL_TOKEN_TTL_S", str(15 * 60)))


# Lifetime of an env-seeded bootstrap enroll token. Re-armed (expires_at pushed
# forward) on each boot so a restart re-enables enrollment, but a long-running
# control plane never keeps an indefinitely valid bootstrap token. Default 24h.
BOOTSTRAP_TOKEN_TTL_S = int(os.environ.get("PALISADE_BOOTSTRAP_TOKEN_TTL_S", str(24 * 3600)))


# --- multi-tenancy (M1) ---
# Bootstrap seeds this user into the demo org so the demo logs in with one click.
DEMO_USER_EMAIL = os.environ.get("PALISADE_DEMO_USER_EMAIL", "demo@palisade.local")
DEMO_USER_PASSWORD_DEFAULT = "palisade"
DEMO_USER_PASSWORD = os.environ.get("PALISADE_DEMO_USER_PASSWORD", DEMO_USER_PASSWORD_DEFAULT)
# Session lifetime for the web UI bearer token (default 7 days).
SESSION_TTL_S = int(os.environ.get("PALISADE_SESSION_TTL_S", str(7 * 24 * 3600)))


# --- demo experience (M-demo) ---
# Seed a believable, populated dataset into the demo org at bootstrap so a fresh
# deploy looks like a live product. Idempotent; safe to leave on across reboots.
def seed_demo() -> bool:
    return os.environ.get("PALISADE_SEED_DEMO", "").lower() in ("1", "true", "yes")


# Public read-only demo: user-session mutations scoped to the demo org are
# rejected with 403. Agent endpoints (enroll/heartbeat/assets/findings) are
# unaffected so the live demo loop keeps writing findings.
def demo_mode() -> bool:
    return os.environ.get("PALISADE_DEMO_MODE", "").lower() in ("1", "true", "yes")


# --- agent mTLS (production hardening) ---
# When true, agent endpoints REQUIRE a verified client cert and the bearer-secret
# fallback is rejected. Default false so the plaintext demo/dev still works.
def require_mtls() -> bool:
    v = os.environ.get("PALISADE_REQUIRE_MTLS")
    if v is not None:
        return v.lower() in ("1", "true", "yes")
    # Unset: required by default in a hardened production deployment, so a stolen
    # bearer agent_secret alone can't authenticate an agent. Relaxed for dev/test
    # (SQLite) and the public demo, where agents enroll over plaintext and rely
    # on the bearer fallback. Set explicitly to override either way.
    return is_production()


# Header carrying the PEM client cert from a TLS-terminating proxy (nginx
# $ssl_client_escaped_cert / Caddy). The app verifies it against the internal CA.
MTLS_CERT_HEADER = os.environ.get("PALISADE_MTLS_HEADER", "x-client-cert")
# Validity window for issued client certs (days).
MTLS_CERT_DAYS = int(os.environ.get("PALISADE_MTLS_CERT_DAYS", "397"))


def db_app_role() -> str:
    # Postgres role the control plane drops to (SET LOCAL ROLE) before touching
    # tenant data, so Row-Level Security actually binds. The connecting role is
    # typically the cluster superuser/owner in bundled setups, which RLS (even
    # FORCEd) does not constrain; this NOLOGIN, NOSUPERUSER role (migration 0012)
    # is the one the policies apply to. Empty string disables the drop.
    return os.environ.get("PALISADE_DB_APP_ROLE", "palisade_app").strip()


def cors_origins() -> list[str]:
    raw = os.environ.get(
        "PALISADE_CORS_ORIGINS",
        "http://localhost:5173,http://127.0.0.1:5173,http://localhost:3000,http://127.0.0.1:3000",
    )
    return [o.strip() for o in raw.split(",") if o.strip()]


# --- responsible scanning (SPEC §428) ---
# Control-plane perimeter probes are paced so a scan never hammers a target.
# PERIMETER_RATE_LIMIT_RPS caps outbound requests/sec per host (<=0 disables
# pacing). PERIMETER_MIN_INTERVAL_S forces a minimum gap between probes to the
# same host (0 = derive from RPS). PERIMETER_MAX_REQUESTS_PER_SCAN hard-bounds
# total probes in a contiguous scan burst so a runaway scan can't fan out.
PERIMETER_RATE_LIMIT_RPS = float(os.environ.get("PALISADE_PERIMETER_RATE_LIMIT_RPS", "5.0"))
PERIMETER_MIN_INTERVAL_S = float(os.environ.get("PALISADE_PERIMETER_MIN_INTERVAL_S", "0"))
PERIMETER_MAX_REQUESTS_PER_SCAN = int(
    os.environ.get("PALISADE_PERIMETER_MAX_REQUESTS_PER_SCAN", "500")
)


# --- cron scheduler (SPEC §177) ---
# Cadence knobs for the Arq worker's cron jobs (app/scheduler.py). These only
# take effect when REDIS_URL is set and the Arq worker runs; the dev/SQLite
# in-process fallback has no scheduler.
# SCAN_EVERY_HOURS: perimeter scan fires at minute 0 of every Nth hour
#   (1..24; clamped). DEFERRED_RELEASE_EVERY_MIN: quiet-hours deferred-alert
#   release cadence in minutes (1..60; clamped, must divide an hour cleanly for
#   even spacing — non-divisors are accepted and arq fires on the matching
#   minutes-of-hour set). SNAPSHOT_UTC_HOUR: hour (0..23, UTC) the daily posture
#   snapshot runs.
SCAN_EVERY_HOURS = max(1, min(24, int(os.environ.get("PALISADE_SCAN_EVERY_HOURS", "6"))))
DEFERRED_RELEASE_EVERY_MIN = max(
    1, min(60, int(os.environ.get("PALISADE_DEFERRED_RELEASE_EVERY_MIN", "5")))
)
SNAPSHOT_UTC_HOUR = max(0, min(23, int(os.environ.get("PALISADE_SNAPSHOT_UTC_HOUR", "0"))))


# --- observability (Prometheus metrics + structured logs for Loki/promtail) ---
# METRICS_ENABLED gates the /metrics endpoint and per-request metrics middleware.
# LOG_LEVEL sets the root logging level; LOG_FORMAT is "json" (Loki-parseable,
# default) or "text" (human-readable for local dev).
def metrics_enabled() -> bool:
    return os.environ.get("PALISADE_METRICS_ENABLED", "true").lower() not in ("0", "false", "no")


LOG_LEVEL = os.environ.get("PALISADE_LOG_LEVEL", "INFO").upper()
LOG_FORMAT = os.environ.get("PALISADE_LOG_FORMAT", "json").lower()


def perimeter_scope_allowlist() -> list[str]:
    # Comma-separated hosts / domain suffixes / CIDRs the operator confirms are
    # in scope. EMPTY default = deny-all in production (is_production()) so a
    # misconfigured prod never probes an unconfirmed target, and allow-all for
    # dev/demo so the SQLite path and back-compat flow keep working. Set this in
    # production to confirm scope before any probe leaves the box.
    raw = os.environ.get("PALISADE_PERIMETER_SCOPE_ALLOWLIST", "")
    return [s.strip() for s in raw.split(",") if s.strip()]
