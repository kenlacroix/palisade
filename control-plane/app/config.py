from __future__ import annotations

import os
from pathlib import Path

# Single place every deploy knob is read. Local, Proxmox, and VPS are the same
# image with different values here. No host-specific paths baked into code.

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./palisade.db")

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


# --- multi-tenancy (M1) ---
# Bootstrap seeds this user into the demo org so the demo logs in with one click.
DEMO_USER_EMAIL = os.environ.get("PALISADE_DEMO_USER_EMAIL", "demo@palisade.local")
DEMO_USER_PASSWORD = os.environ.get("PALISADE_DEMO_USER_PASSWORD", "palisade")
# Session lifetime for the web UI bearer token (default 7 days).
SESSION_TTL_S = int(os.environ.get("PALISADE_SESSION_TTL_S", str(7 * 24 * 3600)))


# --- agent mTLS (production hardening) ---
# When true, agent endpoints REQUIRE a verified client cert and the bearer-secret
# fallback is rejected. Default false so the plaintext demo/dev still works.
def require_mtls() -> bool:
    return os.environ.get("PALISADE_REQUIRE_MTLS", "").lower() in ("1", "true", "yes")


# Header carrying the PEM client cert from a TLS-terminating proxy (nginx
# $ssl_client_escaped_cert / Caddy). The app verifies it against the internal CA.
MTLS_CERT_HEADER = os.environ.get("PALISADE_MTLS_HEADER", "x-client-cert")
# Validity window for issued client certs (days).
MTLS_CERT_DAYS = int(os.environ.get("PALISADE_MTLS_CERT_DAYS", "397"))


def cors_origins() -> list[str]:
    raw = os.environ.get(
        "PALISADE_CORS_ORIGINS",
        "http://localhost:5173,http://127.0.0.1:5173,http://localhost:3000,http://127.0.0.1:3000",
    )
    return [o.strip() for o in raw.split(",") if o.strip()]
