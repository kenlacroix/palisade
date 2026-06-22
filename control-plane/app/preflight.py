"""Startup security preflight: refuse to boot a production deployment that is
still carrying public default secrets.

A real (Postgres-backed, not PALISADE_ALLOW_INSECURE_DEFAULTS) deployment that
ships with the demo DB password, the public catalog-signing seed, the default
demo login, or no evidence/CA key-encryption KEK is trivially compromised — so
we fail closed (raise, container won't start) rather than warn. Dev/test (SQLite)
and the public demo (which sets the escape hatch) only log the findings, so the
one-command local workflow and the live demo keep working.
"""

from __future__ import annotations

import logging

from . import config
from .signing import DEMO_SEED_B64

log = logging.getLogger("palisade.preflight")

# The shipped demo login password (config.DEMO_USER_PASSWORD default).
_DEFAULT_DEMO_PASSWORD = "palisade"


def security_issues() -> list[str]:
    """Insecure-default findings for the current config, newest concern first.
    Empty when the deployment has rotated every public default."""
    issues: list[str] = []

    db = config.DATABASE_URL
    if db.startswith("postgresql") and "palisade:palisade@" in db:
        issues.append(
            "DATABASE_URL uses the public default credentials 'palisade:palisade' — "
            "set a unique database password."
        )
    if not config.SIGNING_KEY or config.SIGNING_KEY == DEMO_SEED_B64:
        issues.append(
            "PALISADE_SIGNING_KEY is unset or the public demo seed — signed catalog "
            "bundles are forgeable; generate a fresh Ed25519 seed and pin its public "
            "key on agents (PALISADE_CATALOG_PUBKEY)."
        )
    if config.DEMO_USER_PASSWORD == _DEFAULT_DEMO_PASSWORD:
        issues.append(
            "PALISADE_DEMO_USER_PASSWORD is the public default 'palisade' — change it "
            "or remove the demo user before exposing the instance."
        )
    if not config.EVIDENCE_KEK:
        issues.append(
            "PALISADE_EVIDENCE_KEK is unset — finding evidence and the internal mTLS "
            "CA private key are stored unencrypted at rest; set a base64 32-byte KEK."
        )
    return issues


def enforce() -> None:
    """Fail closed on insecure defaults in production; warn (and continue) for
    dev/test/demo. Called once at startup before the app serves traffic."""
    issues = security_issues()
    if not issues:
        return
    if config.is_production():
        # Log each issue at ERROR first so the actionable text lands in
        # aggregated logs even if the RuntimeError traceback is truncated or
        # the process is in a tight restart loop.
        for issue in issues:
            log.error("startup blocked (insecure default): %s", issue)
        bullets = "\n  - ".join(issues)
        raise RuntimeError(
            "Palisade refused to start: insecure default configuration detected.\n  - "
            + bullets
            + "\n\nFix each item above, or set PALISADE_ALLOW_INSECURE_DEFAULTS=1 to "
            "override — intended ONLY for local dev and the public demo, never for an "
            "internet-exposed deployment."
        )
    for issue in issues:
        log.warning("insecure configuration (permitted in dev/demo): %s", issue)
