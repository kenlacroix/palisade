"""Startup security preflight (app/preflight.py).

Locks in fail-closed behavior: a Postgres deployment carrying public default
secrets refuses to boot, while SQLite dev/test and the explicit insecure-defaults
escape hatch only warn. Run:  python -m app.preflight_test  or  pytest.
"""
from __future__ import annotations

import base64
import os

from app import config, preflight
from app.signing import DEMO_SEED_B64

_REAL_KEK = base64.b64encode(b"\x07" * 32).decode()


def _snapshot():
    return (
        config.DATABASE_URL, config.SIGNING_KEY, config.DEMO_USER_PASSWORD,
        config.EVIDENCE_KEK, os.environ.get("PALISADE_ALLOW_INSECURE_DEFAULTS"),
    )


def _restore(snap):
    (config.DATABASE_URL, config.SIGNING_KEY, config.DEMO_USER_PASSWORD,
     config.EVIDENCE_KEK, insecure) = snap
    if insecure is None:
        os.environ.pop("PALISADE_ALLOW_INSECURE_DEFAULTS", None)
    else:
        os.environ["PALISADE_ALLOW_INSECURE_DEFAULTS"] = insecure


def _configure(*, db, signing, demo_pw, kek, insecure):
    config.DATABASE_URL = db
    config.SIGNING_KEY = signing
    config.DEMO_USER_PASSWORD = demo_pw
    config.EVIDENCE_KEK = kek
    if insecure:
        os.environ["PALISADE_ALLOW_INSECURE_DEFAULTS"] = "1"
    else:
        os.environ.pop("PALISADE_ALLOW_INSECURE_DEFAULTS", None)


_PG_DEFAULTS = dict(
    db="postgresql+psycopg://palisade:palisade@postgres:5432/palisade",
    signing="", demo_pw="palisade", kek="",
)


def test_production_defaults_refuse_to_boot():
    snap = _snapshot()
    try:
        _configure(**_PG_DEFAULTS, insecure=False)
        issues = preflight.security_issues()
        # All four public-default findings are reported.
        assert len(issues) == 4, issues
        raised = False
        try:
            preflight.enforce()
        except RuntimeError as e:
            raised = True
            assert "refused to start" in str(e)
        assert raised, "enforce() must raise on production defaults"
    finally:
        _restore(snap)


def test_insecure_flag_downgrades_to_warning():
    snap = _snapshot()
    try:
        _configure(**_PG_DEFAULTS, insecure=True)
        # Still flagged, but enforce() does not raise (warns and continues).
        assert preflight.security_issues()
        preflight.enforce()
    finally:
        _restore(snap)


def test_sqlite_dev_only_warns():
    snap = _snapshot()
    try:
        _configure(db="sqlite:///./x.db", signing="", demo_pw="palisade", kek="", insecure=False)
        assert not config.is_production()
        preflight.enforce()  # no raise
    finally:
        _restore(snap)


def test_hardened_production_passes():
    snap = _snapshot()
    try:
        _configure(
            db="postgresql+psycopg://palisade:" + "s3cret-rotated" + "@db:5432/palisade",
            signing=base64.b64encode(b"\x09" * 32).decode(),
            demo_pw="not-the-default",
            kek=_REAL_KEK,
            insecure=False,
        )
        assert preflight.security_issues() == []
        preflight.enforce()  # no raise
    finally:
        _restore(snap)


def test_demo_seed_is_flagged_as_forgeable():
    snap = _snapshot()
    try:
        _configure(
            db="postgresql+psycopg://palisade:rotated@db/palisade",
            signing=DEMO_SEED_B64, demo_pw="x", kek=_REAL_KEK, insecure=False,
        )
        issues = preflight.security_issues()
        assert any("SIGNING_KEY" in i for i in issues), issues
    finally:
        _restore(snap)


if __name__ == "__main__":
    test_production_defaults_refuse_to_boot()
    test_insecure_flag_downgrades_to_warning()
    test_sqlite_dev_only_warns()
    test_hardened_production_passes()
    test_demo_seed_is_flagged_as_forgeable()
    print("PREFLIGHT TESTS OK")
