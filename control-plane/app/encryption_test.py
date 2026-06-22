"""Unit coverage for evidence-at-rest encryption (app/encryption.py).

Locks in: pass-through when no KEK is configured, the seal/open round-trip
under a KEK (ciphertext stored, plaintext column emptied, per-org wrapped DEK
minted once and reused), legacy plaintext reads while a KEK is active, and
graceful fallback when the wrapped DEK can't be opened (wrong/rotated KEK).

Run with:  python -m app.encryption_test
or:        pytest app/encryption_test.py

Uses an isolated temp sqlite DB and exercises the module directly — no HTTP.
"""

from __future__ import annotations

import base64
import os
import tempfile

# Point db.engine at a throwaway sqlite file BEFORE importing the app (the
# engine binds at import time).
_tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
_tmp.close()
os.environ["DATABASE_URL"] = f"sqlite:///{_tmp.name}"
os.environ.pop("PALISADE_EVIDENCE_KEK", None)

from app import (
    config,  # noqa: E402
    encryption,  # noqa: E402
)
from app import db as db_module  # noqa: E402
from app.models import DEMO_ORG_ID, Finding, Org, OrgEncryptionKey  # noqa: E402

_KEK_B64 = base64.b64encode(b"\x11" * 32).decode()


def _session():
    db_module.Base.metadata.create_all(db_module.engine)
    db = db_module.SessionLocal()
    db.add(Org(id=DEMO_ORG_ID, name="demo"))
    db.flush()
    return db


def _finding(evidence_json, evidence_enc):
    return Finding(
        org_id=DEMO_ORG_ID,
        evidence=evidence_json,
        evidence_enc=evidence_enc,
    )


def test_passthrough_when_disabled():
    config.EVIDENCE_KEK = ""
    db = _session()
    try:
        assert not encryption.enabled()
        ev = {"request": "POST /key/info", "note": "delayed >=5s"}
        evidence_json, evidence_enc = encryption.seal(db, DEMO_ORG_ID, ev)
        assert evidence_json == ev and evidence_enc is None
        # No wrapped key minted when encryption is off.
        assert db.query(OrgEncryptionKey).count() == 0
        # Reading a plaintext row returns the evidence unchanged.
        assert encryption.open_evidence(db, _finding(ev, None)) == ev
    finally:
        db.close()


def test_seal_open_roundtrip():
    config.EVIDENCE_KEK = _KEK_B64
    db = _session()
    try:
        assert encryption.enabled()
        ev = {"request": "POST /key/info", "secret": "do-not-leak"}
        evidence_json, evidence_enc = encryption.seal(db, DEMO_ORG_ID, ev)

        # Plaintext column emptied; ciphertext present and not a plaintext leak.
        assert evidence_json == {}
        assert evidence_enc and isinstance(evidence_enc, bytes)
        assert b"do-not-leak" not in evidence_enc

        # Exactly one wrapped DEK minted for the org, and it is not the raw key.
        keys = db.query(OrgEncryptionKey).all()
        assert len(keys) == 1
        assert b"\x11" * 32 not in keys[0].wrapped_dek

        # Round-trips back to the original evidence.
        finding = _finding(evidence_json, evidence_enc)
        assert encryption.open_evidence(db, finding) == ev

        # A second seal reuses the same wrapped DEK (no new row).
        encryption.seal(db, DEMO_ORG_ID, {"x": 1})
        assert db.query(OrgEncryptionKey).count() == 1
    finally:
        db.close()


def test_legacy_plaintext_read_with_kek_active():
    config.EVIDENCE_KEK = _KEK_B64
    db = _session()
    try:
        # Row written before encryption was enabled: plaintext, no ciphertext.
        ev = {"note": "pre-encryption finding"}
        assert encryption.open_evidence(db, _finding(ev, None)) == ev
    finally:
        db.close()


def test_unopenable_dek_falls_back():
    config.EVIDENCE_KEK = _KEK_B64
    db = _session()
    try:
        ev = {"note": "sealed under the original KEK"}
        _, evidence_enc = encryption.seal(db, DEMO_ORG_ID, ev)
        finding = _finding({}, evidence_enc)

        # Rotate the KEK so the stored wrapped DEK can no longer be opened; the
        # reader must not raise — it falls back to the (empty) plaintext column.
        config.EVIDENCE_KEK = base64.b64encode(b"\x22" * 32).decode()
        assert encryption.open_evidence(db, finding) == {}
    finally:
        config.EVIDENCE_KEK = _KEK_B64
        db.close()


def _run():
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"ok  {name}")
    print("ENCRYPTION OK")


if __name__ == "__main__":
    try:
        _run()
    finally:
        try:
            os.unlink(_tmp.name)
        except OSError:
            pass
