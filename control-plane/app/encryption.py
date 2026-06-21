"""Evidence-at-rest encryption: a per-org data key (DEK) wrapped by a master
key (KEK) from config. Finding evidence is sealed with AES-256-GCM under the
org's DEK so raw payloads are unreadable in the database.

Transparent: with no KEK configured (dev/SQLite) evidence stays plaintext JSON
and these helpers are pass-throughs. With a KEK set, writes seal evidence into
`Finding.evidence_enc` and empty `Finding.evidence`; reads go through
open_evidence regardless of which path produced the row.
"""
from __future__ import annotations

import base64
import json
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import config
from .models import Finding, OrgEncryptionKey

_NONCE = 12  # AES-GCM standard nonce length


def enabled() -> bool:
    return bool(config.EVIDENCE_KEK)


def _kek() -> bytes:
    raw = base64.b64decode(config.EVIDENCE_KEK)
    if len(raw) != 32:
        raise ValueError("PALISADE_EVIDENCE_KEK must decode to 32 bytes (AES-256)")
    return raw


def _seal_bytes(plaintext: bytes, key: bytes) -> bytes:
    nonce = os.urandom(_NONCE)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, None)


def _open_bytes(blob: bytes, key: bytes) -> bytes:
    return AESGCM(key).decrypt(blob[:_NONCE], blob[_NONCE:], None)


def _org_dek(db: Session, org_id: str) -> bytes:
    """Per-org 32-byte data key, created and wrapped on first use."""
    row = db.execute(
        select(OrgEncryptionKey).where(OrgEncryptionKey.org_id == org_id)
    ).scalar_one_or_none()
    kek = _kek()
    if row is not None:
        return _open_bytes(row.wrapped_dek, kek)
    dek = os.urandom(32)
    db.add(OrgEncryptionKey(org_id=org_id, wrapped_dek=_seal_bytes(dek, kek)))
    db.flush()
    return dek


def seal(db: Session, org_id: str, evidence: dict) -> tuple[dict, bytes | None]:
    """Map an evidence dict to the (evidence_json, evidence_enc) pair to persist.
    With a KEK set, the plaintext column is emptied and ciphertext is returned;
    otherwise evidence stays plaintext and there is no ciphertext."""
    if not enabled():
        return evidence, None
    dek = _org_dek(db, org_id)
    blob = _seal_bytes(json.dumps(evidence, separators=(",", ":")).encode(), dek)
    return {}, blob


def open_evidence(db: Session, finding: Finding) -> dict:
    """Plaintext evidence for a finding regardless of at-rest encryption."""
    blob = finding.evidence_enc
    if not blob:
        return finding.evidence or {}
    try:
        dek = _org_dek(db, finding.org_id)
        return json.loads(_open_bytes(bytes(blob), dek).decode())
    except Exception:
        return finding.evidence or {}
