"""Agent mTLS coverage: CA-signed client certs, header-driven cert auth, and the
REQUIRE_MTLS gate. Reuses the api_test fresh-DB harness.

Run with:  python -m app.mtls_test
or:        pytest app/mtls_test.py
"""
from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from app import config
from app import mtls
from app.api_test import _cleanup, _enroll, _make_client
from app.db import SessionLocal
from app.models import Agent, CertAuthority

_KEK_B64 = base64.b64encode(b"\x33" * 32).decode()
_NOT_A_PEM = "BEGIN EC PRIVATE KEY"


def _foreign_cert_pem() -> str:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "rogue")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()


# 1) issue -> verify roundtrip; foreign cert and garbage verify to None.
def test_issue_verify_roundtrip():
    client, db_path = _make_client()
    try:
        with client:
            db = SessionLocal()
            try:
                issued = mtls.issue_client_cert(db, "agent-x", "org-demo")
                fp = mtls.verify_client_cert(db, issued["client_cert_pem"])
                assert fp == issued["fingerprint"], fp

                assert mtls.verify_client_cert(db, _foreign_cert_pem()) is None
                assert mtls.verify_client_cert(db, "not a cert") is None
                assert mtls.verify_client_cert(db, "") is None
            finally:
                db.close()
    finally:
        _cleanup(db_path)


# 2) enroll returns cert material and persists a fingerprint on the Agent row.
def test_enroll_issues_cert():
    client, db_path = _make_client()
    try:
        with client:
            r = client.post(
                "/v1/agents/enroll",
                json={
                    "enroll_token": "PLS-DEMO",
                    "host": {
                        "hostname": "nas",
                        "os": "linux",
                        "arch": "amd64",
                        "agent_version": "0.1.0",
                    },
                },
            )
            assert r.status_code == 200, r.text
            e = r.json()
            assert e["client_cert_pem"], e
            assert e["ca_cert_pem"], e

            db = SessionLocal()
            try:
                agent = db.get(Agent, e["agent_id"])
                assert agent is not None
                assert agent.cert_fingerprint, agent.cert_fingerprint
            finally:
                db.close()
    finally:
        _cleanup(db_path)


# 3) require_agent accepts the issued cert in the MTLS header with NO bearer.
def test_cert_header_auth():
    client, db_path = _make_client()
    try:
        with client:
            r = client.post(
                "/v1/agents/enroll",
                json={
                    "enroll_token": "PLS-DEMO",
                    "host": {
                        "hostname": "nas",
                        "os": "linux",
                        "arch": "amd64",
                        "agent_version": "0.1.0",
                    },
                },
            )
            assert r.status_code == 200, r.text
            e = r.json()
            r = client.post(
                f"/v1/agents/{e['agent_id']}/heartbeat",
                json={"agent_version": "0.1.0", "status": "idle"},
                headers={config.MTLS_CERT_HEADER: e["client_cert_pem"]},
            )
            assert r.status_code == 200, r.text
    finally:
        _cleanup(db_path)


# 4) REQUIRE_MTLS rejects a bearer-only request (no cert header).
def test_require_mtls_rejects_bearer(monkeypatch):
    client, db_path = _make_client()
    try:
        with client:
            agent_id, auth = _enroll(client)
            monkeypatch.setattr(config, "require_mtls", lambda: True)
            r = client.post(
                f"/v1/agents/{agent_id}/heartbeat",
                json={"agent_version": "0.1.0", "status": "idle"},
                headers=auth,
            )
            assert r.status_code == 401, r.text
    finally:
        _cleanup(db_path)


# 5) No KEK: CA key stored as plaintext PEM; issue+verify still round-trips.
def test_ca_key_plaintext_without_kek():
    prev = config.EVIDENCE_KEK
    config.EVIDENCE_KEK = ""
    client, db_path = _make_client()
    try:
        with client:
            db = SessionLocal()
            try:
                mtls.ensure_ca(db)
                ca = db.get(CertAuthority, mtls.CA_ID)
                assert ca is not None
                assert "PRIVATE KEY" in ca.key_pem, "expected plaintext PEM"

                issued = mtls.issue_client_cert(db, "agent-x", "org-demo")
                assert mtls.verify_client_cert(db, issued["client_cert_pem"]) == (
                    issued["fingerprint"]
                )
            finally:
                db.close()
    finally:
        _cleanup(db_path)
        config.EVIDENCE_KEK = prev


# 6) KEK set: stored key_pem is NOT plaintext PEM, yet issue+verify round-trips.
def test_ca_key_sealed_with_kek():
    prev = config.EVIDENCE_KEK
    config.EVIDENCE_KEK = _KEK_B64
    client, db_path = _make_client()
    try:
        with client:
            db = SessionLocal()
            try:
                mtls.ensure_ca(db)
                ca = db.get(CertAuthority, mtls.CA_ID)
                assert ca is not None
                assert "PRIVATE KEY" not in ca.key_pem, "CA key leaked plaintext"
                assert ca.key_pem.startswith("enc:v1:"), ca.key_pem[:16]

                issued = mtls.issue_client_cert(db, "agent-y", "org-demo")
                assert mtls.verify_client_cert(db, issued["client_cert_pem"]) == (
                    issued["fingerprint"]
                )
            finally:
                db.close()
    finally:
        _cleanup(db_path)
        config.EVIDENCE_KEK = prev


# 7) A legacy plaintext CA key is still usable once a KEK is configured.
def test_legacy_plaintext_ca_key_readable_with_kek():
    prev = config.EVIDENCE_KEK
    config.EVIDENCE_KEK = ""
    client, db_path = _make_client()
    try:
        with client:
            db = SessionLocal()
            try:
                mtls.ensure_ca(db)  # writes plaintext (no KEK yet)
                # KEK introduced after the row already exists.
                config.EVIDENCE_KEK = _KEK_B64
                issued = mtls.issue_client_cert(db, "agent-z", "org-demo")
                assert mtls.verify_client_cert(db, issued["client_cert_pem"]) == (
                    issued["fingerprint"]
                )
            finally:
                db.close()
    finally:
        _cleanup(db_path)
        config.EVIDENCE_KEK = prev


class _MonkeyPatch:
    """Minimal monkeypatch shim for the __main__ runner (no pytest)."""

    def __init__(self) -> None:
        self._undo: list = []

    def setattr(self, target, name, value) -> None:
        self._undo.append((target, name, getattr(target, name)))
        setattr(target, name, value)

    def undo(self) -> None:
        for target, name, old in reversed(self._undo):
            setattr(target, name, old)
        self._undo.clear()


if __name__ == "__main__":
    test_issue_verify_roundtrip()
    test_enroll_issues_cert()
    test_cert_header_auth()
    test_ca_key_plaintext_without_kek()
    test_ca_key_sealed_with_kek()
    test_legacy_plaintext_ca_key_readable_with_kek()
    mp = _MonkeyPatch()
    try:
        test_require_mtls_rejects_bearer(mp)
    finally:
        mp.undo()
    print("MTLS TESTS OK")
