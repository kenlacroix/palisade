"""Internal certificate authority for agent mTLS.

A single platform-wide CA (CertAuthority row id="default") signs short-lived
client certs at enroll. A TLS-terminating proxy forwards the presented client
cert in the MTLS_CERT_HEADER; verify_client_cert validates it against this CA
and returns the fingerprint that maps back to an Agent row. Verification never
raises on bad input — it returns None so auth can fall through cleanly.
"""
from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from urllib.parse import unquote

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from sqlalchemy.orm import Session

from . import config
from .models import CertAuthority

CA_ID = "default"
_CA_CN = "Palisade Agent CA"
_CA_VALIDITY_DAYS = 3650


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _fingerprint(cert: x509.Certificate) -> str:
    return hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()


def ensure_ca(db: Session) -> CertAuthority:
    """Load the platform CA, generating + persisting it on first call. Idempotent."""
    ca = db.get(CertAuthority, CA_ID)
    if ca is not None:
        return ca

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, _CA_CN)])
    now = _now()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=_CA_VALIDITY_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )

    ca = CertAuthority(
        id=CA_ID,
        cert_pem=cert.public_bytes(serialization.Encoding.PEM).decode(),
        key_pem=key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode(),
    )
    db.add(ca)
    db.commit()
    return ca


def issue_client_cert(db: Session, agent_id: str, org_id: str) -> dict:
    """Mint an EC P-256 client cert for an agent, signed by the platform CA."""
    ca = ensure_ca(db)
    ca_cert = x509.load_pem_x509_certificate(ca.cert_pem.encode())
    ca_key = serialization.load_pem_private_key(ca.key_pem.encode(), password=None)

    key = ec.generate_private_key(ec.SECP256R1())
    now = _now()
    not_after = now + timedelta(days=config.MTLS_CERT_DAYS)
    cert = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, agent_id),
                    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, org_id),
                ]
            )
        )
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(secrets.randbits(128) | 1)
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )

    return {
        "client_cert_pem": cert.public_bytes(serialization.Encoding.PEM).decode(),
        "client_key_pem": key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode(),
        "ca_cert_pem": ca.cert_pem,
        "fingerprint": _fingerprint(cert),
        "not_after": not_after,
    }


def verify_client_cert(db: Session, pem: str) -> str | None:
    """Verify a presented client cert against the platform CA.

    Accepts URL-escaped PEM (nginx $ssl_client_escaped_cert percent-encodes it).
    Returns the cert's sha256-DER fingerprint (hex) if the signature checks out
    against the CA and the cert is within its validity window, else None. Never
    raises — bad input maps to None.
    """
    if not pem:
        return None
    if "%" in pem:
        pem = unquote(pem)
    try:
        cert = x509.load_pem_x509_certificate(pem.encode())
        ca = ensure_ca(db)
        ca_cert = x509.load_pem_x509_certificate(ca.cert_pem.encode())
        ca_pub = ca_cert.public_key()
        if not isinstance(ca_pub, ec.EllipticCurvePublicKey):
            return None
        ca_pub.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            ec.ECDSA(cert.signature_hash_algorithm),
        )
        now = _now()
        if not (cert.not_valid_before_utc <= now <= cert.not_valid_after_utc):
            return None
        return _fingerprint(cert)
    except (
        ValueError,
        TypeError,
        InvalidSignature,
        UnsupportedAlgorithm,
    ):
        return None
