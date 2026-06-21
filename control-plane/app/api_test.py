"""API coverage for the newer Palisade control-plane endpoints.

Locks in: AI draft 503, accept-detection upsert + version bump, signed bundle
(+ tamper detection), seeded CVSS, version-aware scan matching, /v1/rescan
wiring, /v1/findings/{id}/mute, and triage no-op safety.

Run with:  python -m app.api_test
or:        pytest app/api_test.py

The signed-bundle path needs PALISADE_SIGNING_KEY set BEFORE app.main is
imported (config reads it at import). We set it at module top so the whole
module exercises the signed path. The unsigned "stub" path is covered by
app.smoke_test. ANTHROPIC_API_KEY is left unset so AI drafting 503s and triage
no-ops.
"""
from __future__ import annotations

import os
import tempfile

# The demo Ed25519 seed (base64). Must be set in env BEFORE app.config (and thus
# app.signing) is imported, because config reads PALISADE_SIGNING_KEY at import
# time. Mirror of signing.DEMO_SEED_B64; asserted to match below.
_DEMO_SEED_B64 = "70kJtI1NajTd1yQXFHVRuBVQfc6P2CAtRroaLCmYYbY="

os.environ["PALISADE_SIGNING_KEY"] = _DEMO_SEED_B64
os.environ.pop("ANTHROPIC_API_KEY", None)
os.environ.setdefault("PALISADE_ENROLL_TOKENS", "PLS-DEMO")

from fastapi.testclient import TestClient  # noqa: E402

from app import db as db_module  # noqa: E402
from app import signing  # noqa: E402
from app.fingerprint import finding_fingerprint  # noqa: E402
from app.main import _bootstrap, app  # noqa: E402

assert signing.DEMO_SEED_B64 == _DEMO_SEED_B64, "demo seed drifted from signing module"


def _make_client():
    """Fresh isolated sqlite DB per test.

    db.py binds its engine at import time, so per-test isolation means
    rebinding db.engine / db.SessionLocal to a throwaway file, then
    re-bootstrapping (migrations + seed). Returns (client, db_path).
    """
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    url = f"sqlite:///{tmp.name}"

    from sqlalchemy import create_engine

    from app import config as config_module

    # db.py and migrations/env.py both read DATABASE_URL at import; alembic
    # re-imports env.py per command so patching config makes migrations target
    # the throwaway DB. Rebind the live engine/SessionLocal too.
    os.environ["DATABASE_URL"] = url
    config_module.DATABASE_URL = url
    db_module.DATABASE_URL = url

    engine = create_engine(url, connect_args={"check_same_thread": False}, future=True)
    db_module.engine = engine
    db_module.SessionLocal.configure(bind=engine)

    _bootstrap()
    return TestClient(app), tmp.name


def _cleanup(db_path: str) -> None:
    try:
        os.unlink(db_path)
    except OSError:
        pass


def _enroll(client):
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
    return e["agent_id"], {"Authorization": f"Bearer {e['agent_secret']}"}


def _session(client):
    """Log in as the seeded demo user (owner) and return its bearer header.

    BFF/read endpoints now require a user session distinct from agent secrets.
    """
    r = client.post(
        "/v1/auth/login",
        json={"email": "demo@palisade.local", "password": "palisade"},
    )
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['token']}"}


def _heartbeat(client, agent_id, auth):
    r = client.post(
        f"/v1/agents/{agent_id}/heartbeat",
        json={"agent_version": "0.1.0", "status": "idle"},
        headers=auth,
    )
    assert r.status_code == 200, r.text
    return r.json()["jobs"]


def _accept_body():
    return {
        "id": "acme-rce",
        "title": "ACME RCE",
        "cve": "CVE-2026-9999",
        "severity": "high",
        "category": "web",
        "engine": "nuclei",
        "match": {"service": "acme", "versions": "<2.0.0"},
        "http": [
            {"method": "GET", "path": "/x", "matchers": [{"type": "status", "status": [200]}]}
        ],
        "remediation": "upgrade",
        "references": ["https://x"],
        "cvss": 7.5,
    }


# 1) AI drafting requires ANTHROPIC_API_KEY -> 503 when unset.
def test_draft_requires_api_key():
    client, db_path = _make_client()
    try:
        with client:
            r = client.post(
                "/v1/detections/draft",
                json={"cve_url": "https://example.com/cve"},
                headers=_session(client),
            )
            assert r.status_code == 503, r.text
    finally:
        _cleanup(db_path)


# 2) Accept a reviewed draft: version bump, lists, delta, upsert re-bump.
def test_accept_detection_closes_loop():
    client, db_path = _make_client()
    try:
        with client:
            r = client.get("/v1/catalog/bundle?since=0", headers={"Authorization": "Bearer x"})
            # bundle needs agent auth; enroll first for the version read.
            agent_id, auth = _enroll(client)
            sess = _session(client)
            r = client.get("/v1/catalog/bundle?since=0", headers=auth)
            assert r.status_code == 200, r.text
            old_version = r.json()["version"]

            r = client.post("/v1/detections", json=_accept_body(), headers=sess)
            assert r.status_code == 200, r.text
            accepted = r.json()
            assert accepted["id"] == "acme-rce"
            assert accepted["version"] == old_version + 1, accepted

            # read list shows it with cvss + bumped version
            r = client.get("/v1/detections", headers=sess)
            assert r.status_code == 200, r.text
            row = next(d for d in r.json()["detections"] if d["slug"] == "acme-rce")
            assert row["cvss"] == 7.5, row
            assert row["version"] == old_version + 1, row

            # delta bundle since old version includes the new detection
            r = client.get(f"/v1/catalog/bundle?since={old_version}", headers=auth)
            assert r.status_code == 200, r.text
            delta_ids = {d["id"] for d in r.json()["detections"]}
            assert "acme-rce" in delta_ids, delta_ids

            # re-accepting the same id upserts and bumps again
            r = client.post("/v1/detections", json=_accept_body(), headers=sess)
            assert r.status_code == 200, r.text
            assert r.json()["version"] == old_version + 2, r.json()
    finally:
        _cleanup(db_path)


# 3) Signed bundle verifies; tampering breaks verification.
def test_signed_bundle_verifies_and_tamper_detected():
    client, db_path = _make_client()
    try:
        with client:
            agent_id, auth = _enroll(client)
            r = client.get("/v1/catalog/bundle?since=0", headers=auth)
            assert r.status_code == 200, r.text
            b = r.json()
            assert b["signature"] not in ("", "stub"), b["signature"]
            assert signing.verify_bundle(
                b["version"], b["detections"], b["signature"], signing.DEMO_PUB_B64
            ) is True

            tampered = [dict(d) for d in b["detections"]]
            tampered[0]["remediation"] = tampered[0]["remediation"] + " TAMPERED"
            assert signing.verify_bundle(
                b["version"], tampered, b["signature"], signing.DEMO_PUB_B64
            ) is False
    finally:
        _cleanup(db_path)


# 4) Seeded litellm detection carries cvss 9.8 in bundle and read list.
def test_seeded_cvss_present():
    client, db_path = _make_client()
    try:
        with client:
            agent_id, auth = _enroll(client)
            r = client.get("/v1/catalog/bundle?since=0", headers=auth)
            assert r.status_code == 200, r.text
            det = next(
                d for d in r.json()["detections"] if d["id"] == "litellm-proxy-preauth-sqli"
            )
            assert det["cvss"] == 9.8, det

            r = client.get("/v1/detections", headers=_session(client))
            assert r.status_code == 200, r.text
            row = next(
                d for d in r.json()["detections"] if d["slug"] == "litellm-proxy-preauth-sqli"
            )
            assert row["cvss"] == 9.8, row
    finally:
        _cleanup(db_path)


# 5) Version-aware scan matching: in-range asset targeted, out-of-range not.
def test_version_aware_scan_matching():
    client, db_path = _make_client()
    try:
        with client:
            agent_id, auth = _enroll(client)
            # first heartbeat with no assets -> discover
            jobs = _heartbeat(client, agent_id, auth)
            assert any(j["type"] == "discover" for j in jobs), jobs

            r = client.post(
                f"/v1/agents/{agent_id}/assets",
                json={
                    "assets": [
                        {
                            "host": "in.lab",
                            "port": 4000,
                            "service": "litellm",
                            "product": "litellm",
                            "version": "1.39.0",
                            "exposure": "external",
                        },
                        {
                            "host": "out.lab",
                            "port": 4001,
                            "service": "litellm",
                            "product": "litellm",
                            "version": "1.41.0",
                            "exposure": "external",
                        },
                    ]
                },
                headers=auth,
            )
            assert r.status_code == 200, r.text
            ids = r.json()["asset_ids"]
            in_id = ids["in.lab:4000"]
            out_id = ids["out.lab:4001"]

            jobs = _heartbeat(client, agent_id, auth)
            scans = [j for j in jobs if j["type"] == "scan"]
            assert scans, jobs
            targets = {t["asset_id"]: t["detection_ids"] for t in scans[0]["payload"]["targets"]}
            assert in_id in targets, targets
            assert "litellm-proxy-preauth-sqli" in targets[in_id]
            assert out_id not in targets, targets
    finally:
        _cleanup(db_path)


# 6) /v1/rescan clears per-cycle guards so the next heartbeat re-issues a scan.
def test_rescan_reissues_scan():
    client, db_path = _make_client()
    try:
        with client:
            agent_id, auth = _enroll(client)
            _heartbeat(client, agent_id, auth)  # discover
            r = client.post(
                f"/v1/agents/{agent_id}/assets",
                json={
                    "assets": [
                        {
                            "host": "ai.lab",
                            "port": 4000,
                            "service": "litellm",
                            "product": "litellm",
                            "version": "1.39.0",
                            "exposure": "external",
                        }
                    ]
                },
                headers=auth,
            )
            assert r.status_code == 200, r.text

            jobs = _heartbeat(client, agent_id, auth)
            assert any(j["type"] == "scan" for j in jobs), jobs
            # next heartbeat within the cycle would not re-issue (guarded).
            jobs = _heartbeat(client, agent_id, auth)
            assert not any(j["type"] == "scan" for j in jobs), jobs

            r = client.post("/v1/rescan", headers=_session(client))
            assert r.status_code == 200, r.text
            nudged = r.json()["agents_nudged"]
            assert nudged >= 1, nudged

            jobs = _heartbeat(client, agent_id, auth)
            assert any(j["type"] == "scan" for j in jobs), jobs
    finally:
        _cleanup(db_path)


def _ingest_finding(client):
    """enroll -> discover -> assets -> scan -> ingest one critical finding.

    Returns (auth, finding_id).
    """
    agent_id, auth = _enroll(client)
    _heartbeat(client, agent_id, auth)  # discover
    r = client.post(
        f"/v1/agents/{agent_id}/assets",
        json={
            "assets": [
                {
                    "host": "ai.lab",
                    "port": 4000,
                    "service": "litellm",
                    "product": "litellm",
                    "version": "1.39.0",
                    "exposure": "external",
                }
            ]
        },
        headers=auth,
    )
    assert r.status_code == 200, r.text
    asset_id = r.json()["asset_ids"]["ai.lab:4000"]

    jobs = _heartbeat(client, agent_id, auth)
    scan = next(j for j in jobs if j["type"] == "scan")["payload"]
    scan_id = scan["scan_id"]

    fp = finding_fingerprint(asset_id, "litellm-proxy-preauth-sqli", "sleep5")
    r = client.post(
        f"/v1/scans/{scan_id}/findings",
        json={
            "findings": [
                {
                    "detection_id": "litellm-proxy-preauth-sqli",
                    "asset_id": asset_id,
                    "severity": "critical",
                    "fingerprint": fp,
                    "evidence": {"request": "POST /key/info", "note": "delayed >=5s"},
                }
            ]
        },
        headers=auth,
    )
    assert r.status_code == 202, r.text

    r = client.get("/v1/findings?status=open&severity=critical", headers=_session(client))
    assert r.status_code == 200, r.text
    flist = r.json()["findings"]
    assert len(flist) == 1, flist
    return auth, flist[0]["id"]


# 7) /v1/findings/{id}/mute wiring + 404 on unknown id.
def test_mute_finding_wiring():
    client, db_path = _make_client()
    try:
        with client:
            _, finding_id = _ingest_finding(client)
            sess = _session(client)

            r = client.get("/v1/posture/summary", headers=sess)
            assert r.status_code == 200, r.text
            assert r.json()["counts"]["critical"] == 1, r.json()

            r = client.post(
                f"/v1/findings/{finding_id}/mute",
                json={"reason": "accepted", "ttl_s": 600},
                headers=sess,
            )
            assert r.status_code == 200, r.text
            assert r.json()["status"] == "muted", r.json()

            r = client.get("/v1/posture/summary", headers=sess)
            assert r.json()["counts"]["critical"] == 0, r.json()

            r = client.post(
                "/v1/findings/does-not-exist/mute",
                json={"reason": "x", "ttl_s": 1},
                headers=sess,
            )
            assert r.status_code == 404, r.text
    finally:
        _cleanup(db_path)


# 8) Triage no-ops with ANTHROPIC_API_KEY unset: ingest 202, triage fields null.
def test_triage_noop_when_unconfigured():
    client, db_path = _make_client()
    try:
        with client:
            _, finding_id = _ingest_finding(client)
            r = client.get(
                "/v1/findings?status=open&severity=critical", headers=_session(client)
            )
            assert r.status_code == 200, r.text
            f = next(x for x in r.json()["findings"] if x["id"] == finding_id)
            assert f["triage_priority"] is None, f
            assert f["triage_score"] is None, f
            assert f["triage_rationale"] is None, f
    finally:
        _cleanup(db_path)


if __name__ == "__main__":
    test_draft_requires_api_key()
    test_accept_detection_closes_loop()
    test_signed_bundle_verifies_and_tamper_detected()
    test_seeded_cvss_present()
    test_version_aware_scan_matching()
    test_rescan_reissues_scan()
    test_mute_finding_wiring()
    test_triage_noop_when_unconfigured()
    print("API TESTS OK")
