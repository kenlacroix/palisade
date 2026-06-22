"""Cross-tenant isolation at the agent ingest boundary.

Locks in the hardening from this branch: findings ingest binds scan_id and
asset_id to the authenticated agent's org, and finding fingerprints are unique
per org (not globally) so one tenant can't collide with / overwrite another's.

Run with:  python -m app.tenant_isolation_test
or:        pytest app/tenant_isolation_test.py
"""

from __future__ import annotations

from app import db as db_module
from app.api_test import _cleanup, _enroll, _make_client
from app.fingerprint import finding_fingerprint
from app.models import Asset, EnrollToken, Finding, Org


def _demo_scan_and_asset(client):
    """enroll a demo agent, discover, register one asset, get an issued scan.
    Returns (auth, scan_id, asset_id) all in the demo org."""
    agent_id, auth = _enroll(client)
    client.post(  # discover
        f"/v1/agents/{agent_id}/heartbeat",
        json={"agent_version": "0.1.0", "status": "idle"},
        headers=auth,
    )
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
    asset_id = r.json()["asset_ids"]["ai.lab:4000"]
    r = client.post(
        f"/v1/agents/{agent_id}/heartbeat",
        json={"agent_version": "0.1.0", "status": "idle"},
        headers=auth,
    )
    scan = next(j for j in r.json()["jobs"] if j["type"] == "scan")["payload"]
    return auth, scan["scan_id"], asset_id


def _second_org_agent(client):
    """Create a second org + seed enroll token, enroll an agent into it."""
    with db_module.SessionLocal() as db:
        if db.get(Org, "org-two") is None:
            db.add(Org(id="org-two", name="two", plan="free"))
            db.add(EnrollToken(token="PLS-TWO", org_id="org-two", label="seed"))
            db.commit()
    r = client.post(
        "/v1/agents/enroll",
        json={
            "enroll_token": "PLS-TWO",
            "host": {"hostname": "b", "os": "linux", "arch": "amd64", "agent_version": "0.1.0"},
        },
    )
    assert r.status_code == 200, r.text
    e = r.json()
    return {"Authorization": f"Bearer {e['agent_secret']}"}


def _finding_body(asset_id: str):
    return {
        "findings": [
            {
                "detection_id": "litellm-proxy-preauth-sqli",
                "asset_id": asset_id,
                "severity": "critical",
                "fingerprint": finding_fingerprint(
                    asset_id, "litellm-proxy-preauth-sqli", "sleep5"
                ),
                "evidence": {"request": "POST /key/info", "note": "x"},
            }
        ]
    }


def test_ingest_rejects_foreign_scan():
    client, db_path = _make_client()
    try:
        with client:
            _, demo_scan_id, demo_asset_id = _demo_scan_and_asset(client)
            other_auth = _second_org_agent(client)
            # Agent in org-two posts to the demo org's scan -> not its scan.
            r = client.post(
                f"/v1/scans/{demo_scan_id}/findings",
                json=_finding_body(demo_asset_id),
                headers=other_auth,
            )
            assert r.status_code == 404, r.text
    finally:
        _cleanup(db_path)


def test_ingest_rejects_unowned_asset():
    client, db_path = _make_client()
    try:
        with client:
            auth, scan_id, _ = _demo_scan_and_asset(client)
            # Own scan, but a fabricated asset id that isn't in this org.
            r = client.post(
                f"/v1/scans/{scan_id}/findings",
                json=_finding_body("ghost-asset"),
                headers=auth,
            )
            assert r.status_code == 400, r.text
    finally:
        _cleanup(db_path)


def test_fingerprint_unique_per_org_not_global():
    client, db_path = _make_client()
    try:
        with client:
            # Two orgs, an asset in each, two findings sharing one fingerprint.
            # A global unique index would reject the second insert; the per-org
            # composite unique permits it.
            with db_module.SessionLocal() as db:
                if db.get(Org, "org-two") is None:
                    db.add(Org(id="org-two", name="two", plan="free"))
                a1 = Asset(org_id="org-demo", host="h", port=1, service="litellm")
                a2 = Asset(org_id="org-two", host="h", port=1, service="litellm")
                db.add_all([a1, a2])
                db.flush()
                fp = "shared-fingerprint"
                db.add(
                    Finding(
                        org_id="org-demo",
                        asset_id=a1.id,
                        detection_id="litellm-proxy-preauth-sqli",
                        fingerprint=fp,
                    )
                )
                db.add(
                    Finding(
                        org_id="org-two",
                        asset_id=a2.id,
                        detection_id="litellm-proxy-preauth-sqli",
                        fingerprint=fp,
                    )
                )
                db.commit()
                n = db.query(Finding).filter(Finding.fingerprint == fp).count()
                assert n == 2, n
    finally:
        _cleanup(db_path)


if __name__ == "__main__":
    test_ingest_rejects_foreign_scan()
    test_ingest_rejects_unowned_asset()
    test_fingerprint_unique_per_org_not_global()
    print("TENANT ISOLATION TESTS OK")
