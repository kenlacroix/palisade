"""End-to-end smoke test of the Palisade control-plane loop.

enroll -> heartbeat(discover) -> assets -> heartbeat(scan) -> findings -> posture

Run with:  python -m app.smoke_test
or:        pytest app/smoke_test.py
Uses an isolated temp sqlite DB so it never touches palisade.db.
"""

from __future__ import annotations

import os
import tempfile


def _make_client():
    # Point at a throwaway DB BEFORE importing the app.
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    os.environ["DATABASE_URL"] = f"sqlite:///{tmp.name}"
    os.environ.setdefault("PALISADE_ENROLL_TOKENS", "PLS-DEMO")

    from fastapi.testclient import TestClient

    from app.fingerprint import finding_fingerprint
    from app.main import app

    return TestClient(app), finding_fingerprint, tmp.name


def test_end_to_end_loop():
    client, finding_fingerprint, db_path = _make_client()
    try:
        with client:
            _run(client, finding_fingerprint)
    finally:
        try:
            os.unlink(db_path)
        except OSError:
            pass


def _run(client, finding_fingerprint):
    # 1) enroll
    r = client.post(
        "/v1/agents/enroll",
        json={
            "enroll_token": "PLS-DEMO",
            "host": {
                "hostname": "nas-proxmox",
                "os": "linux",
                "arch": "amd64",
                "agent_version": "0.1.0",
            },
        },
    )
    assert r.status_code == 200, r.text
    enroll = r.json()
    agent_id = enroll["agent_id"]
    secret = enroll["agent_secret"]
    assert enroll["heartbeat_interval_s"] == 30
    auth = {"Authorization": f"Bearer {secret}"}

    # bad token must 401
    bad = client.post(
        f"/v1/agents/{agent_id}/heartbeat",
        json={"agent_version": "0.1.0", "status": "idle"},
        headers={"Authorization": "Bearer nope"},
    )
    assert bad.status_code == 401, bad.text

    # 2) heartbeat -> expect a discover job
    r = client.post(
        f"/v1/agents/{agent_id}/heartbeat",
        json={"agent_version": "0.1.0", "status": "idle"},
        headers=auth,
    )
    assert r.status_code == 200, r.text
    jobs = r.json()["jobs"]
    assert any(j["type"] == "discover" for j in jobs), jobs
    assert jobs[0]["payload"]["scope"]["subnets"]

    # 3) post assets (one litellm matching a seeded detection)
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
                },
                {
                    "host": "abs.lab",
                    "port": 13378,
                    "service": "audiobookshelf",
                    "product": "audiobookshelf",
                    "version": "2.7.0",
                    "exposure": "external",
                },
            ]
        },
        headers=auth,
    )
    assert r.status_code == 200, r.text
    asset_ids = r.json()["asset_ids"]
    assert "ai.lab:4000" in asset_ids
    litellm_asset_id = asset_ids["ai.lab:4000"]

    # catalog bundle should serve seeded detections
    r = client.get("/v1/catalog/bundle?since=0", headers=auth)
    assert r.status_code == 200, r.text
    bundle = r.json()
    from . import signing

    assert bundle["signature"] not in ("", "stub"), bundle["signature"]
    assert signing.verify_bundle(
        bundle["version"], bundle["detections"], bundle["signature"], signing.DEMO_PUB_B64
    ), "bundle signature must verify against the demo pubkey"
    det_ids = {d["id"] for d in bundle["detections"]}
    assert "litellm-proxy-preauth-sqli" in det_ids

    # 4) heartbeat -> now expect a scan job
    r = client.post(
        f"/v1/agents/{agent_id}/heartbeat",
        json={"agent_version": "0.1.0", "status": "idle"},
        headers=auth,
    )
    assert r.status_code == 200, r.text
    jobs = r.json()["jobs"]
    scan_jobs = [j for j in jobs if j["type"] == "scan"]
    assert scan_jobs, jobs
    scan = scan_jobs[0]["payload"]
    scan_id = scan["scan_id"]
    target_map = {t["asset_id"]: t["detection_ids"] for t in scan["targets"]}
    assert litellm_asset_id in target_map
    assert "litellm-proxy-preauth-sqli" in target_map[litellm_asset_id]

    # 5) report a finding
    fp = finding_fingerprint(litellm_asset_id, "litellm-proxy-preauth-sqli", "sleep5")
    r = client.post(
        f"/v1/scans/{scan_id}/findings",
        json={
            "findings": [
                {
                    "detection_id": "litellm-proxy-preauth-sqli",
                    "asset_id": litellm_asset_id,
                    "severity": "critical",
                    "fingerprint": fp,
                    "evidence": {
                        "request": "POST /key/info",
                        "note": "response delayed >=5s",
                    },
                }
            ]
        },
        headers=auth,
    )
    assert r.status_code == 202, r.text

    # dedupe: re-report same fingerprint, still one finding
    client.post(
        f"/v1/scans/{scan_id}/findings",
        json={
            "findings": [
                {
                    "detection_id": "litellm-proxy-preauth-sqli",
                    "asset_id": litellm_asset_id,
                    "severity": "critical",
                    "fingerprint": fp,
                    "evidence": {"request": "POST /key/info", "note": "again"},
                }
            ]
        },
        headers=auth,
    )

    # BFF/read APIs require a user session (demo owner), distinct from the
    # agent secret used above.
    r = client.post(
        "/v1/auth/login",
        json={"email": "demo@palisade.local", "password": "palisade"},
    )
    assert r.status_code == 200, r.text
    sess = {"Authorization": f"Bearer {r.json()['token']}"}

    # findings read API
    r = client.get("/v1/findings?status=open&severity=critical", headers=sess)
    assert r.status_code == 200, r.text
    flist = r.json()["findings"]
    assert len(flist) == 1, flist
    finding_id = flist[0]["id"]
    assert flist[0]["cve"] == "CVE-2026-42208"

    # assets read API shows the critical count
    r = client.get("/v1/assets", headers=sess)
    assert r.status_code == 200, r.text
    ai = next(a for a in r.json()["assets"] if a["host"] == "ai.lab")
    assert ai["findings_critical"] == 1

    # 6) posture summary
    r = client.get("/v1/posture/summary", headers=sess)
    assert r.status_code == 200, r.text
    posture = r.json()
    assert posture["counts"]["critical"] == 1
    assert posture["counts"]["assets"] == 2
    assert 0 <= posture["score"] <= 100
    assert posture["score"] == 80  # 100 - 20 (one critical)
    assert len(posture["trend30d"]) == 30

    # mute transitions status -> muted, drops from open posture
    r = client.post(
        f"/v1/findings/{finding_id}/mute",
        json={"reason": "accepted risk", "ttl_s": 600},
        headers=sess,
    )
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "muted"
    r = client.get("/v1/posture/summary", headers=sess)
    assert r.json()["counts"]["critical"] == 0

    print("SMOKE OK: enroll -> discover -> assets -> scan -> findings -> posture")


if __name__ == "__main__":
    test_end_to_end_loop()
