"""Demo seeding + read-only guard coverage.

Run with:  python -m app.seed_test
or:        pytest app/seed_test.py

Asserts: seed is idempotent; the demo org has assets/findings/posture after
seeding; the posture summary matches the seeded active findings; and with
PALISADE_DEMO_MODE on, a user-session mutation 403s while an agent ingest still
succeeds. Reuses api_test's isolated-DB harness.
"""
from __future__ import annotations

import os

from sqlalchemy import select

from app import config as config_module
from app import db as db_module
from app.api_test import (
    _cleanup,
    _enroll,
    _heartbeat,
    _make_client,
    _session,
)
from app.fingerprint import finding_fingerprint
from app.models import DEMO_ORG_ID, Asset, Finding, PostureSnapshot
from app.seed import seed_demo


def _counts(model):
    with db_module.SessionLocal() as db:
        return len(
            db.execute(select(model).where(model.org_id == DEMO_ORG_ID)).scalars().all()
        )


# 1) Seeding populates assets/findings/posture; re-running is a no-op.
def test_seed_populates_and_is_idempotent():
    client, db_path = _make_client()
    try:
        with db_module.SessionLocal() as db:
            seed_demo(db)
        assets1 = _counts(Asset)
        findings1 = _counts(Finding)
        snaps1 = _counts(PostureSnapshot)
        assert assets1 >= 5, assets1
        assert findings1 >= 3, findings1
        assert snaps1 == 30, snaps1

        # Re-run: no new rows.
        with db_module.SessionLocal() as db:
            seed_demo(db)
        assert _counts(Asset) == assets1
        assert _counts(Finding) == findings1
        assert _counts(PostureSnapshot) == snaps1
    finally:
        _cleanup(db_path)


# 2) Posture summary agrees with the seeded active findings.
def test_seeded_posture_summary_matches():
    client, db_path = _make_client()
    try:
        with client:
            with db_module.SessionLocal() as db:
                seed_demo(db)
            sess = _session(client)
            r = client.get("/v1/posture/summary", headers=sess)
            assert r.status_code == 200, r.text
            body = r.json()
            # 1 critical (20) + 2 high (20) active => score 60.
            assert body["counts"]["critical"] == 1, body
            assert body["counts"]["high"] == 2, body
            assert body["counts"]["assets"] == 6, body
            assert body["score"] == 60, body
            assert len(body["trend30d"]) == 30, body
            assert body["trend30d"][-1] == body["score"], body

            # Triage fields surface on at least the litellm finding.
            r = client.get("/v1/findings", headers=sess)
            assert r.status_code == 200, r.text
            triaged = [f for f in r.json()["findings"] if f["triage_priority"]]
            assert triaged, r.json()
    finally:
        _cleanup(db_path)


# 3) Demo read-only guard: user mutation 403s, agent ingest still succeeds.
def test_demo_mode_blocks_user_mutation_not_agent():
    prev = os.environ.get("PALISADE_DEMO_MODE")
    os.environ["PALISADE_DEMO_MODE"] = "1"
    client, db_path = _make_client()
    try:
        with client:
            # /me advertises demo_mode for the web banner.
            sess = _session(client)
            assert client.get("/v1/auth/me", headers=sess).json()["demo_mode"] is True

            # A user-session mutation on the demo org is rejected.
            r = client.post(
                "/v1/agents/enroll-tokens", json={"label": "x"}, headers=sess
            )
            assert r.status_code == 403, r.text
            assert r.json()["detail"] == "demo is read-only", r.json()

            r = client.post("/v1/rescan", headers=sess)
            assert r.status_code == 403, r.text

            # Agent enroll + ingest still works (live demo loop writes findings).
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
            fp = finding_fingerprint(asset_id, "litellm-proxy-preauth-sqli", "sleep5")
            r = client.post(
                f"/v1/scans/{scan['scan_id']}/findings",
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
    finally:
        _cleanup(db_path)
        if prev is None:
            os.environ.pop("PALISADE_DEMO_MODE", None)
        else:
            os.environ["PALISADE_DEMO_MODE"] = prev
        # Keep config module import-time state untouched (demo_mode() reads env live).
        _ = config_module


if __name__ == "__main__":
    test_seed_populates_and_is_idempotent()
    test_seeded_posture_summary_matches()
    test_demo_mode_blocks_user_mutation_not_agent()
    print("SEED TESTS OK")
