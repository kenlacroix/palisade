"""Alerting backend coverage (PHASE 2A / M3).

Exercises: create a webhook channel, create a high-severity "new" rule, ingest a
critical finding through the agent flow, and assert exactly one Alert row is
created for it and a delivery was attempted (status sent|failed -- the dummy
webhook URL fails, which is acceptable; we test rule-eval + Alert creation +
delivery attempt, not real network). A low-severity finding produces no alert.

Reuses the fresh-DB harness from api_test (_make_client). Delivery runs in a
BackgroundTask which, under TestClient, runs synchronously after the response.

Run with:  python -m app.alerts_test
or:        pytest app/alerts_test.py
"""
from __future__ import annotations

import os

os.environ.pop("ANTHROPIC_API_KEY", None)
os.environ.setdefault("PALISADE_ENROLL_TOKENS", "PLS-DEMO")

from app.api_test import _cleanup, _make_client, _session  # noqa: E402
from app.fingerprint import finding_fingerprint  # noqa: E402


def _enroll(client):
    r = client.post(
        "/v1/agents/enroll",
        json={
            "enroll_token": "PLS-DEMO",
            "host": {"hostname": "nas", "os": "linux", "arch": "amd64", "agent_version": "0.1.0"},
        },
    )
    assert r.status_code == 200, r.text
    e = r.json()
    return e["agent_id"], {"Authorization": f"Bearer {e['agent_secret']}"}


def _setup_asset_and_scan(client, agent_id, auth):
    client.post(
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
    assert r.status_code == 200, r.text
    asset_id = r.json()["asset_ids"]["ai.lab:4000"]

    r = client.post(
        f"/v1/agents/{agent_id}/heartbeat",
        json={"agent_version": "0.1.0", "status": "idle"},
        headers=auth,
    )
    scan = next(j for j in r.json()["jobs"] if j["type"] == "scan")["payload"]
    return asset_id, scan["scan_id"]


def _ingest(client, auth, scan_id, asset_id, detection_id, severity, marker):
    fp = finding_fingerprint(asset_id, detection_id, marker)
    r = client.post(
        f"/v1/scans/{scan_id}/findings",
        json={
            "findings": [
                {
                    "detection_id": detection_id,
                    "asset_id": asset_id,
                    "severity": severity,
                    "fingerprint": fp,
                    "evidence": {"request": "POST /x", "note": "delayed >=5s"},
                }
            ]
        },
        headers=auth,
    )
    assert r.status_code == 202, r.text


def test_alert_fires_on_matching_finding_and_skips_low():
    client, db_path = _make_client()
    try:
        with client:
            sess = _session(client)

            # Webhook channel pointing at a dummy URL (delivery will fail -> ok).
            r = client.post(
                "/v1/alert-channels",
                json={
                    "type": "webhook",
                    "name": "ops",
                    "config": {"url": "http://127.0.0.1:1/never"},
                    "enabled": True,
                },
                headers=sess,
            )
            assert r.status_code == 200, r.text
            channel_id = r.json()["id"]

            # Rule: high+ severity, on "new" only.
            r = client.post(
                "/v1/alert-rules",
                json={
                    "name": "criticals",
                    "min_severity": "high",
                    "on_events": ["new"],
                    "channel_id": channel_id,
                },
                headers=sess,
            )
            assert r.status_code == 200, r.text

            agent_id, auth = _enroll(client)
            asset_id, scan_id = _setup_asset_and_scan(client, agent_id, auth)

            # Critical finding -> one alert, delivery attempted.
            _ingest(
                client, auth, scan_id, asset_id,
                "litellm-proxy-preauth-sqli", "critical", "sleep5",
            )

            r = client.get("/v1/alerts", headers=sess)
            assert r.status_code == 200, r.text
            alerts = r.json()["alerts"]
            assert len(alerts) == 1, alerts
            a = alerts[0]
            assert a["severity"] == "critical", a
            assert a["event"] == "new", a
            assert a["status"] in {"sent", "failed"}, a
            assert a["channel_name"] == "ops", a

            # Low-severity finding -> no new alert.
            _ingest(
                client, auth, scan_id, asset_id,
                "litellm-proxy-preauth-sqli", "low", "lowmarker",
            )
            r = client.get("/v1/alerts", headers=sess)
            assert r.status_code == 200, r.text
            assert len(r.json()["alerts"]) == 1, r.json()["alerts"]
    finally:
        _cleanup(db_path)


def test_channel_config_redacted():
    client, db_path = _make_client()
    try:
        with client:
            sess = _session(client)
            r = client.post(
                "/v1/alert-channels",
                json={
                    "type": "telegram",
                    "name": "tg",
                    "config": {"bot_token": "secret123", "chat_id": "42"},
                },
                headers=sess,
            )
            assert r.status_code == 200, r.text
            assert r.json()["config"]["bot_token"] == "***", r.json()
            assert r.json()["config"]["chat_id"] == "42", r.json()

            r = client.get("/v1/alert-channels", headers=sess)
            ch = r.json()["channels"][0]
            assert ch["config"]["bot_token"] == "***", ch
    finally:
        _cleanup(db_path)


def test_rule_rejects_foreign_channel():
    client, db_path = _make_client()
    try:
        with client:
            sess = _session(client)
            r = client.post(
                "/v1/alert-rules",
                json={"name": "x", "min_severity": "high", "channel_id": "no-such-channel"},
                headers=sess,
            )
            assert r.status_code == 400, r.text
    finally:
        _cleanup(db_path)


if __name__ == "__main__":
    test_alert_fires_on_matching_finding_and_skips_low()
    test_channel_config_redacted()
    test_rule_rejects_foreign_channel()
    print("ALERTS TESTS OK")
