"""Posture trend coverage: real history-backed trend + snapshot upsert.

Run with:  python -m app.posture_trends_test
or:        pytest app/posture_trends_test.py
"""
from __future__ import annotations

from sqlalchemy import select

from app import db as db_module
from app.api_test import _cleanup, _ingest_finding, _make_client, _session
from app.models import PostureSnapshot


def _snapshot_count(org_id: str = "org-demo") -> int:
    with db_module.SessionLocal() as db:
        return len(
            db.execute(
                select(PostureSnapshot).where(PostureSnapshot.org_id == org_id)
            ).scalars().all()
        )


# (a) trend30d: length 30, ints in [0,100], newest == live score.
def test_trend_shape_and_live_tail():
    client, db_path = _make_client()
    try:
        with client:
            sess = _session(client)
            r = client.get("/v1/posture/summary", headers=sess)
            assert r.status_code == 200, r.text
            body = r.json()
            trend = body["trend30d"]
            assert len(trend) == 30, trend
            assert all(isinstance(v, int) and 0 <= v <= 100 for v in trend), trend
            assert trend[-1] == body["score"], body
    finally:
        _cleanup(db_path)


# (b) Ingesting a critical lowers today's score and writes exactly one snapshot.
def test_critical_lowers_score_one_snapshot():
    client, db_path = _make_client()
    try:
        with client:
            _, _ = _ingest_finding(client)
            sess = _session(client)
            r = client.get("/v1/posture/summary", headers=sess)
            assert r.status_code == 200, r.text
            body = r.json()
            assert body["score"] == 80, body  # 100 - 20 (one critical)
            assert body["trend30d"][-1] == 80, body
            assert _snapshot_count() == 1, _snapshot_count()
    finally:
        _cleanup(db_path)


# (c) Two summary calls same day -> still one snapshot row (UPSERT idempotency).
def test_summary_idempotent_within_day():
    client, db_path = _make_client()
    try:
        with client:
            sess = _session(client)
            client.get("/v1/posture/summary", headers=sess)
            client.get("/v1/posture/summary", headers=sess)
            assert _snapshot_count() == 1, _snapshot_count()
    finally:
        _cleanup(db_path)


if __name__ == "__main__":
    test_trend_shape_and_live_tail()
    test_critical_lowers_score_one_snapshot()
    test_summary_idempotent_within_day()
    print("POSTURE TRENDS OK")
