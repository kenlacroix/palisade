"""Coverage for the catalog cross-tenant aggregate (/v1/detections).

`tenants_total`/`tenants_hit` are platform-wide metrics. On Postgres they are
served by RLS-bypassing SECURITY DEFINER functions (migration 0004); on SQLite
the read router uses an inline aggregate. This module exercises the SQLite
inline branch end-to-end via api_test's harness. The Postgres branch is covered
structurally by the migration plus the dialect guard in read.list_detections.

Run with:  python -m app.catalog_aggregate_test
or:        pytest app/catalog_aggregate_test.py
"""

from __future__ import annotations

from app.api_test import _cleanup, _ingest_finding, _make_client, _session


# Single demo org: tenants_total == 1, and only detections with an ingested
# active finding report tenants_hit == 1 (others 0).
def test_detections_aggregate_is_per_tenant_accurate():
    client, db_path = _make_client()
    try:
        with client:
            _ingest_finding(client)  # one active critical finding on litellm detection
            sess = _session(client)

            r = client.get("/v1/detections", headers=sess)
            assert r.status_code == 200, r.text
            dets = r.json()["detections"]

            for d in dets:
                assert d["tenants_total"] == 1, d

            hit = next(d for d in dets if d["slug"] == "litellm-proxy-preauth-sqli")
            assert hit["tenants_hit"] == 1, hit

            untouched = next(d for d in dets if d["slug"] != "litellm-proxy-preauth-sqli")
            assert untouched["tenants_hit"] == 0, untouched
    finally:
        _cleanup(db_path)


if __name__ == "__main__":
    test_detections_aggregate_is_per_tenant_accurate()
    print("CATALOG AGGREGATE TESTS OK")
