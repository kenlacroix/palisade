"""Perimeter scope gating (perimeter.host_in_scope).

Locks in the fail-closed change on this branch: an empty allowlist allows in
dev/demo but DENIES in production, plus exact-host / domain-suffix / CIDR
matching when entries are present. Run: python -m app.perimeter_scope_test
or pytest.
"""
from __future__ import annotations

import os

from app import config, perimeter

_ALLOW = "PALISADE_PERIMETER_SCOPE_ALLOWLIST"
_INSECURE = "PALISADE_ALLOW_INSECURE_DEFAULTS"


def _snapshot():
    return (config.DATABASE_URL, os.environ.get(_ALLOW), os.environ.get(_INSECURE))


def _restore(snap):
    config.DATABASE_URL, allow, insecure = snap
    for key, val in ((_ALLOW, allow), (_INSECURE, insecure)):
        if val is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = val


def _set(*, db, allow, insecure):
    config.DATABASE_URL = db
    if allow is None:
        os.environ.pop(_ALLOW, None)
    else:
        os.environ[_ALLOW] = allow
    if insecure:
        os.environ[_INSECURE] = "1"
    else:
        os.environ.pop(_INSECURE, None)


def test_empty_allowlist_allows_in_dev():
    snap = _snapshot()
    try:
        _set(db="sqlite:///./x.db", allow=None, insecure=False)
        assert perimeter.host_in_scope("anything.example.com") is True
    finally:
        _restore(snap)


def test_empty_allowlist_denies_in_production():
    snap = _snapshot()
    try:
        _set(db="postgresql+psycopg://u:p@h/db", allow=None, insecure=False)
        assert config.is_production() is True
        assert perimeter.host_in_scope("anything.example.com") is False
    finally:
        _restore(snap)


def test_insecure_flag_reopens_in_postgres():
    snap = _snapshot()
    try:
        _set(db="postgresql+psycopg://u:p@h/db", allow=None, insecure=True)
        assert perimeter.host_in_scope("anything.example.com") is True
    finally:
        _restore(snap)


def test_allowlist_matching():
    snap = _snapshot()
    try:
        _set(db="postgresql+psycopg://u:p@h/db", allow="api.acme.com, acme.io, 10.0.0.0/24", insecure=False)
        assert perimeter.host_in_scope("api.acme.com") is True       # exact
        assert perimeter.host_in_scope("sub.acme.io") is True        # parent-domain suffix
        assert perimeter.host_in_scope("10.0.0.5") is True           # CIDR membership
        assert perimeter.host_in_scope("evil.example.com") is False  # not listed
        assert perimeter.host_in_scope("10.0.1.5") is False          # outside CIDR
    finally:
        _restore(snap)


if __name__ == "__main__":
    test_empty_allowlist_allows_in_dev()
    test_empty_allowlist_denies_in_production()
    test_insecure_flag_reopens_in_postgres()
    test_allowlist_matching()
    print("PERIMETER SCOPE TESTS OK")
