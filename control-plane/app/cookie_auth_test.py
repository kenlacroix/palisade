"""Cookie-backed session auth: login sets an httpOnly `palisade_session`
cookie, a request carrying only that cookie authenticates, and logout clears it.
Mirrors api_test.py's isolated-sqlite harness."""
from __future__ import annotations

from .api_test import _cleanup, _make_client

_LOGIN = {"email": "demo@palisade.local", "password": "palisade"}


def _https_client():
    # The session cookie is Secure, so the TestClient cookie jar only replays it
    # over https. Point the client at an https base_url for these tests.
    client, db_path = _make_client()
    client.base_url = "https://testserver"
    return client, db_path


def test_login_sets_httponly_session_cookie():
    client, db_path = _https_client()
    try:
        r = client.post("/v1/auth/login", json=_LOGIN)
        assert r.status_code == 200, r.text
        set_cookie = r.headers.get("set-cookie", "")
        assert "palisade_session=" in set_cookie
        assert "HttpOnly" in set_cookie
        assert "Path=/" in set_cookie
        assert "SameSite=lax" in set_cookie
        # TestClient stored the cookie in its jar.
        assert client.cookies.get("palisade_session")
    finally:
        _cleanup(db_path)


def test_cookie_only_request_authenticates():
    client, db_path = _https_client()
    try:
        assert client.post("/v1/auth/login", json=_LOGIN).status_code == 200
        # No Authorization header: the persisted cookie alone must authenticate.
        r = client.get("/v1/auth/me")
        assert r.status_code == 200, r.text
        assert r.json()["user"]["email"] == _LOGIN["email"]
    finally:
        _cleanup(db_path)


def test_logout_clears_cookie():
    client, db_path = _https_client()
    try:
        assert client.post("/v1/auth/login", json=_LOGIN).status_code == 200
        r = client.post("/v1/auth/logout")
        assert r.status_code == 204, r.text
        # Cookie deleted: the jar no longer carries a session, so /me is 401.
        assert not client.cookies.get("palisade_session")
        assert client.get("/v1/auth/me").status_code == 401
    finally:
        _cleanup(db_path)
