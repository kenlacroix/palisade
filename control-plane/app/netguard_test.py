"""Unit coverage for the SSRF guard (app/netguard.py).

Locks in: only http/https schemes are fetched; loopback, link-local/cloud
metadata, and RFC1918 hosts are blocked before any connection; redirects are
not followed (treated as no content); and a normal public host with a mocked
2xx returns the body capped to `max_bytes`.

No real network: socket.getaddrinfo is monkeypatched to control resolution and
httpx's underlying transport is stubbed so no socket is ever opened.

Run with:  pytest app/netguard_test.py -q
"""

from __future__ import annotations

import socket

import httpx
import pytest

from app import netguard

_UA = "palisade-test/0.1"


def _fake_getaddrinfo(ip: str):
    """Build a getaddrinfo replacement that always resolves to `ip`."""

    def _resolver(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, port))]

    return _resolver


def _stub_transport(monkeypatch, status_code: int, body: str) -> dict:
    """Stub the real transport so any allowed request gets a canned response.

    Records the IP the transport was actually asked to connect to so tests can
    assert the validated/pinned IP was used.
    """
    seen: dict = {}

    def _handle(self, request: httpx.Request) -> httpx.Response:
        seen["connect_host"] = request.url.host
        seen["sni"] = request.extensions.get("sni_hostname")
        return httpx.Response(status_code, text=body, request=request)

    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", _handle)
    return seen


# --- scheme rejection -------------------------------------------------------


def test_rejects_file_scheme(monkeypatch) -> None:
    # Must short-circuit before any resolution attempt.
    monkeypatch.setattr(socket, "getaddrinfo", _boom)
    assert netguard.safe_get("file:///etc/passwd", timeout=1, max_bytes=100, user_agent=_UA) == ""


def test_rejects_gopher_scheme(monkeypatch) -> None:
    monkeypatch.setattr(socket, "getaddrinfo", _boom)
    assert netguard.safe_get("gopher://evil/1", timeout=1, max_bytes=100, user_agent=_UA) == ""


def _boom(*args, **kwargs):
    raise AssertionError("getaddrinfo must not be called for rejected schemes")


# --- blocked loopback -------------------------------------------------------


def test_blocks_loopback_literal() -> None:
    assert (
        netguard.safe_get("http://127.0.0.1/admin", timeout=1, max_bytes=100, user_agent=_UA) == ""
    )


def test_blocks_localhost_name(monkeypatch) -> None:
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo("127.0.0.1"))
    assert (
        netguard.safe_get("http://localhost/admin", timeout=1, max_bytes=100, user_agent=_UA) == ""
    )


def test_blocks_ipv6_loopback() -> None:
    assert netguard.safe_get("http://[::1]/admin", timeout=1, max_bytes=100, user_agent=_UA) == ""


# --- blocked link-local / cloud metadata ------------------------------------


def test_blocks_metadata_literal() -> None:
    assert (
        netguard.safe_get(
            "http://169.254.169.254/latest/meta-data/", timeout=1, max_bytes=100, user_agent=_UA
        )
        == ""
    )


def test_blocks_metadata_via_dns(monkeypatch) -> None:
    # DNS-rebinding shape: a benign-looking name resolves to the metadata IP.
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo("169.254.169.254"))
    assert (
        netguard.safe_get("http://metadata.example/", timeout=1, max_bytes=100, user_agent=_UA)
        == ""
    )


# --- blocked private ranges -------------------------------------------------


def test_blocks_private_10() -> None:
    assert netguard.safe_get("http://10.0.0.5/", timeout=1, max_bytes=100, user_agent=_UA) == ""


def test_blocks_private_192_168() -> None:
    assert netguard.safe_get("http://192.168.1.1/", timeout=1, max_bytes=100, user_agent=_UA) == ""


def test_blocks_private_via_dns(monkeypatch) -> None:
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo("10.1.2.3"))
    assert (
        netguard.safe_get("http://internal.example/", timeout=1, max_bytes=100, user_agent=_UA)
        == ""
    )


def test_blocks_when_any_resolved_ip_is_private(monkeypatch) -> None:
    # Mixed answer: one public, one internal -> reject entirely.
    def _mixed(host, port, *args, **kwargs):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("93.184.216.34", port)),
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("10.0.0.1", port)),
        ]

    monkeypatch.setattr(socket, "getaddrinfo", _mixed)
    assert netguard.safe_get("http://example.com/", timeout=1, max_bytes=100, user_agent=_UA) == ""


# --- redirects are not followed ---------------------------------------------


def test_redirect_not_followed(monkeypatch) -> None:
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo("93.184.216.34"))
    _stub_transport(monkeypatch, 302, "")
    # A 3xx is treated as no content; the Location target is never fetched.
    assert netguard.safe_get("http://example.com/", timeout=1, max_bytes=100, user_agent=_UA) == ""


# --- non-2xx ----------------------------------------------------------------


def test_non_2xx_returns_empty(monkeypatch) -> None:
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo("93.184.216.34"))
    _stub_transport(monkeypatch, 500, "boom")
    assert netguard.safe_get("http://example.com/", timeout=1, max_bytes=100, user_agent=_UA) == ""


# --- happy path -------------------------------------------------------------


def test_public_host_returns_body(monkeypatch) -> None:
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo("93.184.216.34"))
    seen = _stub_transport(monkeypatch, 200, "advisory body")
    out = netguard.safe_get("http://example.com/cve", timeout=1, max_bytes=100, user_agent=_UA)
    assert out == "advisory body"
    # Connection was pinned to the validated IP, with the hostname preserved for SNI.
    assert seen["connect_host"] == "93.184.216.34"
    assert seen["sni"] == "example.com"


def test_body_capped_to_max_bytes(monkeypatch) -> None:
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo("93.184.216.34"))
    _stub_transport(monkeypatch, 200, "x" * 500)
    out = netguard.safe_get("http://example.com/", timeout=1, max_bytes=64, user_agent=_UA)
    assert out == "x" * 64


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
