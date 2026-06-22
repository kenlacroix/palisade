"""SSRF-hardened HTTP fetch for user-supplied URLs.

The draft endpoint lets an authenticated user point the control plane at an
arbitrary URL (a CVE advisory). Without guardrails that is a server-side
request forgery primitive: the URL can target cloud metadata
(169.254.169.254), the database/Redis, loopback, or any RFC1918 host, and the
fetched body is then fed into an LLM prompt.

`safe_get` accepts only http/https, resolves the host, rejects any non-public
resolved IP, refuses to follow redirects (the classic SSRF bypass), caps the
body, and never raises — on any problem it returns "" so the caller treats it
as "could not fetch".

DNS-rebinding / TOCTOU: we resolve the hostname, validate every resolved IP,
then *pin* the validated IP into the connection via a custom httpx transport
that rewrites the connect target. Because the socket connects to the exact IP
we validated (not a freshly re-resolved one), a rebinding attacker cannot swap
in an internal address between our check and the connect. The Host header /
TLS SNI still carry the original hostname so virtual hosting and certs work.
"""

from __future__ import annotations

import ipaddress
import socket

import httpx

_ALLOWED_SCHEMES = frozenset({"http", "https"})


def _is_public(ip: str) -> bool:
    """True only for globally-routable unicast addresses."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    # Normalize IPv4-mapped IPv6 (e.g. ::ffff:169.254.169.254 / ::ffff:127.0.0.1)
    # to the embedded v4 before classifying. .is_loopback/.is_link_local don't
    # flag the mapped form, and .is_private only normalizes it on Python >=3.12.4,
    # so collapse it ourselves to stay correct across versions.
    mapped = getattr(addr, "ipv4_mapped", None)
    if mapped is not None:
        addr = mapped
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local  # covers 169.254.0.0/16 metadata + fe80::/10
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
    )


def _resolve_public_ips(host: str, port: int) -> list[str]:
    """Resolve `host`, returning its IPs only if ALL of them are public.

    Returns [] if resolution fails or any resolved IP is non-public. We reject
    when *any* IP is unsafe rather than filtering, so a host that resolves to a
    mix of public and internal addresses cannot be used as a bypass.
    """
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError, OSError):
        return []
    ips = [info[4][0] for info in infos]
    if not ips or not all(_is_public(ip) for ip in ips):
        return []
    return ips


class _PinnedResolverTransport(httpx.HTTPTransport):
    """Transport that connects to a pre-validated IP for one specific host.

    httpx resolves the host inside `connect`; to avoid a second (re-bindable)
    DNS lookup we rewrite the request URL's host to the IP we already validated
    while restoring the original Host header and TLS SNI server hostname.
    """

    def __init__(self, host: str, ip: str) -> None:
        super().__init__()
        self._host = host
        self._ip = ip

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        if request.url.host == self._host:
            request.headers.setdefault("Host", request.url.netloc.decode("ascii"))
            request.url = request.url.copy_with(host=self._ip)
            request.extensions = dict(request.extensions)
            request.extensions["sni_hostname"] = self._host
        return super().handle_request(request)


def safe_get(
    url: str,
    *,
    timeout: float,
    max_bytes: int,
    user_agent: str,
) -> str:
    """Fetch `url` defensively for SSRF.

    Returns the response body (truncated to `max_bytes`) on a 2xx from a public
    host, or "" on anything else: disallowed scheme, non-public/unresolvable
    host, redirect, non-2xx status, or any network error. Never raises.
    """
    try:
        parsed = httpx.URL(url)
    except (httpx.InvalidURL, TypeError):
        return ""

    if parsed.scheme not in _ALLOWED_SCHEMES:
        return ""

    host = parsed.host
    if not host:
        return ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    # If the URL already contains a literal IP, validate it directly; otherwise
    # resolve and validate every address the host maps to.
    try:
        ipaddress.ip_address(host)
        ips = [host] if _is_public(host) else []
    except ValueError:
        ips = _resolve_public_ips(host, port)
    if not ips:
        return ""

    transport = _PinnedResolverTransport(host, ips[0])
    try:
        with httpx.Client(
            transport=transport,
            timeout=timeout,
            follow_redirects=False,  # a 3xx to an internal host is the classic bypass
            headers={"User-Agent": user_agent},
        ) as client:
            resp = client.get(url)
            if not (200 <= resp.status_code < 300):
                return ""
            return resp.text[:max_bytes]
    except Exception:
        return ""
