"""Pure delivery helpers for alert channels. No DB access here; alerting.py owns
the session and persistence. Every sender swallows its exceptions and returns
(ok, error) so a bad channel config can never crash the delivery worker.
"""
from __future__ import annotations

import smtplib
from email.message import EmailMessage
from typing import Any

import httpx

_TIMEOUT_S = 8.0


def render_alert_text(
    *,
    title: str,
    severity: str,
    host: str,
    port: int,
    cve: str | None,
    event: str,
    evidence_note: str,
) -> tuple[str, str]:
    """Plaintext body + short email subject for one alert."""
    subject = f"[Palisade] {severity.upper()} {event}: {title}"
    lines = [
        f"{title} ({severity})",
        f"Event: {event}",
        f"Host: {host}:{port}",
    ]
    if cve:
        lines.append(f"CVE: {cve}")
    if evidence_note:
        lines.append(f"Evidence: {evidence_note}")
    return subject, "\n".join(lines)


def send_telegram(config: dict[str, Any], text: str) -> tuple[bool, str | None]:
    try:
        token = config.get("bot_token")
        chat_id = config.get("chat_id")
        if not token or not chat_id:
            return False, "telegram config missing bot_token/chat_id"
        r = httpx.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            json={"chat_id": chat_id, "text": text},
            timeout=_TIMEOUT_S,
        )
        if r.status_code >= 400:
            return False, f"telegram http {r.status_code}"
        return True, None
    except Exception as exc:
        return False, str(exc)


def send_email(config: dict[str, Any], subject: str, text: str) -> tuple[bool, str | None]:
    try:
        host = config.get("smtp_host")
        to_addr = config.get("to")
        from_addr = config.get("from")
        if not host or not to_addr or not from_addr:
            return False, "email config missing smtp_host/from/to"
        port = int(config.get("smtp_port", 587))

        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = from_addr
        msg["To"] = to_addr
        msg.set_content(text)

        with smtplib.SMTP(host, port, timeout=_TIMEOUT_S) as server:
            if port == 587:
                server.starttls()
            username = config.get("username")
            password = config.get("password")
            if username and password:
                server.login(username, password)
            server.send_message(msg)
        return True, None
    except Exception as exc:
        return False, str(exc)


def send_webhook(config: dict[str, Any], payload: dict[str, Any]) -> tuple[bool, str | None]:
    try:
        url = config.get("url")
        if not url:
            return False, "webhook config missing url"
        r = httpx.post(url, json=payload, timeout=_TIMEOUT_S)
        if r.status_code >= 400:
            return False, f"webhook http {r.status_code}"
        return True, None
    except Exception as exc:
        return False, str(exc)


def dispatch(
    channel_type: str,
    config: dict[str, Any],
    *,
    subject: str,
    text: str,
    payload: dict[str, Any],
) -> tuple[bool, str | None]:
    if channel_type == "telegram":
        return send_telegram(config, text)
    if channel_type == "email":
        return send_email(config, subject, text)
    if channel_type == "webhook":
        return send_webhook(config, payload)
    return False, "unknown channel type"
