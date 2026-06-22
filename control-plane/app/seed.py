"""Demo dataset seeding: make a fresh deploy of the demo org look like a live,
populated product. Gated by config.seed_demo() and wired into main._bootstrap()
after detections are seeded (the findings reference real seeded detection ids).

Idempotent: if the demo org already has any Asset, this is a no-op. Values are
deterministic (no randomness) and timezone-aware, matching models._now(). Scores
are reconstructed with the same weights as app.snapshots so the Dashboard
sparkline, posture summary, and stored snapshots all agree.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from . import encryption
from .fingerprint import finding_fingerprint
from .models import (
    DEMO_ORG_ID,
    Agent,
    Alert,
    AlertChannel,
    AlertRule,
    Asset,
    AuditLog,
    Finding,
    PostureSnapshot,
)
from .snapshots import SEVERITY_WEIGHTS
from .tenancy import _set_rls_org

# Mirror app.snapshots' scoring so seeded snapshots agree with the live scorer.
ACTIVE_STATUSES = ("open", "regressed")

# Demo user email (mirrors config.DEMO_USER_EMAIL default; used as audit actor).
_ACTOR = "demo@palisade.local"


def _now() -> datetime:
    return datetime.now(UTC)


def _score(penalty: int) -> int:
    return max(0, min(100, 100 - penalty))


def seed_demo(db: Session) -> None:
    """Populate DEMO_ORG_ID with a believable dataset. No-op if assets exist."""
    # Scope Postgres RLS to the demo org for this whole transaction: with RLS
    # FORCEd (migration 0011), inserts/reads on the tenant tables below require a
    # matching app.current_org_id GUC. No-op on SQLite.
    _set_rls_org(db, DEMO_ORG_ID)
    existing = db.execute(
        select(Asset).where(Asset.org_id == DEMO_ORG_ID).limit(1)
    ).scalar_one_or_none()
    if existing is not None:
        return

    now = _now()

    # --- agent (so the Agents screen isn't empty; recent heartbeat = online) ---
    agent = Agent(
        org_id=DEMO_ORG_ID,
        secret="demo-agent-secret-do-not-use",
        hostname="nas-proxmox",
        os="linux",
        arch="amd64",
        version="0.1.0",
        status="idle",
        last_seen=now - timedelta(seconds=20),
        last_discover_at=now - timedelta(hours=2),
        last_scan_issued_at=now - timedelta(minutes=12),
    )
    db.add(agent)
    db.flush()

    # --- assets: a few hosts/services that match seeded detections ---
    # (host, port, service, product, version, exposure, scheme)
    asset_specs = [
        ("ai-proxy.lab", 4000, "litellm", "litellm", "1.39.0", "external", "http"),
        ("ai-proxy.lab", 11434, "ollama", "ollama", "0.1.32", "internal", "http"),
        ("web-edge.lab", 3000, "nextjs", "Next.js", "15.1.0", "external", "http"),
        ("obs.lab", 3001, "grafana", "Grafana", "8.2.3", "external", "https"),
        ("ci.lab", 8080, "jenkins", "Jenkins", "2.426.1", "internal", "http"),
        ("storage.lab", 9000, "minio", "MinIO", "RELEASE.2024-01-01", "internal", "http"),
    ]
    assets: dict[str, Asset] = {}
    for host, port, service, product, version, exposure, scheme in asset_specs:
        a = Asset(
            org_id=DEMO_ORG_ID,
            agent_id=agent.id,
            host=host,
            port=port,
            service=service,
            product=product,
            version=version,
            exposure=exposure,
            scheme=scheme,
            first_seen=now - timedelta(days=29),
            last_seen=now - timedelta(minutes=12),
        )
        db.add(a)
        db.flush()
        assets[f"{host}:{port}"] = a

    # --- findings tied to real seeded detection ids ---
    # (asset_key, detection_id, severity, status, evidence_key, evidence,
    #  first_seen_days_ago, last_seen_days_ago, triage)
    finding_specs = [
        (
            "ai-proxy.lab:4000",
            "litellm-proxy-preauth-sqli",  # CVE-2026-42208, critical
            "critical",
            "open",
            "sleep5",
            {"request": "POST /key/info", "note": "pre-auth response delayed >=5s"},
            21,
            0,
            {
                "triage_priority": "act-now",
                "triage_score": 96,
                "triage_rationale": "Pre-auth SQLi on an internet-facing LLM proxy; CVSS 9.8, trivial exploit.",
            },
        ),
        (
            "web-edge.lab:3000",
            "nextjs-middleware-bypass",  # CVE-2025-29927, high
            "high",
            "open",
            "x-middleware-subrequest",
            {"request": "GET /admin", "note": "x-middleware-subrequest bypassed auth middleware"},
            14,
            0,
            {
                "triage_priority": "act-now",
                "triage_score": 84,
                "triage_rationale": "Auth-middleware bypass on an external Next.js edge; protected routes reachable.",
            },
        ),
        (
            "obs.lab:3001",
            "grafana-plugin-path-traversal",  # CVE-2021-43798, high
            "high",
            "regressed",
            "plugin-traversal",
            {
                "request": "GET /public/plugins/alertlist/../../../../etc/passwd",
                "note": "read /etc/passwd via plugin path traversal",
            },
            9,
            0,
            None,
        ),
        (
            "ci.lab:8080",
            "jenkins-cli-arbitrary-file-read",  # CVE-2024-23897, critical
            "critical",
            "muted",
            "cli-file-read",
            {
                "request": "java -jar jenkins-cli.jar @/etc/passwd",
                "note": "arbitrary file read via CLI arg expansion",
            },
            18,
            3,
            None,
        ),
        (
            "obs.lab:3001",
            "grafana-https-admin-exposed",  # CVE-2025-30001, high
            "high",
            "resolved",
            "admin-exposed",
            {
                "request": "GET /admin",
                "note": "admin UI reachable without auth (patched in upgrade)",
            },
            26,
            6,
            None,
        ),
    ]

    findings: list[Finding] = []
    for (
        akey,
        det_id,
        severity,
        status,
        ev_key,
        evidence,
        first_days,
        last_days,
        triage,
    ) in finding_specs:
        asset = assets[akey]
        fp = finding_fingerprint(asset.id, det_id, ev_key)
        evidence_json, evidence_enc = encryption.seal(db, DEMO_ORG_ID, evidence)
        f = Finding(
            org_id=DEMO_ORG_ID,
            asset_id=asset.id,
            detection_id=det_id,
            severity=severity,
            status=status,
            fingerprint=fp,
            evidence=evidence_json,
            evidence_enc=evidence_enc,
            first_seen=now - timedelta(days=first_days),
            last_seen=now - timedelta(days=last_days),
            triage_priority=triage["triage_priority"] if triage else None,
            triage_score=triage["triage_score"] if triage else None,
            triage_rationale=triage["triage_rationale"] if triage else None,
        )
        db.add(f)
        findings.append(f)
    db.flush()

    # --- posture snapshots: one per day for the last 30 days ---
    # Reconstruct each day's score the same way snapshots._day_score does: a
    # finding is active on day D if first_seen<=D and (currently active OR
    # last_seen>=D). Today's tail equals the live posture summary.
    # Posture scoring may have already written a snapshot for the demo org (e.g.
    # today's) before seeding ran; clear any such rows so the reconstruction
    # below inserts cleanly under the unique(org_id, day) constraint.
    db.execute(delete(PostureSnapshot).where(PostureSnapshot.org_id == DEMO_ORG_ID))
    db.flush()
    today = now.date()
    for i in range(30):
        d = today - timedelta(days=29 - i)
        crit = high = med = 0
        penalty = 0
        for f in findings:
            first = (f.first_seen or now).date()
            last = (f.last_seen or f.first_seen or now).date()
            if first <= d and (f.status in ACTIVE_STATUSES or last >= d):
                penalty += SEVERITY_WEIGHTS.get(f.severity, 0)
                if f.severity == "critical":
                    crit += 1
                elif f.severity == "high":
                    high += 1
                elif f.severity == "medium":
                    med += 1
        db.add(
            PostureSnapshot(
                org_id=DEMO_ORG_ID,
                day=d.isoformat(),
                captured_at=now - timedelta(days=29 - i),
                score=_score(penalty),
                critical=crit,
                high=high,
                medium=med,
                assets_count=len(assets),
            )
        )

    # --- one webhook channel + one rule + a few historical sent alerts ---
    channel = AlertChannel(
        org_id=DEMO_ORG_ID,
        type="webhook",
        name="Ops webhook",
        config={"url": "https://hooks.example.com/palisade/demo"},
        enabled=True,
        created_at=now - timedelta(days=28),
    )
    db.add(channel)
    db.flush()
    rule = AlertRule(
        org_id=DEMO_ORG_ID,
        name="High & critical",
        min_severity="high",
        on_events=["new", "regressed"],
        channel_id=channel.id,
        enabled=True,
        created_at=now - timedelta(days=28),
    )
    db.add(rule)
    db.flush()

    # Historical alerts for the active high/critical findings (sent).
    alert_findings = [
        (findings[0], "new", 21),  # litellm critical
        (findings[1], "new", 14),  # nextjs high
        (findings[2], "regressed", 2),  # grafana traversal regressed
    ]
    for f, event, days_ago in alert_findings:
        created = now - timedelta(days=days_ago)
        db.add(
            Alert(
                org_id=DEMO_ORG_ID,
                finding_id=f.id,
                rule_id=rule.id,
                channel_id=channel.id,
                event=event,
                severity=f.severity,
                status="sent",
                created_at=created,
                sent_at=created + timedelta(seconds=3),
            )
        )

    # --- a few audit-trail entries with the demo user as actor ---
    audit_specs = [
        ("enroll_token.mint", "nas-proxmox", 29),
        ("session.create", "demo", 1),
        ("detection.accept", "grafana-https-admin-exposed", 7),
    ]
    for action, target, days_ago in audit_specs:
        db.add(
            AuditLog(
                org_id=DEMO_ORG_ID,
                actor=_ACTOR,
                action=action,
                target=target,
                at=now - timedelta(days=days_ago),
            )
        )

    db.commit()
