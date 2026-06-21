# Palisade — Full Specification

**Working title.** Palisade = a defensive perimeter wall. Renameable pre-launch.

> Continuous attack-surface monitoring for self-hosted / homelab / small-team
> infrastructure, with first-class coverage of AI infra (LiteLLM, Ollama, MCP
> servers, vector DBs) that generic scanners miss. Detections authored by
> someone who finds these CVEs.

---

## 1. Why this exists

- The author writes real CVE detections for self-hosted + AI infra (LiteLLM, Next.js, Audiobookshelf, Splunk, Kopia). Today they live as PRs in other people's repos.
- Palisade turns that into an owned, operated product.
- It is the one project that forces what the rest of the portfolio never proves: **ships to multiple users, operates production, and the infrastructure is the product.**

### Moat
- Curated, freshly-authored detections in a niche the big scanners ignore — often before a public Nuclei/Nessus template exists.
- AI-infra coverage as a first-class category (nobody owns this well yet).

### Competitive frame
| Tool | Gap Palisade fills |
|------|--------------------|
| Nessus / Qualys | Enterprise-heavy, expensive, not homelab-shaped |
| Nuclei (raw) | No control plane, scheduling, history, multi-tenant, triage |
| Trivy / Grype | Image/dep CVEs only — not running-service exposure |
| Wazuh | Heavy SIEM, steep ops; no AI-infra detections |
| Shodan | External only; no owned-asset depth, no remediation |

---

## 2. Goals / Non-goals

### Goals (v1)
- Discover services on a user's network/hosts via a lightweight agent.
- Run authored detections against them on a schedule.
- Triage findings with an LLM (explanation, blast radius, fix).
- Track posture over time; alert on new/critical findings.
- Be deployed live, multi-tenant-ready, fully operated (IaC + CI/CD + observability + runbooks).

### Non-goals (v1 — add only with real users)
- Agentless cloud CSPM (AWS/GCP/Azure posture).
- Compliance frameworks (SOC2 / CIS / PCI mapping).
- Windows agent.
- Detection marketplace / third-party authors.
- EDR / runtime/host intrusion detection.

---

## 3. Personas & core user stories

**P1 — Homelabber (primary).** Runs 10–40 self-hosted services on a NAS/Proxmox box.
- "Tell me which of my exposed services has a known auth bypass, before someone else finds it."
- "Alert me on Telegram the moment a new critical appears."

**P2 — Small-team / startup infra owner.**
- "Give me a posture dashboard I can show a customer doing security due diligence."
- "Track whether we're getting better or worse over time."

**P3 — AI-infra operator.**
- "Is my LiteLLM/Ollama/MCP endpoint exposed or misconfigured?"

**Author (you).**
- "Write a detection once; ship it to every tenant; see how many assets it flags."

---

## 4. System architecture

```
                          ┌─────────────────────────────────────────┐
                          │            CONTROL PLANE (SaaS)           │
   ┌──────────┐   mTLS    │                                          │
   │  Agent   │◀─────────▶│  API (FastAPI)  ──┐                      │
   │ (homelab)│  gRPC/    │   - enroll        │   ┌───────────────┐  │
   │          │  HTTPS    │   - heartbeat     ├──▶│  Postgres     │  │
   │ discover │           │   - submit scan   │   │  (RLS multi-  │  │
   │ + scan   │           │   - pull jobs     │   │   tenant)     │  │
   └──────────┘           │                   │   └───────────────┘  │
        ▲                 │  Scheduler ───▶ Redis queue ───▶ Workers │
        │ ships           │                                  │       │
        │ detections      │  Workers:                        ▼       │
   ┌──────────┐           │   - Nuclei exec engine    ┌───────────┐  │
   │Detection │──────────▶│   - custom modules        │ AI triage │  │
   │ catalog  │  signed   │   - findings normalize    │ (Claude)  │  │
   │ (YAML)   │  bundles  │                           └───────────┘  │
   └──────────┘           │  Alerting ─▶ Telegram / email / webhook  │
                          │  Web UI (React/Vite/Tailwind)            │
                          └─────────────────────────────────────────┘
                          Ops: Terraform · CI/CD · Prom/Grafana/Loki/OTel · status page
```

### Scan execution model
- **Light scans** (port/service discovery, banner, version) run **on the agent** — keeps internal assets internal.
- **Detection logic** runs **agent-side too** by default (zero exfil of internal traffic); the agent pulls signed detection bundles and reports only normalized findings.
- **External/perimeter scans** (what's exposed to the internet) can optionally run from a control-plane worker for an attacker's-eye view.
- This split is the privacy story *and* the distributed-systems story.

### 4.5 Agent inner loop (one host, end to end)

Design rule: **thin pull-only agent, smart control plane.** The agent never
accepts inbound connections; it pulls work via heartbeat (firewall-friendly,
core to the trust story). Scheduling, catalog matching, dedupe, triage, and
alerting all live server-side.

```
 ENROLL (once)                 STEADY STATE (forever, ~30s tick)
 curl | sh                     heartbeat ─▶ pull jobs ─▶ run ─▶ report
 palisade enroll --token …                   └──── loop ────┘
```

**0. Enroll (once).** `POST /v1/agents/enroll {token, hostinfo}` → server
validates a single-use token, joins the agent to the token's org, and returns
`agent_id` + `agent_secret` (the target is an mTLS client cert; 15-min token
expiry is not yet enforced). Agent stores the secret; all later agent calls send
it as `Authorization: Bearer <agent_secret>`.

**1. Heartbeat (the clock).** Every ~30s `POST /v1/agents/{id}/heartbeat
{version,status,capacity}` → `{jobs:[{type:"discover"|"scan",...}]}`. Server
decides what/when; agent executes.

**2. Discover.** Enumerate local listening sockets (`/proc`) + optional in-scope
subnet sweep (naabu); fingerprint service+version (httpx). `POST
/v1/agents/{id}/assets [...]` → server upserts inventory, diffs vs last.

**3. Scan.** Server matches assets to catalog by service+version → job
`{scan_id, targets:[{asset_id, detection_ids:[...]}]}`. Agent pulls signed
bundle, **verifies minisign before executing**, runs each detection locally
(nuclei engine or Go module), safe-check variants only. Raw bodies stay local.

**4. Report.** Agent emits `{detection_id, asset_id, severity, fingerprint,
evidence}` where `fingerprint = hash(asset_id+detection_id+key_evidence)`.
`POST /v1/scans/{scan_id}/findings [...]` → pipeline: ingest → dedupe by
fingerprint → diff vs open → classify event → store.

**Finding state machine (server-side):**
```
 new fingerprint ──────────────▶ open ──▶ AI triage ──▶ alert
 still present on rescan ───────▶ open (bump last_seen, no re-alert)
 absent on rescan ──────────────▶ resolved
 reappears after resolved ──────▶ regressed ──▶ alert
 user silences ─────────────────▶ muted (ttl)
```

*Implemented:* alert-rule evaluation runs inside the ingest transaction; both
alert delivery and AI triage run in background tasks off the request path (not a
queue/worker yet).

**The boundary:** on-host = discovery + detection execution + raw evidence;
across the wire = normalized assets + findings only; control plane =
scheduling, matching, dedupe, AI triage, alerting, multi-tenant storage.

---

## 5. Components

### 5.1 Agent (Go, single static binary)
- Cross-platform (Linux/macOS/ARM for NAS/Pi), no runtime deps.
- Enrolls with a one-time token → receives mTLS client cert.
- Modes: `discover` (asset inventory), `scan` (run detection bundle), `heartbeat`.
- Embeds the Nuclei engine + custom Go detection modules.
- Reports normalized findings only; raw response bodies stay local unless user opts in.
- Auto-updates detection bundles; binary updates are user-approved.

*Why Go:* static binary distribution, the ProjectDiscovery ecosystem (nuclei, naabu, httpx) is Go-native.

### 5.2 Control plane API (Python / FastAPI)
- Matches existing stack (sentinel). Async, OpenAPI auto-docs.
- Endpoints: enrollment, heartbeat, job pull, finding submit, catalog distribution, UI BFF.
- AuthN: user sessions (web) + agent mTLS. AuthZ: org-scoped RBAC.

### 5.3 Scan engine
- Scheduler enqueues per-asset scan jobs (cron-like, per-org cadence).
- Redis + Arq workers for control-plane-side work (external scans, normalization, AI triage).
- Idempotent jobs; findings deduped by stable fingerprint.

### 5.4 Detection catalog
- Git-backed, versioned YAML. Two kinds:
  - **Nuclei-compatible** templates (HTTP/TCP/DNS) for fast authoring.
  - **Custom modules** (Go) for multi-step logic Nuclei can't express (auth-bypass chains, stateful RCE PoCs).
- Bundles are **signed** (cosign/minisign); agents verify before execution.
- Seeded from CVEs the author already understands.

### 5.5 Findings pipeline
- ingest → normalize (CVSS, category, asset link) → dedupe (fingerprint) → store → diff vs last scan → emit events (new / resolved / regressed).

### 5.6 AI triage layer (Claude)
- Per finding: plain-English explanation, blast radius, prioritized remediation, exploitability note.
- **Detection authoring assistant:** drafts a candidate template from a CVE advisory URL → author reviews/signs. Ties into your garak / LLM-sec work.
- Guardrails: AI never auto-publishes detections; never sees raw internal response bodies unless opted in.

### 5.7 Alerting (implemented)
- Channels: Telegram, email, generic webhook. Channel secrets redacted on read.
- Rules: `min_severity` threshold + `on_events` (`new` | `regressed`) → channel,
  plus per-finding mute (ttl). Quiet hours not yet implemented.
- Alert history table; delivery in a background task.

---

## 6. Data model

```
org(id, name, plan, created_at)
user(id, org_id, email, role[owner|admin|viewer], auth)
agent(id, org_id, name, fingerprint, last_seen, version, status, cert_serial)
asset(id, org_id, agent_id, hostname, ip, port, service, product, version,
      exposure[internal|external], first_seen, last_seen)
detection(id, slug, title, severity, category, cve, engine[nuclei|module],
          spec_ref, version, signature, author, published_at)
scan(id, org_id, agent_id, started_at, finished_at, status, assets_count)
finding(id, org_id, asset_id, detection_id, scan_id, severity, status[open|
        resolved|muted|regressed], fingerprint, evidence, ai_triage_json,
        first_seen, last_seen)
alert(id, org_id, finding_id, channel, sent_at, status)
audit_log(id, org_id, actor, action, target, at)
```

- **Isolation:** Postgres **Row-Level Security** keyed on `org_id` for every tenant table. Belt-and-suspenders with app-layer org scoping. **Implemented** (migration 0003) on agent, asset, scan, finding, alert_channel, alert_rule, alert, posture_snapshot, keyed on the `app.current_org_id` GUC the app sets per request; skipped on SQLite. The app must run as a **non-owner** Postgres role in prod (owner bypasses RLS; bootstrap relies on owner-bypass to seed). *Known limitation:* the `/v1/detections` cross-tenant `tenants_hit`/`tenants_total` aggregate is RLS-scoped on Postgres and needs a security-definer/unscoped path to be a true platform metric.
- *Implementation note:* users are stored in `app_user` with a separate `membership(user_id, org_id, role)` join (a user can belong to many orgs), not a single `org_id` on the user row; sessions live in `user_session`; single-use enroll tokens in `enroll_token`.
- `evidence` and any raw payloads encrypted at rest (per-org key envelope) — *not yet implemented.*

---

## 7. Detection format

```yaml
id: litellm-proxy-preauth-sqli
title: LiteLLM proxy pre-auth SQLi
cve: CVE-2026-42208
severity: critical          # critical|high|medium|low|info
category: ai-infra          # ai-infra|self-hosted|web|backup|observability
engine: nuclei              # nuclei | module
match:
  service: litellm
  versions: "<1.40.2"
http:
  - method: POST
    path: /key/info
    body: '{"key":"1'' OR sleep(5)-- -"}'
    matchers:
      - type: dsl
        dsl: ["duration>=5"]
remediation: |
  Upgrade LiteLLM to >=1.40.2. Restrict /key/* to authenticated admin.
references:
  - https://github.com/.../advisory
signature: <minisign>
```

Custom-module detections reference a compiled Go module by `spec_ref` instead of inline `http`.

---

## 8. API (key endpoints)

```
# agent-authenticated (Authorization: Bearer <agent_secret>; mTLS is the target)
POST /v1/agents/enroll            {token}            -> {agent_id, agent_secret}
POST /v1/agents/{id}/heartbeat    {version,status}   -> {jobs:[...]}
POST /v1/agents/{id}/assets       [...]              -> {asset_ids}
POST /v1/scans/{id}/findings      [normalized...]    -> 202
GET  /v1/catalog/bundle?since=ver                    -> signed bundle

# user-session-authenticated (Authorization: Bearer <session-token>), org-scoped
POST /v1/auth/login               {email,password}   -> {token, org, role, memberships}
POST /v1/auth/logout                                 -> 204
GET  /v1/auth/me                                      -> current user/org/role
POST /v1/auth/switch-org          {org_id}           -> current user/org/role
GET  /v1/assets                                       -> list
GET  /v1/findings?status=open&severity=critical       -> list
POST /v1/findings/{id}/mute        {reason,ttl}       -> finding   (member+)
POST /v1/rescan                                       -> nudge agents (member+)
GET  /v1/posture/summary                              -> score + counts + trend30d
GET  /v1/detections                                   -> catalog rows
POST /v1/detections                {detection}        -> {id, version}  (admin+)
POST /v1/detections/draft          {cve_url}          -> draft (AI)
GET  /v1/alerts                                       -> alert history
GET/POST/PATCH/DELETE /v1/alert-channels[/{id}]                  (admin+ to mutate)
POST /v1/alert-channels/{id}/test                    -> {ok, error}   (admin+)
GET/POST/PATCH/DELETE /v1/alert-rules[/{id}]                     (admin+ to mutate)
```

> **Auth note (implemented):** enrollment returns a bearer `agent_secret`, not an
> mTLS cert; tokens are single-use but not yet 15-min-expiring. mTLS remains the
> production target (section 11).

---

## 9. Wireframes

### 9.1 Dashboard (landing after login)

```
┌ Palisade ───────────────────────────── [org ▾]  [⚙]  [you ▾] ┐
│                                                               │
│  POSTURE                          ◐ Score 72/100  ▲ +6 (7d)   │
│  ┌──────────────┬──────────────┬──────────────┬────────────┐ │
│  │ ● Critical 2 │ ● High    5  │ ● Medium 11  │ Assets  38 │ │
│  └──────────────┴──────────────┴──────────────┴────────────┘ │
│                                                               │
│  FINDINGS OVER TIME                                           │
│   crit ┤   ▁▁▂▂▁▁▁                                            │
│   high ┤ ▃▃▃▂▂▂▁▁                                            │
│        └─────────────────────────────────────── 30d          │
│                                                               │
│  NEEDS ATTENTION                                  [view all ▸]│
│  ┌───────────────────────────────────────────────────────┐  │
│  │ ⛔ LiteLLM pre-auth SQLi      ai.lab:4000   new  2h    │  │
│  │ ⛔ Audiobookshelf auth bypass abs.lab:13378 new  2h    │  │
│  │ ⚠  Next.js middleware bypass  web.lab:3000  open 3d    │  │
│  └───────────────────────────────────────────────────────┘  │
│                                                               │
│  AGENTS   ● nas-proxmox (12s ago)   ● pi-edge (40s ago)      │
└───────────────────────────────────────────────────────────────┘
```

### 9.2 Asset inventory

```
┌ Assets ──────────────────────────── [search ____]  [exposure ▾] ┐
│ HOST            SERVICE    VER      EXPOSURE  FINDINGS  SEEN     │
│ ─────────────────────────────────────────────────────────────  │
│ ai.lab:4000     litellm    1.39.0   external  ⛔1 ⚠0    2h ago  │
│ abs.lab:13378   audiobook  2.7.0    external  ⛔1 ⚠1    2h ago  │
│ web.lab:3000    next.js    14.1.0   external  ⚠1        3d ago  │
│ nas.lab:9000    minio      —        internal  ✓ clean   1h ago  │
│ ollama.lab:11434 ollama    0.3.1    internal  ⚠2        1h ago  │
│                                                  ◀ 1 2 3 ▶      │
└─────────────────────────────────────────────────────────────────┘
```

### 9.3 Finding detail (the money screen)

```
┌ ⛔ LiteLLM proxy pre-auth SQLi ───────────── CVE-2026-42208 ┐
│ Asset  ai.lab:4000 (external)   Severity CRITICAL  CVSS 9.8 │
│ Status [ Open ▾]   First seen 2h ago   [Mute] [Rescan]      │
│                                                            │
│ ── AI TRIAGE ──────────────────────────────────────────── │
│ What: Unauthenticated SQL injection in /key/info lets an   │
│   attacker read the API-key table without credentials.     │
│ Blast radius: Full disclosure of all proxy API keys →      │
│   downstream LLM accounts compromised. Internet-exposed.   │
│ Fix (do this): 1) Upgrade LiteLLM ≥1.40.2  2) Put /key/*   │
│   behind admin auth  3) Rotate all proxy keys.             │
│                                                            │
│ ── EVIDENCE ───────────────────────────────────────────── │
│ POST /key/info  →  response time 5.02s (baseline 0.04s)    │
│ [show request]  [show raw response (stored locally)]       │
│                                                            │
│ References: advisory · your MSF module #21567              │
└────────────────────────────────────────────────────────────┘
```

### 9.4 Agent install (onboarding)

```
┌ Add an agent ────────────────────────────────────────────┐
│ 1. Run on the host you want to monitor:                   │
│                                                           │
│    curl -fsSL https://palisade.sh/install | sh \          │
│      && palisade enroll --token  PLS-7F3A-9C21-LK48       │
│                                                           │
│    (token expires in 15 min, single use)                 │
│                                                           │
│ 2. Waiting for first heartbeat...   ◐ listening          │
│                                                           │
│ Supports: Linux x86_64/arm64 · macOS · Synology · Pi      │
└───────────────────────────────────────────────────────────┘
```

### 9.5 Detection catalog (author view)

```
┌ Detections ─────────────────────────── [+ New from CVE URL] ┐
│ SLUG                       SEV   CAT        TENANTS HIT  VER │
│ litellm-proxy-preauth-sqli ⛔    ai-infra   3 / 7     v4   │
│ nextjs-middleware-bypass   ⚠     web        5 / 7     v2   │
│ audiobookshelf-authbypass  ⛔    self-host  2 / 7     v1   │
│ ollama-exposed-noauth      ⚠     ai-infra   4 / 7     v1   │
│                                                            │
│ [+ New from CVE URL] → AI drafts template → you review/sign│
└────────────────────────────────────────────────────────────┘
```

---

## 10. Tech stack

| Layer | Choice | Rationale |
|-------|--------|-----------|
| Agent | Go | static binary, ProjectDiscovery ecosystem |
| API | FastAPI (Python) | matches sentinel; async; OpenAPI |
| Workers | Arq + Redis | async, FastAPI-friendly |
| DB | Postgres + RLS | multi-tenant isolation |
| Frontend | React + Vite + Tailwind + TS strict | matches MagnetShelf/Seventeen |
| Detection exec | Nuclei engine + Go modules | don't reinvent HTTP matching |
| AI | Claude API | triage + detection drafting |
| Signing | minisign/cosign | trusted bundle distribution |
| IaC | Terraform + Docker Compose (+ optional k3s) | self-host friendly |
| Observability | Prometheus + Grafana + Loki + OTel | the ops story |
| Host | Hetzner/Fly + Cloudflare edge | cheap; matches CF Pages exp. |

---

## 11. Security & privacy (it's a security product — must be trustworthy)

- **Default no-exfil:** detections run agent-side; only normalized findings leave the network. Raw evidence stays local unless opted in.
- **mTLS** agent↔control plane; one-time enrollment tokens.
- **Postgres RLS** per `org_id`; encrypted evidence at rest (per-org envelope key).
- **Signed detection bundles**; agent verifies before execution (supply-chain integrity — you, of all people, must get this right).
- **AI guardrails:** never auto-publishes detections; no raw internal bodies sent to the LLM without opt-in.
- **Audit log** for every privileged action.
- **Responsible scanning:** rate limits, scope confirmation, no destructive PoCs run by default (safe-check variants).

---

## 12. Roadmap / milestones

**M0 — Skeleton (week 1–2):** repo, IaC, CI/CD, Postgres+RLS, FastAPI health, agent enroll + heartbeat, deployed live + status page.

**M1 — Discover (week 2–3) — implemented:** agent asset discovery → inventory UI. Multi-tenant auth + org RBAC (users/sessions/memberships, owner/admin/member/viewer roles, single-use enroll tokens, Postgres Row-Level Security per `org_id`).

**M2 — Detect (week 3–5):** Nuclei engine in agent, signed bundles, 10–15 seeded detections, findings pipeline + dashboard.

**M3 — Triage + alert (week 5–6) — implemented:** AI triage on findings (background, off the ingest request path); Telegram/email/webhook alert channels + severity/event rules + alert history.

**M4 — Author loop (week 6+):** "new detection from CVE URL" AI drafting + sign/publish — implemented. Posture trends — implemented (real 30-day series from daily snapshots).

**Post-MVP:** external/perimeter scan worker, more AI-infra detections, scheduled reports, customer due-diligence export.

---

## 13. Success criteria (portfolio-grade, not feature count)

- Live URL, real uptime, public status page.
- ≥1 external tenant onboarded besides you.
- Full IaC apply-from-scratch in one command.
- Runbook + on-call doc + observability dashboards.
- A blog post: "I run a security platform that detects the CVEs I report."

---

## 14. Open questions / risks

- **Liability of active scanning** — keep PoCs non-destructive; require scope acknowledgement.
- **Nuclei licensing/embedding** — verify license fit for redistribution in the agent.
- **Detection freshness** — the moat decays without steady authoring; the AI loop must make this cheap.
- **Trust bootstrapping** — a security SaaS asking for an agent on your box is a hard sell; default-no-exfil + open-source agent mitigates.
- **Name** — "Palisade" availability (domain, npm, trademark) unchecked.
