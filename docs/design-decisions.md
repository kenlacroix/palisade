# Design decisions

Why Palisade is built the way it is. Each decision lists the **context**, the
**choice**, and the **tradeoff** — the threat model and the operator-facing
controls live in [`SECURITY.md`](../SECURITY.md); this is the *why* behind them.

---

## Pull-only agent — raw host surface never leaves

**Context.** A monitored host runs untrusted, internet-facing services. The agent
needs to know what's listening and whether it's vulnerable.

**Choice.** The agent enrolls once, then **pulls** work: it parses its own
`/proc/net/tcp{,6}` for LISTEN sockets, runs detections locally, and ships back
**only normalized findings**. The control plane never reaches into the host, and
the host's raw surface (open ports, banners, process list) never crosses the
wire.

**Why.** A push/scan-from-the-cloud model means the control plane holds inbound
credentials to every host and the host's full surface transits the network. Pull
inverts the trust: a compromised control plane can request a scan but cannot log
in anywhere, and a packet capture between agent and server reveals findings, not
an attack map. It also works behind NAT/CGNAT with no inbound firewall holes.

**Tradeoff.** Detections run with the agent's local view only — on-host services,
not arbitrary network targets. Perimeter/external scanning is a separate,
explicitly-scoped control-plane path (`PALISADE_PERIMETER_SCOPE_ALLOWLIST`,
deny-all by default in production).

## Signed detection catalog — verify before running *anything*, fail closed

**Context.** The agent fetches its detection catalog from the control plane over
a channel that may be untrusted (a tunnel, a CDN, a compromised hop). A forged
catalog is arbitrary code-adjacent: it tells the agent what to probe and how to
decide a host is "fine."

**Choice.** The control plane signs a canonical manifest of the bundle with
**Ed25519**; the agent rebuilds the same manifest and verifies it against a
**pinned public key** before running a single detection. Empty signature →
refuse. Verification failure → refuse. Only a valid signature (or, in dev, the
explicit `"stub"` sentinel with a warning) lets detections run.

**Why.** Integrity has to be enforced at the *consumer*, independent of transport
security, or the catalog is a silent supply-chain hole. Fail-**closed** is the
only safe default for an integrity check: a scanner that runs an unverified
catalog is worse than one that runs nothing, because it reports false assurance.

**Tradeoff.** Operators must manage a keypair (rotate the seed, re-pin the
pubkey). The startup preflight refuses to boot production on the public demo seed
precisely so this can't be skipped by accident.

## Version-aware matching — but fail *open* on unknown versions

**Context.** Detections target a service *and* a version range (`litellm
<1.40.2`). The asset's version is often unknown or in a vendor format PEP 440
can't parse.

**Choice.** Match by service and version range; when the version is missing or
unparseable, **scan anyway** (return true).

**Why.** This is the deliberate inverse of the signing decision, and the asymmetry
is the point. For *integrity* the cost of a false "trusted" is catastrophic, so
fail closed. For *coverage* the cost of a false "not applicable" is a silently
skipped real vuln, so fail open — a redundant probe is cheap; a missed critical
is not.

**Tradeoff.** Occasional probes against assets that turn out not to be in range.
Acceptable: detections are non-destructive identification checks, not exploits.

## Postgres RLS + a non-superuser app role — defense in depth past the ORM

**Context.** One database holds every tenant's assets, findings, and secrets.
Application-layer `WHERE org_id = ?` filters are one forgotten clause away from a
cross-tenant leak.

**Choice.** Row-Level Security keyed on `org_id`, with **`FORCE ROW LEVEL
SECURITY`** (migration 0011) so it applies even to the table owner, and a
**NOLOGIN, NOSUPERUSER `palisade_app` role** that the app `SET LOCAL ROLE`s into
before every tenant query (migration 0012). The `app.current_org_id` GUC becomes
a database-level backstop, proven in CI (`rls_postgres_test.py`).

**Why.** RLS that's merely `ENABLE`d is a no-op for a superuser connection — and
the app *was* the superuser, so isolation rode entirely on Python filters. The
control plane is the highest-value asset in the system; tenant isolation belongs
*below* the application, where an app-layer bug can't reach it. Two independent
layers (ORM filter + DB policy) must both fail to leak data.

**Tradeoff.** A per-transaction `SET LOCAL ROLE` round-trip and more migration
machinery. Connecting as a dedicated least-privilege role for the whole session
is the stronger next step (noted in `SECURITY.md` → residual risks).

## Encrypt evidence and the CA key at rest — survive a stolen dump

**Context.** Finding evidence can contain sensitive response data, and the
internal **mTLS CA private key** lives in the same database. A stolen DB dump
otherwise yields plaintext evidence and the ability to mint trusted agent certs.

**Choice.** Seal both with **AES-256-GCM** under a per-deployment KEK
(`PALISADE_EVIDENCE_KEK`, `enc:v1:` format). Evidence reads fall back to
plaintext for keyless dev; the CA key does **not** fall back — a decrypt failure
hard-stops enrollment rather than silently degrading.

**Why.** The database is the thing most likely to leak (backups, snapshots,
replicas). Encrypting the two highest-value columns turns a dump from "game over"
into "ciphertext." The CA key's no-fallback stance is intentional: a CA that
quietly accepts a wrong key is a CA you can't trust.

**Tradeoff.** The KEK is effectively non-rotatable for the CA key without
re-wrapping it in the same step (documented in `SECURITY.md` → operational notes).

## AI stays off the request path

**Context.** Two features call an LLM: drafting a detection from a CVE advisory,
and triaging new findings. Both are slow, fallible, and network-dependent.

**Choice.** Triage runs in a **background worker** (Arq + Redis, with an
in-process fallback) after ingest commits; drafting is an explicit operator
action behind a review-and-accept step. Ingest never blocks on, and never fails
because of, an LLM call. No key → the features no-op cleanly.

**Why.** A finding must be recorded whether or not the model is reachable,
rate-limited, or wrong. Keeping AI off the ingest path means model failure
degrades a *convenience*, never the core security record. Human-in-the-loop on
drafting keeps a generated detection from shipping to agents unreviewed.

**Tradeoff.** Triage metadata appears a beat after the finding, not synchronously.

## One artifact, env-only differences, home-hostable

**Context.** The same control plane should run on a laptop, a Proxmox box, and a
VPS without divergent builds.

**Choice.** A single image; only environment variables differ between
dev/demo/production. A startup **preflight refuses to boot** a production
(Postgres, no insecure-defaults escape hatch) deployment that still carries any
public default — DB password, signing seed, demo password, or evidence KEK. The
live demo is published from a home box over a **Cloudflare Tunnel** (no port
forwarding, no exposed IP) and is *intentionally* insecure and disposable.

**Why.** "Same artifact everywhere" removes the class of bugs where prod behaves
unlike the thing you tested. The preflight makes the secure configuration the
*only* one that boots in production, so hardening can't be forgotten — while
dev/demo downgrade the same checks to warnings so the one-command workflow keeps
working. See [`control-plane/deploy/README.md`](../control-plane/deploy/README.md)
for the blast-radius isolation of the demo box.

**Tradeoff.** Operators must supply real secrets to launch production — by
design; the failure mode is "won't start," not "started insecure."
