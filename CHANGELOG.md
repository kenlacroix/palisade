# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.2] - 2026-06-22

### Added

- Lint and format tooling across all components: `ruff` (control plane),
  `golangci-lint` (agent), and ESLint + Prettier (web), plus `make lint` /
  `make fmt` targets and a `lint` CI job.
- CI now runs the web `vitest` suite and production build.
- `CONTRIBUTING.md` and `CHANGELOG.md`.

### Changed

- The agent installer now pins to a known-good release by default
  (`PALISADE_VERSION` overrides; set it to `latest` to track newest).

### Fixed

- The agent now reports its real version (`0.1.2`); the constant had been left at
  `0.1.0`.
- Corrected stale docs: `agent/README.md` (module engine and Ed25519 fail-closed
  verification are implemented, no longer TODO) and the README Tests section.

## [0.1.1] - 2026-06-22

### Added

- Release `SHA256SUMS` are signed with minisign and verified by the installer
  when a public key is provisioned.
- Hardened the agent supply chain and enrollment authentication.

### Fixed

- Control plane drops to a non-superuser role so Postgres Row-Level Security
  actually binds.
- Forward `PALISADE_EVIDENCE_KEK`, perimeter scope, `PALISADE_ENV`, bootstrap
  TTL, and `REQUIRE_MTLS` into the api/worker containers.
- Tightened tenant isolation, secret handling, and ingress surfaces.

## [0.1.0] - 2026-06-22

Initial release.

### Added

- **Agent** (Go, stdlib-only): one-time enrollment, on-host service discovery
  via `/proc/net/tcp`, TLS-scheme detection, and local CVE scanning. Only
  normalized findings leave the host.
- **Signed detection catalog**: Ed25519-signed bundles the agent verifies before
  running any detection; fails closed when verification fails.
- **Detection engines**: nuclei-style matchers (dsl/word/status/regex/binary,
  matcher conditions) and a module engine — compiled modules plus signed
  declarative flows (approach B), including the Next.js CVE-2025-29927 module.
- **Version-aware matching**: PEP 440 version ranges so detections fire by
  service and version.
- **Control plane** (FastAPI): findings ingest, 30-day posture scoring and
  trends, channel/rule alerting on new and regressed findings, and LLM-assisted
  detection drafting and triage off the request path.
- **Multi-tenancy**: users, orgs, session auth, RBAC, and Postgres Row-Level
  Security per `org_id` (FORCE RLS on a non-superuser role).
- **Security**: evidence-at-rest encryption (per-org key envelope), mTLS for
  agents, single-use expiring enrollment tokens, and a production preflight gate.
- **Web UI** (React + TypeScript): dashboard, assets, findings, detections,
  alerts, members, and audit screens; read-only demo mode.
- **Marketing site** (Astro) with a live status page and an install script
  served from trypalisade.dev.
- **Demo**: one-command `make demo` full stack with a seeded org and a live
  agent loop against a fake-vulnerable target.

[Unreleased]: https://github.com/kenlacroix/palisade/compare/v0.1.2...HEAD
[0.1.2]: https://github.com/kenlacroix/palisade/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/kenlacroix/palisade/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/kenlacroix/palisade/releases/tag/v0.1.0
