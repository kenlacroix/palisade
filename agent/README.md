# Palisade Agent

A thin, **pull-only** Go agent for [Palisade](../SPEC.md). It enrolls once,
then heartbeats the control plane every ~30s, discovers locally listening
services, and runs authored detections **on-host**. It never accepts inbound
connections.

## No-exfil guarantee

Detection logic runs on the agent. Raw HTTP requests and response bodies
**stay local** — they are read into memory only long enough to evaluate
matchers and are never transmitted. Only **normalized findings**
(`detection_id`, `asset_id`, `severity`, a stable `fingerprint`, and a short
evidence note like `POST /key/info` + `matched dsl:duration>=5 in 5.02s`)
cross the wire. This is the core trust story for putting an agent on someone's
box.

## Build

Requires Go 1.22+.

```sh
go build -o palisade ./cmd/palisade
# or run directly
go run ./cmd/palisade <command>
```

Cross-compile for a NAS / Pi:

```sh
GOOS=linux GOARCH=arm64 go build -o palisade-arm64 ./cmd/palisade
```

## Run

### 1. Enroll (once)

```sh
PALISADE_ENROLL_TOKEN=PLS-7F3A-9C21-LK48 palisade enroll --server https://api.trypalisade.dev
# or pipe the token in (e.g. from a secret store) without an env var:
printf %s "$TOKEN" | palisade enroll --token-stdin --server https://api.trypalisade.dev
```

The token is resolved in order: `--token-stdin`, then `PALISADE_ENROLL_TOKEN`,
then the bare `--token` flag. Passing `--token <t>` still works but is
**discouraged** — it is visible in the process list (`ps`).

This calls `POST /v1/agents/enroll` and stores `{agent_id, agent_secret, server}`
plus the issued mTLS client cert (`client_cert_pem`, `client_key_pem`,
`ca_cert_pem`) to `$PALISADE_HOME/config.json` (default
`./.palisade/config.json`, mode `0600`). The enroll token is **single-use**
server-side: it mints exactly
one agent, binds it to the token's org, and is then marked used (re-enrolling
with the same token returns 401). Override the directory with `PALISADE_HOME`:

```sh
PALISADE_HOME=/etc/palisade PALISADE_ENROLL_TOKEN=... palisade enroll --server ...
```

### 2. Run the loop

```sh
palisade run                      # uses server from config
palisade run --server https://...  # override
```

Every heartbeat interval the agent:

1. `POST /v1/agents/{id}/heartbeat` → receives `jobs`.
2. **discover** jobs: enumerate listening TCP sockets from `/proc/net/tcp` and
   `/proc/net/tcp6` (LISTEN state), guess the service from well-known ports,
   classify exposure (loopback/private = internal, else external), then
   `POST /v1/agents/{id}/assets`.
3. **scan** jobs: `GET /v1/catalog/bundle`, verify the bundle signature is
   present, then for each target run the matching detection's HTTP steps and
   `POST /v1/scans/{scan_id}/findings`.

## Detection matchers

For `engine: nuclei` detections the agent evaluates these matcher types
(ANDed, nuclei default):

- **`dsl`** — duration comparisons `duration>=N` / `>` / `<=` / `<` / `==`,
  where `N` is seconds. Used for time-based detections (e.g. blind SQLi sleep
  payloads).
- **`word`** — response body contains **all** listed words.
- **`status`** — response status code is in the list.

`engine: module` detections run a compiled module when one is registered for
the detection's `spec_ref` (e.g. the Next.js middleware bypass), otherwise they
interpret the declarative `flow` shipped in the signed catalog. A module with
neither is skipped with a logged note.

## Auth

Enrollment returns both an `agent_secret` and an **mTLS client cert** (issued by
the control plane's internal CA). Over an **https** server the agent presents the
stored client cert + key for mutual TLS (CA PEM as the trusted root); over
plaintext **http** it falls back to `Authorization: Bearer <agent_secret>`. The
server prefers the cert when both are sent, and can require it via
`PALISADE_REQUIRE_MTLS`. See `client.NewWithCerts` in `internal/client`.

## Layout

```
cmd/palisade/main.go      CLI + steady-state loop
internal/config           config.json persistence (PALISADE_HOME aware; stores mTLS cert/key/CA)
internal/client           control-plane HTTP client (mTLS over https; bearer over http)
internal/catalog          shared wire types + detection format
internal/discover         /proc/net/tcp{,6} listening-socket enumeration
internal/scan             detection execution + matcher engine + fingerprint
```

## Seed detections (end-to-end)

The control plane seeds these CVEs; the agent runs them as-is:

- `litellm-proxy-preauth-sqli` — CVE-2026-42208, ai-infra, critical
  (nuclei: `POST /key/info` with a sleep payload, matcher `duration>=5`).
- `audiobookshelf-authbypass` — CVE-2025-25205, self-hosted, critical.

## Finding fingerprint

```
sha256_hex("<asset_id>|<detection_id>|<short_evidence_key>")
```

The evidence key is the first matched matcher's key, e.g. `dsl:duration>=5`,
`status:500`, or `word:sql,error`.
```

## TODO

- [ ] Subnet sweep for discover jobs with a `scope` (currently on-host
      `/proc` enumeration only).
- [ ] Full nuclei DSL beyond duration comparisons (`internal/scan`).
