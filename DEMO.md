# Palisade — End-to-End Demo

Runs the full loop on one machine: control plane up, a fake-vulnerable target
exposed, agent enrolled + running, a real finding produced on-host, then logged
in to the multi-tenant read APIs to observe it — plus optional alerting, signed
bundles, and AI drafting.

The agent discovers services by parsing this host's `/proc/net/tcp{,6}` for
LISTEN sockets and maps **port 4000 -> service `litellm`**. The control plane
then targets the `litellm-proxy-preauth-sqli` detection at that asset. That
detection sends `POST /key/info` and matches on `duration>=5`. So the fake
target below just needs to listen on port 4000 and sleep >=5s on `/key/info`.

Requires: Go 1.22+, Python 3.12 with the control-plane `.venv` already created
(it is). All commands use absolute paths and are copy-pasteable.

---

## 0. One-time: confirm builds (optional)

```bash
cd /home/ken/Documents/GitHub/palisade/agent && go build ./...
/home/ken/Documents/GitHub/palisade/control-plane/.venv/bin/python -m app.smoke_test
/home/ken/Documents/GitHub/palisade/detections/.venv/bin/python /home/ken/Documents/GitHub/palisade/detections/validate.py
```

## 1. Terminal A — start the control plane (fresh DB)

```bash
rm -f /home/ken/Documents/GitHub/palisade/control-plane/palisade.db
cd /home/ken/Documents/GitHub/palisade/control-plane
PALISADE_ENROLL_TOKENS=PLS-DEMO ./.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Leave it running. Health check from another shell:

```bash
curl -s http://127.0.0.1:8000/healthz
```

## 2. Terminal B — start the fake-vulnerable target on port 4000

This stub mimics a vulnerable LiteLLM proxy: it sleeps 6s on `POST /key/info`
(satisfying the `duration>=5` time-based-SQLi matcher).

```bash
cat > /tmp/fake_litellm.py <<'PY'
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

class H(BaseHTTPRequestHandler):
    def do_POST(self):
        ln = int(self.headers.get("content-length", 0) or 0)
        self.rfile.read(ln)
        if self.path == "/key/info":
            time.sleep(6)  # time-based SQLi: triggers duration>=5
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"ok":true}')
    def log_message(self, *a): pass

HTTPServer(("0.0.0.0", 4000), H).serve_forever()
PY
python3 /tmp/fake_litellm.py
```

Leave it running. (Binding `0.0.0.0` makes the agent classify exposure as
`external`.)

## 3. Terminal C — enroll the agent

```bash
cd /home/ken/Documents/GitHub/palisade/agent
export PALISADE_HOME=/tmp/palisade-agent
rm -rf "$PALISADE_HOME"
go run ./cmd/palisade enroll --token PLS-DEMO --server http://127.0.0.1:8000
```

Expected: `palisade: enrolled as agent <uuid> (heartbeat every 30s)`.

## 4. Terminal C — run the agent loop

```bash
cd /home/ken/Documents/GitHub/palisade/agent
PALISADE_HOME=/tmp/palisade-agent go run ./cmd/palisade run
```

What happens (watch the log):
1. heartbeat #1 -> control plane returns a **discover** job (inventory empty).
2. agent enumerates `/proc/net/tcp`, sees port 4000, reports asset
   `service=litellm exposure=external`, logs `discover ...: N asset(s) reported`.
3. heartbeat #2 (after 30s) -> control plane returns a **scan** job targeting the
   litellm asset with `litellm-proxy-preauth-sqli`.
4. agent pulls the catalog bundle, runs `POST /key/info` against the port-4000
   stub, the 6s delay satisfies `duration>=5`, and it logs
   `scan ...: 1 finding(s) reported`.

The first scan job is issued on the **second** heartbeat, so allow ~30-60s. To
skip the wait, leave it running through one tick.

## 5. Terminal D — log in, then observe the finding and posture

The UI/BFF read endpoints require a user session (distinct from the agent
secret). Log in as the seeded demo user and pass the session token as a bearer.

```bash
BASE=http://127.0.0.1:8000

# log in (demo user is seeded into the demo org as owner at bootstrap)
TOKEN=$(curl -s $BASE/v1/auth/login -H 'content-type: application/json' \
  -d '{"email":"demo@palisade.local","password":"palisade"}' \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['token'])")
UAUTH="Authorization: Bearer $TOKEN"

# who am I / which org (owner role on org "demo")
curl -s $BASE/v1/auth/me -H "$UAUTH" | python3 -m json.tool

# assets: the discovered litellm service on :4000 with a critical finding count
curl -s $BASE/v1/assets -H "$UAUTH" | python3 -m json.tool

# the finding (open, critical, CVE-2026-42208)
curl -s "$BASE/v1/findings?status=open&severity=critical" -H "$UAUTH" | python3 -m json.tool

# posture: score drops by the critical weight (20) -> 80, counts.critical == 1.
# trend30d is real: today's live score plus daily snapshots (older days are
# reconstructed from finding first_seen/last_seen).
curl -s $BASE/v1/posture/summary -H "$UAUTH" | python3 -m json.tool
```

Expected finding row: `detection_id=litellm-proxy-preauth-sqli`,
`cve=CVE-2026-42208`, `severity=critical`, `status=open`, `host=<this hostname>`,
`port=4000`, evidence `{request:"POST /key/info", note:"matched dsl:... in ~6s"}`.

## 6. Optional — mute and watch posture recover

Mute requires the `member` role or higher (the demo user is `owner`); reuse the
`$UAUTH` session bearer from step 5.

```bash
FID=$(curl -s "$BASE/v1/findings?status=open" -H "$UAUTH" | python3 -c "import sys,json;print(json.load(sys.stdin)['findings'][0]['id'])")
curl -s -X POST $BASE/v1/findings/$FID/mute -H "$UAUTH" -H 'content-type: application/json' \
  -d '{"reason":"accepted risk, lab box","ttl_s":3600}' | python3 -m json.tool
curl -s $BASE/v1/posture/summary -H "$UAUTH" | python3 -m json.tool   # score back to 100
```

## 7. Optional — alerting (channel + rule + a delivered alert)

Define a channel and a rule, then make a finding fire it. Rules are evaluated on
ingest, so the rule must exist **before** the finding is (re)reported. Easiest
showcase: stand up a local webhook sink, add a webhook channel + a high+ rule,
then nudge a rescan so the agent re-reports the finding.

Reuse `$BASE` and `$UAUTH` from step 5. Channel/rule mutations require `admin`+.
Run this before step 6 (muting) so the finding is still active when it
re-reports — a `new`/`regressed` event fires the rule, a `muted` one does not.

```bash
# Terminal E — a throwaway webhook sink that prints what it receives
cat > /tmp/hook.py <<'PY'
from http.server import BaseHTTPRequestHandler, HTTPServer
class H(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("content-length", 0) or 0)
        print("ALERT:", self.rfile.read(n).decode(), flush=True)
        self.send_response(200); self.end_headers()
    def log_message(self, *a): pass
HTTPServer(("127.0.0.1", 9099), H).serve_forever()
PY
python3 /tmp/hook.py &

# create a webhook channel
CH=$(curl -s -X POST $BASE/v1/alert-channels -H "$UAUTH" -H 'content-type: application/json' \
  -d '{"type":"webhook","name":"local","config":{"url":"http://127.0.0.1:9099/hook"}}' \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['id'])")

# optional: test it now (sends a synthetic message) -> {"ok":true,...}
curl -s -X POST $BASE/v1/alert-channels/$CH/test -H "$UAUTH" | python3 -m json.tool

# rule: fire on any high+ finding that is new or regressed
curl -s -X POST $BASE/v1/alert-rules -H "$UAUTH" -H 'content-type: application/json' \
  -d "{\"name\":\"high+\",\"min_severity\":\"high\",\"on_events\":[\"new\",\"regressed\"],\"channel_id\":\"$CH\"}" \
  | python3 -m json.tool

# nudge a rescan so the next heartbeat re-issues discover/scan and the agent
# re-reports the litellm finding -> the rule fires -> Terminal E prints ALERT:
curl -s -X POST $BASE/v1/rescan -H "$UAUTH" | python3 -m json.tool

# after the next agent cycle (~30-60s), the alert history shows the delivery
curl -s $BASE/v1/alerts -H "$UAUTH" | python3 -m json.tool
```

In the web UI this is the **Alerts** screen (channels, rules, recent alerts),
reachable from the sidebar.

## Cleanup

```bash
# Ctrl-C terminals A, B, C; kill the webhook sink (Terminal E)
rm -f /tmp/fake_litellm.py /tmp/hook.py
rm -rf /tmp/palisade-agent
rm -f /home/ken/Documents/GitHub/palisade/control-plane/palisade.db
```

## 8. Optional — signed bundle over an untrusted channel

Restart the control plane (Terminal A) with the demo signing key so the catalog
bundle is Ed25519-signed instead of `"stub"`:

```bash
cd /home/ken/Documents/GitHub/palisade/control-plane
PALISADE_ENROLL_TOKENS=PLS-DEMO \
PALISADE_SIGNING_KEY=70kJtI1NajTd1yQXFHVRuBVQfc6P2CAtRroaLCmYYbY= \
  ./.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000
```

The agent (Terminal C) pins the matching public key by default, so on its next
scan it logs `bundle signature verified (N detections)` before running anything.
The bundle now carries a real base64 signature:

```bash
curl -s "http://127.0.0.1:8000/v1/catalog/bundle?since=0" \
  -H "Authorization: Bearer $SECRET" | python3 -c "import sys,json;print(json.load(sys.stdin)['signature'][:24],'...')"
```

Tamper test: point the agent at a wrong pubkey and it refuses to scan —
`PALISADE_CATALOG_PUBKEY=AAAA...` on the agent → `bundle signature verification
FAILED, refusing to run detections`.

## 9. Optional — draft a detection from a CVE URL and ship it

With `ANTHROPIC_API_KEY` set on the control plane, the **Detections** screen's
**+ New from CVE URL** drafts a detection; **Accept & ship** persists it and
bumps the catalog version so agents pull it next bundle. Headless equivalent
(accept requires an `admin`+ session bearer; reuse `$UAUTH` from step 5):

```bash
curl -s -X POST http://127.0.0.1:8000/v1/detections -H "$UAUTH" -H 'content-type: application/json' -d '{
  "id":"acme-rce","title":"ACME RCE","cve":"CVE-2026-9999","severity":"high",
  "category":"web","engine":"nuclei","match":{"service":"acme","versions":"<2.0.0"},
  "http":[{"method":"GET","path":"/x","matchers":[{"type":"status","status":[200]}]}],
  "remediation":"upgrade to >=2.0.0","references":["https://example.com"],"cvss":7.5
}'   # -> {"id":"acme-rce","version":<bumped>}
```

## Notes / known scaffold limits

- The agent scans **on-host only**; the target must listen on this machine.
  Port 4000 is required for the demo because discover maps 4000 -> `litellm`.
- The Next.js detection (`nextjs-middleware-bypass`) is `engine: module`; its
  `spec_ref` (`modules/nextjs_middleware_bypass`) is registered in the agent
  binary and runs on-host like any other detection. Module detections whose
  `spec_ref` is unregistered and carry no declarative `flow` are logged+skipped.
- Two credentials: agents send a bearer `agent_secret`; in production enroll also
  issues a client cert from an internal CA (mTLS), verified at a TLS-terminating
  proxy, with the bearer as the plaintext-demo fallback. The web UI / read APIs
  require a user **session** bearer from `POST /v1/auth/login` (step 5),
  org-scoped with owner/admin/member/viewer roles.
- Catalog bundles are Ed25519-signed when `PALISADE_SIGNING_KEY` is set
  (step 8); unset → `signature` stays `"stub"` and the agent proceeds in dev
  mode after a warning.
- Scan targeting now matches `match.service` **and** `match.versions`, so the
  litellm asset is scanned only when its version is in range (`<1.40.2`).
