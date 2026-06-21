# Palisade M0 — End-to-End Demo

Runs the full loop on one machine: control plane up, a fake-vulnerable target
exposed, agent enrolled + running, a real finding produced on-host, then observed
via the read APIs.

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

## 5. Terminal D — observe the finding and posture

```bash
BASE=http://127.0.0.1:8000

# assets: the discovered litellm service on :4000 with a critical finding count
curl -s $BASE/v1/assets | python3 -m json.tool

# the finding (open, critical, CVE-2026-42208)
curl -s "$BASE/v1/findings?status=open&severity=critical" | python3 -m json.tool

# posture: score drops by the critical weight (20) -> 80, counts.critical == 1
curl -s $BASE/v1/posture/summary | python3 -m json.tool
```

Expected finding row: `detection_id=litellm-proxy-preauth-sqli`,
`cve=CVE-2026-42208`, `severity=critical`, `status=open`, `host=<this hostname>`,
`port=4000`, evidence `{request:"POST /key/info", note:"matched dsl:... in ~6s"}`.

## 6. Optional — mute and watch posture recover

```bash
BASE=http://127.0.0.1:8000
FID=$(curl -s "$BASE/v1/findings?status=open" | python3 -c "import sys,json;print(json.load(sys.stdin)['findings'][0]['id'])")
curl -s -X POST $BASE/v1/findings/$FID/mute -H 'content-type: application/json' \
  -d '{"reason":"accepted risk, lab box","ttl_s":3600}' | python3 -m json.tool
curl -s $BASE/v1/posture/summary | python3 -m json.tool   # score back to 100
```

## Cleanup

```bash
# Ctrl-C terminals A, B, C
rm -f /tmp/fake_litellm.py
rm -rf /tmp/palisade-agent
rm -f /home/ken/Documents/GitHub/palisade/control-plane/palisade.db
```

## 7. Optional — signed bundle over an untrusted channel

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

## 8. Optional — draft a detection from a CVE URL and ship it

With `ANTHROPIC_API_KEY` set on the control plane, the **Detections** screen's
**+ New from CVE URL** drafts a detection; **Accept & ship** persists it and
bumps the catalog version so agents pull it next bundle. Headless equivalent:

```bash
curl -s -X POST http://127.0.0.1:8000/v1/detections -H 'content-type: application/json' -d '{
  "id":"acme-rce","title":"ACME RCE","cve":"CVE-2026-9999","severity":"high",
  "category":"web","engine":"nuclei","match":{"service":"acme","versions":"<2.0.0"},
  "http":[{"method":"GET","path":"/x","matchers":[{"type":"status","status":[200]}]}],
  "remediation":"upgrade to >=2.0.0","references":["https://example.com"],"cvss":7.5
}'   # -> {"id":"acme-rce","version":<bumped>}
```

## Notes / known scaffold limits

- The agent scans **on-host only**; the target must listen on this machine.
  Port 4000 is required for the demo because discover maps 4000 -> `litellm`.
- The Next.js detection (`nextjs-middleware-bypass`) is `engine: module` and the
  agent logs+skips module detections, so it cannot be demoed end-to-end yet.
- Auth is a bearer `agent_secret` (mTLS is a documented TODO).
- Catalog bundles are Ed25519-signed when `PALISADE_SIGNING_KEY` is set
  (step 7); unset → `signature` stays `"stub"` and the agent proceeds in dev
  mode after a warning.
- Scan targeting now matches `match.service` **and** `match.versions`, so the
  litellm asset is scanned only when its version is in range (`<1.40.2`).
