"""Live agent<->control-plane integration test.

Unlike smoke_test.py (which exercises the API in-process with TestClient and a
simulated agent), this drives the *real compiled Go agent binary* against a
*real uvicorn server* over HTTP, end to end:

    go build palisade -> uvicorn(app) on a real port
    -> palisade enroll -> palisade run
    -> heartbeat(discover) -> assets -> heartbeat(scan)
    -> agent pulls + verifies the signed bundle, probes a planted vulnerable
       service on-host, reports a finding
    -> finding is readable via the org-scoped read API

Hermetic + fast via two agent knobs:
  PALISADE_PROC_NET           - discovery reads a synthetic socket table, so the
                                agent discovers exactly the planted service and
                                never probes real host services.
  PALISADE_HEARTBEAT_INTERVAL_S - collapse the 30s loop so the scan job lands in
                                ~1s.

The planted service mimics Audiobookshelf < 2.17.0 (CVE-2025-25205): an
unauthenticated GET /api/users that leaks user records, which the seeded
`audiobookshelf-authbypass` detection matches.

Run with:  python -m app.live_integration_test
or:        pytest app/live_integration_test.py
"""
from __future__ import annotations

import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
from contextlib import closing
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import httpx

CP_DIR = Path(__file__).resolve().parents[1]          # control-plane/
REPO_ROOT = CP_DIR.parent
AGENT_DIR = REPO_ROOT / "agent"

ENROLL_TOKEN = "PLS-DEMO"
# Discovery maps this well-known port to the "audiobookshelf" service (see
# agent/internal/discover wellKnown), so the planted service is recognised.
VULN_PORT = 13378
DETECTION_ID = "audiobookshelf-authbypass"
DETECTION_CVE = "CVE-2025-25205"


def _free_port() -> int:
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class _VulnHandler(BaseHTTPRequestHandler):
    """Minimal vulnerable Audiobookshelf: unauthenticated /api/users."""

    def do_GET(self):  # noqa: N802 - stdlib naming
        if self.path == "/api/users":
            body = b'{"users":[{"username":"admin","isActive":true}]}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(404)
        self.end_headers()

    def log_message(self, *_args):  # silence per-request logging
        pass


def _synthetic_proc_net(path: Path) -> None:
    """Write a /proc/net/tcp table with a single LISTEN row for 0.0.0.0:VULN_PORT."""
    hex_port = format(VULN_PORT, "04X")
    header = (
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when "
        "retrnsmt   uid  timeout inode\n"
    )
    row = f"   0: 00000000:{hex_port} 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 0\n"
    path.write_text(header + row)


def _wait_http(url: str, timeout: float, *, expect_status: int | None = None) -> httpx.Response:
    deadline = time.monotonic() + timeout
    last: Exception | None = None
    while time.monotonic() < deadline:
        try:
            r = httpx.get(url, timeout=2.0)
            if expect_status is None or r.status_code == expect_status:
                return r
        except Exception as e:  # noqa: BLE001 - retry until ready
            last = e
        time.sleep(0.2)
    raise TimeoutError(f"timed out waiting for {url}: {last}")


def test_live_agent_control_plane():
    tmp = Path(tempfile.mkdtemp(prefix="palisade-live-"))
    db_path = tmp / "live.db"
    proc_net = tmp / "proc_net_tcp"
    home = tmp / "agent-home"
    binary = tmp / "palisade"

    cp_port = _free_port()
    server_url = f"http://127.0.0.1:{cp_port}"
    hostname = socket.gethostname()

    procs: list[subprocess.Popen] = []
    vuln_srv: ThreadingHTTPServer | None = None
    try:
        # 1) build the real agent binary
        subprocess.run(
            ["go", "build", "-o", str(binary), "./cmd/palisade"],
            cwd=AGENT_DIR, check=True,
        )

        # 2) plant the vulnerable service on the well-known port (all interfaces,
        #    so http://<hostname>:<port> reaches it like the agent will)
        vuln_srv = ThreadingHTTPServer(("0.0.0.0", VULN_PORT), _VulnHandler)
        threading.Thread(target=vuln_srv.serve_forever, daemon=True).start()
        # confirm the agent's eventual target URL is actually reachable
        _wait_http(f"http://{hostname}:{VULN_PORT}/api/users", 5.0, expect_status=200)

        # 3) synthetic socket table -> agent discovers exactly this one service
        _synthetic_proc_net(proc_net)

        # 4) boot the real control plane (uvicorn) on a temp sqlite DB
        cp_env = {
            **os.environ,
            "DATABASE_URL": f"sqlite:///{db_path}",
            "PALISADE_ENROLL_TOKENS": ENROLL_TOKEN,
        }
        procs.append(subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "app.main:app",
             "--host", "127.0.0.1", "--port", str(cp_port)],
            cwd=CP_DIR, env=cp_env,
        ))
        _wait_http(f"{server_url}/healthz", 30.0, expect_status=200)

        agent_env = {
            **os.environ,
            "PALISADE_HOME": str(home),
            "PALISADE_PROC_NET": str(proc_net),
            "PALISADE_HEARTBEAT_INTERVAL_S": "1",
        }

        # 5) enroll the real binary against the live server
        subprocess.run(
            [str(binary), "enroll", "--token", ENROLL_TOKEN, "--server", server_url],
            env=agent_env, check=True,
        )

        # 6) run the agent loop (discover -> assets -> scan -> findings)
        procs.append(subprocess.Popen([str(binary), "run"], env=agent_env))

        # 7) poll the org-scoped read API until the finding lands
        with httpx.Client(base_url=server_url, timeout=5.0) as c:
            r = c.post("/v1/auth/login",
                       json={"email": "demo@palisade.local", "password": "palisade"})
            assert r.status_code == 200, r.text
            sess = {"Authorization": f"Bearer {r.json()['token']}"}

            finding = None
            deadline = time.monotonic() + 30.0
            while time.monotonic() < deadline and finding is None:
                r = c.get("/v1/findings?status=open", headers=sess)
                assert r.status_code == 200, r.text
                for f in r.json()["findings"]:
                    if f["detection_id"] == DETECTION_ID:
                        finding = f
                        break
                if finding is None:
                    time.sleep(0.5)

        assert finding is not None, (
            f"no {DETECTION_ID} finding after live agent run "
            f"(host={hostname}, vuln_port={VULN_PORT})"
        )
        assert finding["severity"] == "critical", finding
        assert finding["cve"] == DETECTION_CVE, finding

        print("LIVE OK: real agent binary -> live control plane -> "
              f"{DETECTION_ID} finding ({DETECTION_CVE})")
    finally:
        for p in procs:
            p.terminate()
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill()
        if vuln_srv is not None:
            vuln_srv.shutdown()


if __name__ == "__main__":
    test_live_agent_control_plane()
