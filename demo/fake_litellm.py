"""Fake-vulnerable LiteLLM proxy for the Palisade demo.

Mimics CVE-2026-42208: a pre-auth time-based SQL injection in the LiteLLM
proxy. It listens on 0.0.0.0:4000 (so the agent classifies exposure as
`external`) and sleeps 6s on `POST /key/info`, satisfying the
`litellm-proxy-preauth-sqli` detection's `duration>=5` matcher.

Stdlib-only; runs under python:3.12-slim with no dependencies.
"""

import time
from http.server import BaseHTTPRequestHandler, HTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("content-length", 0) or 0)
        self.rfile.read(length)
        if self.path == "/key/info":
            time.sleep(6)  # time-based SQLi: trips the duration>=5 matcher
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"ok":true}')

    def log_message(self, *_args):
        pass


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 4000), Handler).serve_forever()
