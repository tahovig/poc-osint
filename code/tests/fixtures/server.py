#!/usr/bin/env python3
"""Minimal HTTP server for local recon-tool test fixtures.

One image covers every fixture host in docker-compose.yml; behavior is
selected via env vars so the "healthy" vs "vulnerable" hosts differ only
in configuration, not code:
  PORT            - port to listen on (default: 80)
  SERVER_BANNER   - value for the Server response header
  SECURE_HEADERS  - "1" to send the security header checklist, "0" to omit it
  EXTRA_HEADERS   - optional "Name:Value,Name:Value" pairs (e.g. X-Powered-By)
"""
import os
from http.server import BaseHTTPRequestHandler, HTTPServer

SECURE_HEADERS = {
    "Content-Security-Policy": "default-src 'self'",
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
}


class FixtureHandler(BaseHTTPRequestHandler):
    server_version = os.environ.get("SERVER_BANNER", "FixtureServer/1.0")
    sys_version = ""

    def do_GET(self):
        self._respond(with_body=True)

    def do_HEAD(self):
        self._respond(with_body=False)

    def _respond(self, with_body):
        self.send_response(200)
        if os.environ.get("SECURE_HEADERS") == "1":
            for name, value in SECURE_HEADERS.items():
                self.send_header(name, value)
        for pair in os.environ.get("EXTRA_HEADERS", "").split(","):
            if ":" in pair:
                name, value = pair.split(":", 1)
                self.send_header(name.strip(), value.strip())
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        if with_body:
            self.wfile.write(b"<html><body>fixture host</body></html>")

    def log_message(self, format, *args):
        pass


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "80"))
    HTTPServer(("0.0.0.0", port), FixtureHandler).serve_forever()
