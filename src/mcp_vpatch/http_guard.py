"""Localhost reverse proxy that enforces Host/Origin rules for HTTP MCP servers.

    mcp-vpatch http-guard --listen 127.0.0.1:8765 --upstream http://127.0.0.1:8080

Point the MCP client at the listen address and stop exposing the upstream
port. Requests whose Host or Origin fail a ``block`` rule get a 403 and never
reach the server; ``Access-Control-Allow-Origin: *`` is removed from
responses when a rule asks for it. Responses are streamed, so SSE and
Streamable HTTP keep working.

The guard only listens on loopback addresses: it exists to protect local
servers from the browser, not to publish them.
"""
from __future__ import annotations

import http.client
import json
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from mcp_vpatch.conditions import Context
from mcp_vpatch.engine import blocks, evaluate_http
from mcp_vpatch.rules import Rule

HOP_BY_HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
              "te", "trailers", "transfer-encoding", "upgrade"}
LOOPBACK_BINDS = {"127.0.0.1", "localhost", "::1"}


def make_server(listen: tuple[str, int], upstream: str, rules: list[Rule], ctx: Context,
                monitor: bool = False, log=None) -> ThreadingHTTPServer:
    if listen[0] not in LOOPBACK_BINDS:
        raise ValueError("http-guard only listens on loopback (127.0.0.1, ::1, localhost)")
    up = urlsplit(upstream)
    if up.scheme not in ("http", "https") or not up.hostname:
        raise ValueError(f"bad upstream URL {upstream!r}")
    up_port = up.port or (443 if up.scheme == "https" else 80)
    strip_cors = any(r.strip_wildcard_cors for r in rules if r.kind == "http")
    logs = [sys.stderr] + ([log] if log else [])

    def write_log(event: dict) -> None:
        line = json.dumps({"ts": round(time.time(), 3), "guard": "mcp-vpatch-http", **event})
        for f in logs:
            try:
                f.write(line + "\n")
                f.flush()
            except (OSError, ValueError):
                pass

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):  # quiet default access log
            pass

        def _handle(self):
            decisions = evaluate_http(rules, dict(self.headers.items()), ctx)
            hard = blocks(decisions)
            if decisions:
                write_log({"event": "blocked" if hard and not monitor else "matched",
                           "method": self.command, "path": self.path,
                           "decisions": [d.to_dict() for d in decisions]})
            if hard and not monitor:
                # Drain the request body and close, so leftover bytes are never
                # parsed as a second request on a kept-alive connection.
                n = int(self.headers.get("Content-Length") or 0)
                if n:
                    self.rfile.read(n)
                self.close_connection = True
                body = json.dumps({"error": "blocked by virtual patch",
                                   "rules": sorted({d.rule_id for d in hard})}).encode()
                self.send_response(403)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(body)
                return
            self._forward()

        def _forward(self):
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length else None
            headers = {k: v for k, v in self.headers.items() if k.lower() not in HOP_BY_HOP}
            headers["Host"] = f"{up.hostname}:{up_port}"
            conn_cls = http.client.HTTPSConnection if up.scheme == "https" else http.client.HTTPConnection
            conn = conn_cls(up.hostname, up_port, timeout=300)
            try:
                conn.request(self.command, self.path, body=body, headers=headers)
                resp = conn.getresponse()
            except OSError as exc:
                msg = f"upstream unreachable: {exc}".encode()
                self.send_response(502)
                self.send_header("Content-Length", str(len(msg)))
                self.end_headers()
                self.wfile.write(msg)
                return
            self.send_response(resp.status, resp.reason)
            has_length = False
            for k, v in resp.getheaders():
                lk = k.lower()
                if lk in HOP_BY_HOP:
                    continue
                if strip_cors and lk == "access-control-allow-origin" and v.strip() == "*":
                    continue
                if lk == "content-length":
                    has_length = True
                self.send_header(k, v)
            chunked = not has_length and self.command != "HEAD" and resp.status not in (204, 304)
            if chunked:
                self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            try:
                while True:
                    chunk = resp.read1(65536)
                    if not chunk:
                        break
                    if chunked:
                        self.wfile.write(f"{len(chunk):X}\r\n".encode() + chunk + b"\r\n")
                    else:
                        self.wfile.write(chunk)
                    self.wfile.flush()
                if chunked:
                    self.wfile.write(b"0\r\n\r\n")
            except (BrokenPipeError, ConnectionResetError):
                pass
            finally:
                conn.close()

        do_GET = do_POST = do_DELETE = do_PUT = do_PATCH = do_OPTIONS = do_HEAD = _handle

    cls = ThreadingHTTPServer
    if ":" in listen[0]:
        import socket

        class V6(ThreadingHTTPServer):
            address_family = socket.AF_INET6
        cls = V6
    server = cls(listen, Handler)
    server.daemon_threads = True
    return server
