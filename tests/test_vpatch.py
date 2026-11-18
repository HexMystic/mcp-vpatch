"""Tests for mcp_vpatch (virtual patches)."""
from __future__ import annotations

import http.client
import io
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from mcp_vpatch.cli import main
from mcp_vpatch import http_guard, stdio_guard
from mcp_vpatch.conditions import CHECKS, Context
from mcp_vpatch.engine import evaluate_http, evaluate_tool_call, run_fixtures
from mcp_vpatch.rules import RuleError, load_rules, parse_rule, select_rules

FIXTURES = Path(__file__).parent / "fixtures"
ALL_RULES = load_rules()

# Advisory rules may only describe bugs that are PUBLIC and FIXED. Adding a
# package here is a deliberate act: check the advisory is published first.
PUBLIC_FIXED_PACKAGES = {
    "mcp-server-kubernetes": {"CVE-2026-85753", "GHSA-cmgv-rr9q-f7gw"},
    "davinci-resolve-mcp": {"GHSA-x29h-6rgf-w233"},
    "fastmcp": set(),  # fixed in 4.26.2 (commit 3a4faf3); no advisory id of ours
    "@1mcp/agent": {"GHSA-vrqm-3x52-5334"},  # published 2026-11-18, patched 0.39.9
}


# --- the catalog -----------------------------------------------------------------

@pytest.mark.parametrize("rule", ALL_RULES, ids=lambda r: r.id)
def test_rule_fixtures(rule):
    results = run_fixtures(rule)
    assert results, f"{rule.id} has no fixtures"
    bad = [f"must-{r.expect} #{r.index}: {r.detail}" for r in results if not r.ok]
    assert not bad, bad


def test_every_advisory_rule_is_public_and_fixed():
    for r in ALL_RULES:
        if r.is_class_rule:
            continue
        pkg = r.affected.get("package")
        assert pkg in PUBLIC_FIXED_PACKAGES, f"{r.id}: {pkg} is not on the public+fixed list"
        assert r.affected.get("fixed"), f"{r.id}: advisory rules must name the fixed version"
        ids = {ref.get("id") for ref in r.references if ref.get("type") in ("CVE", "GHSA")}
        assert ids <= PUBLIC_FIXED_PACKAGES[pkg], f"{r.id}: unexpected advisory ids {ids}"
        assert r.tests.get("block") and r.tests.get("allow")


def test_class_rules_are_opt_in():
    default = select_rules(ALL_RULES)
    assert default and not any(r.is_class_rule for r in default)
    assert any(r.is_class_rule for r in select_rules(ALL_RULES, with_classes=True))
    assert [r.id for r in select_rules(ALL_RULES, package="fastmcp")] == ["GVP-2026-0003"]
    with pytest.raises(RuleError):
        select_rules(ALL_RULES, ids=["GVP-NOPE"])


def test_rule_validation():
    base = {"id": "X", "title": "t", "kind": "tool_call",
            "match": {"tools": ["t"], "args": ["a"]}, "when": [{"starts_with_dash": {}}],
            "tests": {"block": [{"tool": "t", "arguments": {"a": "-x"}}],
                      "allow": [{"tool": "t", "arguments": {"a": "x"}}]}}
    parse_rule(base)
    with pytest.raises(RuleError, match="block AND allow"):
        parse_rule({**base, "tests": {"block": base["tests"]["block"]}})
    with pytest.raises(RuleError, match="unknown check"):
        parse_rule({**base, "when": [{"eval_python": {}}]})
    with pytest.raises(RuleError, match="field"):
        parse_rule({**base, "kind": "http", "when": [{"host_not_loopback": {}}]})


# --- checks ------------------------------------------------------------------------

def test_symlink_escape_is_caught(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    secret = tmp_path / "outside.yaml"
    secret.write_text("x")
    link = root / "values.yaml"
    try:
        link.symlink_to(secret)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not available")
    ctx = Context(roots=[str(root)])
    assert CHECKS["path_outside_roots"](str(link), {}, ctx)
    (root / "real.yaml").write_text("x")
    assert CHECKS["path_outside_roots"](str(root / "real.yaml"), {}, ctx) is None


@pytest.mark.parametrize("url", [
    "http://127.1/", "http://0177.0.0.1/", "http://10.1.2.3:8080/x", "http://[::]/",
    "http://192.168.0.1/", "http://foo.localhost/", "http://0.0.0.0/",
])
def test_ssrf_internal_spellings(url):
    assert CHECKS["url_internal_host"](url, {}, Context())


def test_ssrf_ignores_non_urls():
    assert CHECKS["url_internal_host"]("not a url", {}, Context()) is None


def test_http_allowlists():
    rule = select_rules(ALL_RULES, ids=["GVP-2026-0003"])
    ctx = Context(allow_hosts=["mcp.dev.test"], allow_origins=["https://inspector.dev.test"])
    assert not evaluate_http(rule, {"Host": "mcp.dev.test:9000",
                                    "Origin": "https://inspector.dev.test"}, ctx)
    assert evaluate_http(rule, {"Host": "mcp.dev.test:9000",
                                "Origin": "https://other.dev.test"}, ctx)


def test_tool_name_must_match():
    rules = select_rules(ALL_RULES, ids=["GVP-2026-0001"])
    assert not evaluate_tool_call(rules, "read_file", {"valuesFile": "/etc/passwd"})


# --- stdio guard (end to end, local toy server) -------------------------------------

def _rpc(i, method, params=None):
    return json.dumps({"jsonrpc": "2.0", "id": i, "method": method, "params": params or {}})


def _run_guard(lines, monitor=False):
    rules = select_rules(ALL_RULES, ids=["GVP-2026-0002"])
    guard = stdio_guard.Guard(rules, Context(), monitor=monitor, log=io.StringIO())
    stdin = io.BytesIO(("\n".join(lines) + "\n").encode())
    stdout = io.BytesIO()
    rc = stdio_guard.run([sys.executable, str(FIXTURES / "echo_server.py")], guard, stdin, stdout)
    assert rc == 0
    replies = [json.loads(l) for l in stdout.getvalue().decode().splitlines() if l.strip()]
    return {r["id"]: r for r in replies}


def test_stdio_guard_blocks_exploit_and_passes_normal_calls():
    evil = {"name": "conform", "arguments": {"action": "relink_scalefix",
                                             "args": {"footageDirs": ["/media/A", "-delete"]}}}
    good = {"name": "conform", "arguments": {"action": "relink_scalefix",
                                             "args": {"footageDir": "/media/A"}}}
    out = _run_guard([_rpc(1, "initialize"), _rpc(2, "tools/call", evil), _rpc(3, "tools/call", good)])
    assert out[1]["result"] == {"ok": "initialize"}
    blocked = out[2]["result"]
    assert blocked["isError"] is True
    assert "GVP-2026-0002" in blocked["content"][0]["text"]
    assert "RAN" not in blocked["content"][0]["text"]          # never reached the server
    assert out[3]["result"]["content"][0]["text"].startswith("RAN")


def test_stdio_guard_monitor_mode_forwards():
    evil = {"name": "conform", "arguments": {"footageDir": "-exec"}}
    out = _run_guard([_rpc(7, "tools/call", evil)], monitor=True)
    assert out[7]["result"]["content"][0]["text"].startswith("RAN")


def test_stdio_guard_batch():
    rules = select_rules(ALL_RULES, ids=["GVP-2026-0002"])
    g = stdio_guard.Guard(rules, Context(), log=io.StringIO())
    batch = [json.loads(_rpc(1, "tools/call", {"name": "conform", "arguments": {"footageDir": "-x"}})),
             json.loads(_rpc(2, "tools/list"))]
    fwd, replies = g.screen(batch)
    assert [m["id"] for m in fwd] == [2]
    assert [r["id"] for r in replies] == [1]


# --- http guard (end to end, local toy upstream) -------------------------------------

class _Upstream(BaseHTTPRequestHandler):
    """Imitates the vulnerable shape: wildcard CORS, no Host/Origin check."""
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n)
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Type", "text/event-stream")
        self.end_headers()  # no length: streamed until close
        self.wfile.write(b"data: " + body + b"\n\n")
        self.wfile.flush()
        self.close_connection = True


def _serve(srv):
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv


@pytest.fixture
def guarded():
    up = _serve(ThreadingHTTPServer(("127.0.0.1", 0), _Upstream))
    rules = select_rules(ALL_RULES, ids=["GVP-2026-0003"])
    g = _serve(http_guard.make_server(("127.0.0.1", 0), f"http://127.0.0.1:{up.server_port}",
                                      rules, Context(), log=io.StringIO()))
    yield g.server_port
    g.shutdown()
    up.shutdown()


def _post(port, headers):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    c.request("POST", "/mcp", body=b'{"jsonrpc":"2.0","id":1,"method":"tools/list"}',
              headers={"Content-Type": "application/json", **headers})
    r = c.getresponse()
    return r, r.read()


def test_http_guard_blocks_cross_site_and_rebinding(guarded):
    r, body = _post(guarded, {"Origin": "https://evil.example"})
    assert r.status == 403 and b"GVP-2026-0003" in body
    c = http.client.HTTPConnection("127.0.0.1", guarded, timeout=5)
    c.putrequest("POST", "/mcp", skip_host=True)
    c.putheader("Host", "rebind.attacker.example:8765")
    c.putheader("Content-Length", "0")
    c.endheaders()
    assert c.getresponse().status == 403


def test_http_guard_passes_local_client_and_strips_wildcard_cors(guarded):
    r, body = _post(guarded, {"Origin": "http://localhost:6274"})
    assert r.status == 200
    assert r.getheader("Access-Control-Allow-Origin") is None
    assert b"tools/list" in body


def test_http_guard_refuses_public_bind():
    with pytest.raises(ValueError):
        http_guard.make_server(("0.0.0.0", 0), "http://127.0.0.1:1", [], Context())


# --- CLI -------------------------------------------------------------------------------

def test_cli_test_and_check(tmp_path, capsys):
    assert main(["test"]) == 0
    p = tmp_path / "call.json"
    p.write_text(json.dumps({"tool": "install_helm_chart",
                             "arguments": {"valuesFile": "/proc/self/environ"}}))
    assert main(["check", str(p), "--root", str(tmp_path)]) == 1
    assert json.loads(capsys.readouterr().out.split("pass\n", 1)[1])["blocked"] is True


def test_cli_export_is_json(capsys):
    assert main(["export", "--with-classes"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["format"] == "mcp-vpatch/1" and len(data["rules"]) == len(ALL_RULES)


# --- path rules (1MCP cli-token) ------------------------------------------------------

class _TokenUpstream(BaseHTTPRequestHandler):
    """Imitates the vulnerable shape: hands a token to anyone on loopback."""
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def do_POST(self):
        body = (b'{"token":"tk-test"}' if self.path.startswith("/api/auth/cli-token")
                else b'{"ok":true}')
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def test_http_guard_blocks_token_route_but_passes_mcp():
    up = _serve(ThreadingHTTPServer(("127.0.0.1", 0), _TokenUpstream))
    rules = select_rules(ALL_RULES, package="@1mcp/agent")
    assert [r.id for r in rules] == ["GVP-2026-0004"]
    g = _serve(http_guard.make_server(("127.0.0.1", 0), f"http://127.0.0.1:{up.server_port}",
                                      rules, Context(), log=io.StringIO()))
    try:
        for path in ("/api/auth/cli-token", "/API/auth/cli-token/", "/api/auth/%63li-token"):
            c = http.client.HTTPConnection("127.0.0.1", g.server_port, timeout=5)
            c.request("POST", path, body=b"", headers={"Host": "mcp.example.test",
                                                       "X-Forwarded-For": "203.0.113.7"})
            r = c.getresponse()
            assert r.status == 403 and b"tk-" not in r.read(), path
        c = http.client.HTTPConnection("127.0.0.1", g.server_port, timeout=5)
        c.request("POST", "/mcp", body=b"{}", headers={"Host": "mcp.example.test"})
        r = c.getresponse()
        assert r.status == 200 and r.read() == b'{"ok":true}'
    finally:
        g.shutdown()
        up.shutdown()


def test_cli_check_path(tmp_path, capsys):
    p = tmp_path / "req.json"
    p.write_text(json.dumps({"path": "/api/auth/cli-token", "headers": {"Host": "x"}}))
    assert main(["check", str(p), "--package", "@1mcp/agent"]) == 1
