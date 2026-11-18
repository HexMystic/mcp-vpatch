"""Wrap a stdio MCP server and screen its tools/call requests.

Usage (in the MCP client's config, replace the server command):

    mcp-vpatch wrap --package mcp-server-kubernetes --root ~/charts -- \\
        npx -y mcp-server-kubernetes

MCP stdio is newline-delimited JSON-RPC. Client -> server lines are parsed;
a ``tools/call`` that a ``block`` rule matches is answered by the guard with a
tool error (``isError: true``) the model can read, and never reaches the
server. Everything else, including server -> client traffic, is passed
through byte for byte. Decisions are logged as JSON lines to stderr (which
MCP clients keep as the server log) and optionally to a file.
"""
from __future__ import annotations

import json
import subprocess
import sys
import threading
import time
from typing import IO

from mcp_vpatch.conditions import Context
from mcp_vpatch.engine import Decision, blocks, evaluate_tool_call
from mcp_vpatch.rules import Rule


class Guard:
    def __init__(self, rules: list[Rule], ctx: Context, monitor: bool = False,
                 log: IO[str] | None = None):
        self.rules = rules
        self.ctx = ctx
        self.monitor = monitor
        self.logs = [sys.stderr] + ([log] if log else [])

    def _log(self, event: dict) -> None:
        line = json.dumps({"ts": round(time.time(), 3), "guard": "mcp-vpatch", **event})
        for f in self.logs:
            try:
                f.write(line + "\n")
                f.flush()
            except (OSError, ValueError):
                pass

    def screen(self, msg) -> tuple[object | None, object | None]:
        """Return (message to forward to server or None, reply to client or None)."""
        if isinstance(msg, list):  # JSON-RPC batch (older protocol revisions)
            fwd, replies = [], []
            for m in msg:
                f, r = self.screen(m)
                if f is not None:
                    fwd.append(f)
                if r is not None:
                    replies.append(r)
            return (fwd or None), (replies or None)
        if not isinstance(msg, dict) or msg.get("method") != "tools/call":
            return msg, None
        params = msg.get("params") or {}
        tool = params.get("name", "")
        decisions = evaluate_tool_call(self.rules, tool, params.get("arguments") or {}, self.ctx)
        if not decisions:
            return msg, None
        hard = blocks(decisions)
        enforce = bool(hard) and not self.monitor
        self._log({"event": "blocked" if enforce else "matched", "tool": tool,
                   "id": msg.get("id"), "decisions": [d.to_dict() for d in decisions]})
        if not enforce:
            return msg, None
        if "id" not in msg:  # a notification gets no reply
            return None, None
        return None, _blocked_result(msg["id"], tool, hard)


def _blocked_result(req_id, tool: str, decisions: list[Decision]) -> dict:
    lines = [f"Blocked by virtual patch {d.rule_id}: {d.reason} ({d.location})" for d in decisions]
    lines.append("The call was not sent to the server. Do not retry with a variation "
                 "of this value; ask the user to confirm the intended input.")
    return {"jsonrpc": "2.0", "id": req_id,
            "result": {"content": [{"type": "text", "text": "\n".join(lines)}], "isError": True}}


def run(command: list[str], guard: Guard, stdin: IO[bytes] | None = None,
        stdout: IO[bytes] | None = None) -> int:
    stdin = stdin or sys.stdin.buffer
    stdout = stdout or sys.stdout.buffer
    proc = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    out_lock = threading.Lock()

    def to_client(data: bytes) -> None:
        with out_lock:
            stdout.write(data)
            stdout.flush()

    def pump_server() -> None:
        assert proc.stdout is not None
        for line in iter(proc.stdout.readline, b""):
            to_client(line)

    t = threading.Thread(target=pump_server, daemon=True)
    t.start()
    assert proc.stdin is not None
    try:
        for raw in iter(stdin.readline, b""):
            try:
                msg = json.loads(raw)
            except ValueError:
                proc.stdin.write(raw)  # not ours to judge; let the server reject it
                proc.stdin.flush()
                continue
            fwd, reply = guard.screen(msg)
            if reply is not None:
                to_client((json.dumps(reply) + "\n").encode())
            if fwd is msg:
                proc.stdin.write(raw)
            elif fwd is not None:
                proc.stdin.write((json.dumps(fwd) + "\n").encode())
            proc.stdin.flush()
    except BrokenPipeError:
        pass
    finally:
        try:
            proc.stdin.close()
        except OSError:
            pass
    rc = proc.wait()
    t.join(timeout=2)
    return rc
