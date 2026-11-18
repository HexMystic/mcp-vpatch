"""`mcp-vpatch` command line."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from mcp_vpatch import __version__, http_guard, stdio_guard
from mcp_vpatch.conditions import Context
from mcp_vpatch.engine import evaluate_http, evaluate_tool_call, run_fixtures
from mcp_vpatch.rules import RuleError, load_rules, select_rules


def _rules_from(args) -> list:
    paths = [Path(p) for p in (args.rules_path or [])] or None
    rules = load_rules(paths)
    ids = [i for chunk in (args.rule or []) for i in chunk.split(",") if i]
    return select_rules(rules, ids=ids, package=getattr(args, "package", None),
                        with_classes=getattr(args, "with_classes", False))


def _ctx(args) -> Context:
    roots = [os.path.abspath(os.path.expanduser(r)) for r in (getattr(args, "root", None) or [])]
    return Context(roots=roots or [os.getcwd()],
                   allow_hosts=getattr(args, "allow_host", None) or [],
                   allow_origins=getattr(args, "allow_origin", None) or [])


def cmd_list(args) -> int:
    for r in _rules_from(args):
        aff = r.affected
        tag = "class" if r.is_class_rule else f"{aff.get('package', '?')} fixed {aff.get('fixed', '?')}"
        print(f"{r.id:22} {r.kind:9} {r.action:5} {r.severity:6} {tag}\n  {r.title}")
    return 0


def cmd_test(args) -> int:
    args.with_classes = True
    failed = total = 0
    for r in _rules_from(args):
        for res in run_fixtures(r):
            total += 1
            if not res.ok:
                failed += 1
                print(f"FAIL {res.rule_id} must-{res.expect} #{res.index}: {res.detail}")
            elif args.verbose:
                print(f"ok   {res.rule_id} must-{res.expect} #{res.index}: {res.detail}")
    print(f"{total - failed}/{total} fixtures pass")
    return 1 if failed else 0


def cmd_check(args) -> int:
    """Evaluate one tool call or header set given as JSON (for CI or gateways)."""
    payload = json.loads(Path(args.input).read_text() if args.input != "-" else sys.stdin.read())
    rules, ctx = _rules_from(args), _ctx(args)
    if "headers" in payload:
        ds = evaluate_http(rules, payload["headers"], ctx)
    else:
        ds = evaluate_tool_call(rules, payload["tool"], payload.get("arguments", {}), ctx)
    print(json.dumps({"decisions": [d.to_dict() for d in ds],
                      "blocked": any(d.action == "block" for d in ds)}, indent=2))
    return 1 if any(d.action == "block" for d in ds) else 0


def cmd_export(args) -> int:
    print(json.dumps({"format": "mcp-vpatch/1",
                      "rules": [r.to_dict() for r in _rules_from(args)]}, indent=2))
    return 0


def cmd_wrap(args) -> int:
    cmd = args.command
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        print("error: give the server command after --", file=sys.stderr)
        return 2
    rules = [r for r in _rules_from(args) if r.kind == "tool_call"]
    log = open(args.log, "a", encoding="utf-8") if args.log else None
    guard = stdio_guard.Guard(rules, _ctx(args), monitor=args.mode == "monitor", log=log)
    print(json.dumps({"guard": "mcp-vpatch", "event": "start", "mode": args.mode,
                      "rules": [r.id for r in rules]}), file=sys.stderr, flush=True)
    return stdio_guard.run(cmd, guard)


def cmd_http_guard(args) -> int:
    host, _, port = args.listen.rpartition(":")
    host = host.strip("[]")
    rules = [r for r in _rules_from(args) if r.kind == "http"]
    if not rules:
        print("error: no http rules selected", file=sys.stderr)
        return 2
    log = open(args.log, "a", encoding="utf-8") if args.log else None
    try:
        srv = http_guard.make_server((host, int(port)), args.upstream, rules, _ctx(args),
                                     monitor=args.mode == "monitor", log=log)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"http-guard on http://{args.listen} -> {args.upstream} rules={[r.id for r in rules]}",
          file=sys.stderr, flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


def build_parser() -> argparse.ArgumentParser:
    vp = argparse.ArgumentParser(
        prog="mcp-vpatch",
        description="Virtual patches for MCP servers: tested guard rules for known, fixed bugs.")
    vp.add_argument("--version", action="version", version=f"mcp-vpatch {__version__}")
    vsub = vp.add_subparsers(dest="vpatch_command", required=True)

    def common(p, selection=True):
        p.add_argument("--rules-path", action="append",
                       help="rule file or dir (default: built-in pack); repeatable")
        if selection:
            p.add_argument("--rule", action="append", help="rule id(s), comma-separated")
            p.add_argument("--package", help="only advisory rules for this package")
            p.add_argument("--with-classes", action="store_true",
                           help="also enable the broad bug-class rules (tune first)")

    def ctx_flags(p):
        p.add_argument("--root", action="append",
                       help="allowed root folder for path rules (default: cwd); repeatable")
        p.add_argument("--allow-host", action="append", help="extra allowed Host name")
        p.add_argument("--allow-origin", action="append", help="extra allowed Origin")

    p = vsub.add_parser("list", help="list rules")
    common(p)
    p.set_defaults(func=cmd_list, with_classes=True)

    p = vsub.add_parser("test", help="run every rule's must-block/must-allow fixtures")
    p.add_argument("--rules-path", action="append")
    p.add_argument("--rule", action="append")
    p.add_argument("-v", "--verbose", action="store_true")
    p.set_defaults(func=cmd_test)

    p = vsub.add_parser("check", help="evaluate one tool call / header set from JSON")
    p.add_argument("input", help='JSON file or - : {"tool":..,"arguments":..} or {"headers":..}')
    common(p)
    ctx_flags(p)
    p.set_defaults(func=cmd_check)

    p = vsub.add_parser("export", help="dump selected rules as JSON for other gateways")
    common(p)
    p.set_defaults(func=cmd_export)

    p = vsub.add_parser("wrap", help="run a stdio MCP server behind the guard")
    common(p)
    ctx_flags(p)
    p.add_argument("--mode", choices=["block", "monitor"], default="block")
    p.add_argument("--log", help="also append JSON decision log here")
    p.add_argument("command", nargs=argparse.REMAINDER, help="-- <server command...>")
    p.set_defaults(func=cmd_wrap)

    p = vsub.add_parser("http-guard", help="loopback reverse proxy enforcing Host/Origin rules")
    common(p)
    ctx_flags(p)
    p.add_argument("--listen", default="127.0.0.1:8765")
    p.add_argument("--upstream", required=True, help="e.g. http://127.0.0.1:8080")
    p.add_argument("--mode", choices=["block", "monitor"], default="block")
    p.add_argument("--log")
    p.set_defaults(func=cmd_http_guard)
    return vp


def main(argv: list[str] | None = None) -> int:
    return dispatch(build_parser().parse_args(argv))


def dispatch(args) -> int:
    try:
        return args.func(args)
    except RuleError as exc:
        print(f"rule error: {exc}", file=sys.stderr)
        return 2
