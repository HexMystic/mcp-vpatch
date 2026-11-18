"""Evaluate MCP traffic against virtual-patch rules."""
from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatchcase
from typing import Iterator

from mcp_vpatch.conditions import CHECKS, Context
from mcp_vpatch.rules import Rule


@dataclass
class Decision:
    rule_id: str
    action: str          # "block" | "alert"
    reason: str
    location: str = ""   # e.g. "arguments.args.footageDirs[1]" or "header Host"

    def to_dict(self) -> dict:
        return {"rule": self.rule_id, "action": self.action,
                "reason": self.reason, "location": self.location}


def _key_matches(key: str, patterns: list[str]) -> bool:
    k = key.lower()
    return any(fnmatchcase(k, p.lower()) for p in patterns)


def iter_matching_values(obj, patterns: list[str], path: str = "arguments") -> Iterator[tuple[str, object]]:
    """Yield (location, value) for every key matching `patterns`, at any depth.

    Searching by key name at any depth keeps rules stable when a server nests
    its parameters (e.g. ``{"action": ..., "args": {"footageDir": ...}}``).
    A list value yields each element, so ``footageDirs: ["-exec", ...]`` is
    checked item by item.
    """
    if isinstance(obj, dict):
        for k, v in obj.items():
            here = f"{path}.{k}"
            if isinstance(k, str) and _key_matches(k, patterns):
                if isinstance(v, list):
                    for i, item in enumerate(v):
                        if not isinstance(item, (dict, list)):
                            yield f"{here}[{i}]", item
                elif not isinstance(v, dict):
                    yield here, v
            yield from iter_matching_values(v, patterns, here)
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            yield from iter_matching_values(item, patterns, f"{path}[{i}]")


def tool_matches(rule: Rule, tool: str) -> bool:
    return any(fnmatchcase(tool, p) for p in rule.tools)


def evaluate_tool_call(rules: list[Rule], tool: str, arguments, ctx: Context | None = None) -> list[Decision]:
    ctx = ctx or Context()
    out: list[Decision] = []
    for rule in rules:
        if rule.kind != "tool_call" or not tool_matches(rule, tool):
            continue
        for loc, value in iter_matching_values(arguments or {}, rule.args):
            for _field, cond in rule.conditions:
                reason = CHECKS[cond.check](value, cond.params, ctx)
                if reason:
                    out.append(Decision(rule.id, rule.action, reason, loc))
                    break  # one reason per value is enough
    return out


def _header(headers: dict, name: str):
    for k, v in headers.items():
        if k.lower() == name:
            return v
    return None


def evaluate_http(rules: list[Rule], headers: dict, ctx: Context | None = None) -> list[Decision]:
    ctx = ctx or Context()
    out: list[Decision] = []
    for rule in rules:
        if rule.kind != "http":
            continue
        for fld, cond in rule.conditions:
            reason = CHECKS[cond.check](_header(headers, fld), cond.params, ctx)
            if reason:
                out.append(Decision(rule.id, rule.action, reason, f"header {fld.capitalize()}"))
    return out


def blocks(decisions: list[Decision]) -> list[Decision]:
    return [d for d in decisions if d.action == "block"]


# --- fixtures ------------------------------------------------------------------

@dataclass
class FixtureResult:
    rule_id: str
    expect: str      # "block" | "allow"
    index: int
    ok: bool
    detail: str


def run_fixtures(rule: Rule) -> list[FixtureResult]:
    """Check a rule against its own must-block / must-allow examples."""
    tests = rule.tests or {}
    tctx = tests.get("context", {})
    results: list[FixtureResult] = []
    for expect in ("block", "allow"):
        for i, fx in enumerate(tests.get(expect) or []):
            ctx = Context(
                roots=fx.get("roots") or tctx.get("roots") or Context().roots,
                allow_hosts=tctx.get("allow_hosts", []),
                allow_origins=tctx.get("allow_origins", []),
            )
            if rule.kind == "tool_call":
                ds = evaluate_tool_call([rule], fx["tool"], fx.get("arguments", {}), ctx)
            else:
                ds = evaluate_http([rule], fx.get("headers", {}), ctx)
            hit = bool(ds)
            ok = hit if expect == "block" else not hit
            detail = "; ".join(f"{d.location}: {d.reason}" for d in ds) or "no match"
            results.append(FixtureResult(rule.id, expect, i, ok, detail))
    return results
