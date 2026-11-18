"""Load and validate virtual-patch rules (YAML)."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from mcp_vpatch.conditions import CHECKS

BUILTIN_DIR = Path(__file__).parent / "rules"

KINDS = ("tool_call", "http")
ACTIONS = ("block", "alert")
HTTP_FIELDS = ("host", "origin")


class RuleError(ValueError):
    pass


@dataclass
class Condition:
    check: str
    params: dict = field(default_factory=dict)


@dataclass
class Rule:
    id: str
    title: str
    kind: str
    action: str
    severity: str
    message: str
    # tool_call rules
    tools: list[str] = field(default_factory=list)
    args: list[str] = field(default_factory=list)
    # http rules: which header each condition reads
    conditions: list[tuple[str | None, Condition]] = field(default_factory=list)
    strip_wildcard_cors: bool = False
    # metadata
    cwe: str = ""
    references: list[dict] = field(default_factory=list)
    affected: dict = field(default_factory=dict)
    is_class_rule: bool = False
    tests: dict = field(default_factory=dict)
    source: str = ""

    def to_dict(self) -> dict:
        return {
            "id": self.id, "title": self.title, "kind": self.kind,
            "action": self.action, "severity": self.severity, "cwe": self.cwe,
            "message": self.message, "tools": self.tools, "args": self.args,
            "when": [{"field": f, "check": c.check, **({"params": c.params} if c.params else {})}
                     for f, c in self.conditions],
            "strip_wildcard_cors": self.strip_wildcard_cors,
            "references": self.references, "affected": self.affected,
            "class_rule": self.is_class_rule,
        }


def _req(d: dict, key: str, where: str):
    if key not in d:
        raise RuleError(f"{where}: missing required field '{key}'")
    return d[key]


def parse_rule(d: dict, source: str = "<memory>") -> Rule:
    where = f"{source}:{d.get('id', '?')}"
    rid = _req(d, "id", where)
    kind = _req(d, "kind", where)
    if kind not in KINDS:
        raise RuleError(f"{where}: kind must be one of {KINDS}")
    action = d.get("action", "block")
    if action not in ACTIONS:
        raise RuleError(f"{where}: action must be one of {ACTIONS}")

    conds: list[tuple[str | None, Condition]] = []
    for raw in _req(d, "when", where):
        if not isinstance(raw, dict) or len([k for k in raw if k != "field"]) != 1:
            raise RuleError(f"{where}: each 'when' entry needs exactly one check")
        fld = raw.get("field")
        name = next(k for k in raw if k != "field")
        if name not in CHECKS:
            raise RuleError(f"{where}: unknown check '{name}' (known: {sorted(CHECKS)})")
        if kind == "http" and fld not in HTTP_FIELDS:
            raise RuleError(f"{where}: http conditions need field: one of {HTTP_FIELDS}")
        conds.append((fld, Condition(name, raw[name] or {})))

    match = d.get("match", {})
    tools = list(match.get("tools", []))
    args = list(match.get("args", []))
    if kind == "tool_call" and (not tools or not args):
        raise RuleError(f"{where}: tool_call rules need match.tools and match.args")

    tests = d.get("tests") or {}
    if not d.get("class_rule") and (not tests.get("block") or not tests.get("allow")):
        raise RuleError(f"{where}: advisory rules must ship block AND allow fixtures")

    return Rule(
        id=rid, title=_req(d, "title", where), kind=kind, action=action,
        severity=d.get("severity", "medium"), message=d.get("message", ""),
        tools=tools, args=args, conditions=conds,
        strip_wildcard_cors=bool(d.get("response", {}).get("strip_wildcard_cors")),
        cwe=d.get("cwe", ""), references=d.get("references", []),
        affected=d.get("affected", {}), is_class_rule=bool(d.get("class_rule")),
        tests=tests, source=source,
    )


def load_rules(paths: list[Path] | None = None) -> list[Rule]:
    """Load every *.yaml under the given files/dirs (default: built-in pack)."""
    files: list[Path] = []
    for p in paths or [BUILTIN_DIR]:
        p = Path(p)
        files.extend(sorted(p.glob("*.yaml")) if p.is_dir() else [p])
    rules: list[Rule] = []
    seen: set[str] = set()
    for f in files:
        for doc in yaml.safe_load_all(f.read_text(encoding="utf-8")):
            if not doc:
                continue
            rule = parse_rule(doc, source=f.name)
            if rule.id in seen:
                raise RuleError(f"duplicate rule id {rule.id}")
            seen.add(rule.id)
            rules.append(rule)
    return rules


def select_rules(rules: list[Rule], ids: list[str] | None = None,
                 package: str | None = None, with_classes: bool = False) -> list[Rule]:
    """Pick the rules to enforce.

    Explicit ids win. Otherwise: advisory rules (optionally only those for one
    package), plus the broad bug-class rules only when asked for, because those
    need tuning per server.
    """
    if ids:
        wanted = set(ids)
        missing = wanted - {r.id for r in rules}
        if missing:
            raise RuleError(f"unknown rule id(s): {sorted(missing)}")
        return [r for r in rules if r.id in wanted]
    out = []
    for r in rules:
        if r.is_class_rule:
            if with_classes:
                out.append(r)
        elif package is None or r.affected.get("package") == package:
            out.append(r)
    return out
