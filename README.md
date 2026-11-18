# mcp-vpatch: virtual patches for MCP servers

A **virtual patch** blocks the exploit shape of one known, public MCP
vulnerability in front of the vulnerable server, so you are protected today
while the real upgrade waits for a release window. It is a stopgap, never a
substitute for the fix: every rule names the fixed version.

Built and maintained by [Gridsline](https://gridsline.com), from the bugs we
find and report in MCP servers. MIT licensed.

```bash
pip install git+https://github.com/HexMystic/mcp-vpatch
mcp-vpatch list
mcp-vpatch test -v
```

Requires Python 3.10+ and PyYAML. No other dependencies.

## Why this shape (and not "another MCP firewall")

There are already several open-source MCP gateways and firewalls
(mcp-firewall, McpVanguard, Pipelock, mcp-gate, mcp-scan's proxy mode, and the
routing gateways). They enforce allow/deny policy and generic heuristics:
prompt-injection patterns, secret scanners, path and command regexes. None of
them ships a **catalog keyed to specific MCP advisories** where each rule
proves, with fixtures, that it blocks the advisory's exploit shape and lets
normal calls through. That is how network IPS vendors do virtual patching
(one signature per CVE), and it is the piece MCP is missing.

So the core of this pack is the **rule catalog + fixtures**. The two guards
are small reference enforcers so a team can deploy a rule in five minutes;
the engine is a library and `vpatch export` emits JSON, so the same rules can
be ported into whichever gateway a team already runs.

## Rules

| ID | Bug | Enforced by | Fixed in |
|---|---|---|---|
| GVP-2026-0001 | mcp-server-kubernetes `valuesFile` arbitrary file read (CVE-2026-85753) | `wrap` | 4.0.5 |
| GVP-2026-0002 | davinci-resolve-mcp `find` argument injection (GHSA-x29h-6rgf-w233) | `wrap` | 4.14.3 |
| GVP-2026-0003 | fastmcp httpStream callable cross-site / DNS rebinding | `http-guard` | 4.26.2 |
| GVP-2026-0004 | 1MCP agent full-scope CLI token for remote callers behind a same-host reverse proxy (GHSA-vrqm-3x52-5334) | `http-guard` between proxy and 1MCP, or a proxy one-liner | 0.39.9 |
| GVP-CLASS-ARGV-DASH | option injection (value starts with `-`) | `wrap` | (class) |
| GVP-CLASS-PATH-ROOT | path escape / symlink escape / secret paths | `wrap` | (class) |
| GVP-CLASS-SSRF | URL to internal address, any spelling | `wrap` | (class) |
| GVP-CLASS-SHELL-META | shell metacharacters in command args (alert only) | `wrap` | (class) |

Advisory rules are on by default. Class rules are opt-in (`--with-classes`)
because the argument names need tuning per server; start them with
`--mode monitor`, read the log, then switch to block.

**Policy:** advisory rules may only describe bugs that are public and fixed.
`tests/test_vpatch.py::test_every_advisory_rule_is_public_and_fixed` enforces
an explicit allowlist of packages and advisory IDs; adding one is deliberate.

## Use

```bash
mcp-vpatch list                 # what's in the pack
mcp-vpatch test -v              # run every must-block / must-allow fixture

# stdio server: replace the server command in your MCP client config
mcp-vpatch wrap --package mcp-server-kubernetes --root ~/charts -- npx -y mcp-server-kubernetes
mcp-vpatch wrap --package davinci-resolve-mcp -- node path/to/server.mjs

# HTTP server on localhost: put the guard in front, point the client at it
mcp-vpatch http-guard --package fastmcp --listen 127.0.0.1:8765 --upstream http://127.0.0.1:8080

# reverse-proxied server: Caddy/nginx -> guard -> server (keeps local-only routes local)
mcp-vpatch http-guard --package @1mcp/agent --listen 127.0.0.1:8766 --upstream http://127.0.0.1:3050

# one-off / CI / other gateways
echo '{"tool":"conform","arguments":{"args":{"footageDir":"-exec"}}}' | mcp-vpatch check -
mcp-vpatch export --with-classes > vpatch.json
```

A blocked `tools/call` is answered by the guard with a tool error the model
can read (`isError: true`, naming the rule); it never reaches the server.
Decisions are JSON lines on stderr (and `--log FILE`).

## Writing a rule

```yaml
id: GVP-2026-00NN
title: "package: what the bug is (advisory id)"
kind: tool_call            # or http
action: block              # or alert
match:
  tools: [tool_name]       # glob
  args: [argName]          # key names, matched at any depth; list values are checked per item
when:                      # any check firing = match
  - starts_with_dash: {}
affected: {package: ..., vulnerable: ..., fixed: ...}
references: [{type: GHSA, id: ..., url: ...}]
tests:
  block: [ {tool: ..., arguments: {...}} ]   # the advisory's exploit shape
  allow: [ {tool: ..., arguments: {...}} ]   # normal use that must keep working
```

Checks: `starts_with_dash`, `shell_metachar`, `regex`, `path_outside_roots`,
`path_sensitive`, `not_suffix`, `url_internal_host`, and for http rules
`host_not_loopback`, `origin_not_loopback`, `path_is` (compares a normalized
path: case, trailing slash, repeated slashes, dot segments and percent
escapes, so `/API/auth/%63li-token/` still matches).

## Limits (say these out loud to clients)

* A guard sees arguments, not the server's internals. If a value is
  transformed server-side (decoded, joined, re-read from a file) the rule can
  miss it. The real fix is still the upgrade.
* `url_internal_host` judges the URL as written. A hostname that resolves
  to an internal IP is only caught with `resolve_dns`, and even then the
  server must re-check the IP it actually connects to (rebinding, redirects).
* `http-guard` only protects clients that go through it. Close the upstream
  port to everything else (bind it to loopback and don't publish it).
* Path rules resolve symlinks that exist when the call is checked; a server
  that creates links later is out of scope.

## Verified locally

`@1mcp/agent@0.39.8` with `--enable-auth --trust-proxy loopback`, guard on :18766:

```
Direct (what a same-host proxy forwards) POST /api/auth/cli-token -> 200 {"token":"tk-..."}
Guard  POST /api/auth/cli-token     -> 403
Guard  POST /API/auth/cli-token/    -> 403
Guard  POST /api/auth/%63li-token   -> 403
Guard  POST /mcp (no token)         -> 401 from 1MCP (normal auth still applies)
```

`fastmcp@4.24.5` httpStream demo server on 127.0.0.1:18080, guard on :18765:

```
Direct, Origin: https://evil.example  -> 200, Access-Control-Allow-Origin: *
Guard,  Origin: https://evil.example  -> 403 {"rules": ["GVP-2026-0003"]}
Guard,  Host: rebind.attacker.example -> 403
Guard,  local client (no Origin)      -> initialize, initialized (202), tools/call 200 over SSE,
                                         wildcard CORS header removed
```

## Contributing

New rules are welcome for advisories that are **public and fixed**. A rule
needs `affected.fixed`, a reference to the advisory, and both fixture lists;
add the package to `PUBLIC_FIXED_PACKAGES` in `tests/test_vpatch.py` in the
same PR. Please don't send rules for unfixed or unpublished bugs: report
those to the maintainer first.

Found a bug in the guard itself? See [SECURITY.md](SECURITY.md).
