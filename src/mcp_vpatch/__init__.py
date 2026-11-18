"""mcp-vpatch: virtual patches for MCP servers.

A virtual patch is a rule that blocks the exploit shape of one known, *public*
vulnerability in front of the vulnerable server, so a team is protected while
they schedule the real upgrade. Every rule ships with fixtures: inputs it must
block (the exploit shape from the advisory) and inputs it must allow (normal
use). ``mcp-vpatch test`` runs them, so a rule cannot silently drift into
blocking nothing, or blocking everything.

Two enforcement points, both small and dependency-free apart from PyYAML:

* ``stdio_guard``: wraps a stdio MCP server and screens ``tools/call``.
* ``http_guard``: a localhost reverse proxy that enforces Host/Origin checks
  and strips wildcard CORS in front of an HTTP MCP transport.

Rules are plain YAML and the engine is a library (``engine.evaluate_tool_call``,
``engine.evaluate_http``), so the same catalog can be fed to any gateway that
can call Python or read JSON (``mcp-vpatch export``).

Policy: rules may only describe vulnerabilities that are public and fixed.
"""

__version__ = "0.1.0"
