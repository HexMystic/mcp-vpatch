"""Minimal stdio MCP-ish server for guard tests: echoes every tools/call."""
import json
import sys

for line in sys.stdin:
    msg = json.loads(line)
    if "id" not in msg:
        continue
    if msg.get("method") == "tools/call":
        result = {"content": [{"type": "text", "text": "RAN " + json.dumps(msg["params"])}]}
    else:
        result = {"ok": msg.get("method")}
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": result}) + "\n")
    sys.stdout.flush()
