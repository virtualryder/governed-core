"""Tiny MCP (Streamable HTTP) client for the AgentCore Gateway.
Usage:
  python mcp_client.py <gateway_url> <bearer_token> LIST
  python mcp_client.py <gateway_url> <bearer_token> <short_tool> '<json_args>'
Resolves a short tool name (e.g. draft_narrative) against the gateway's `<target>___<tool>` ids.
Prints ONE line: TOOLS ... | ALLOW <result> | DENY <message>. Stdlib only.
"""
import json, sys, urllib.request, urllib.error

URL, TOKEN, WHAT = sys.argv[1], sys.argv[2], sys.argv[3]
ARGS = json.loads(sys.argv[4]) if len(sys.argv) > 4 else {}
SESSION = {"id": None}


def rpc(method, params=None, notif=False):
    body = {"jsonrpc": "2.0", "method": method}
    if not notif:
        body["id"] = 1
    if params is not None:
        body["params"] = params
    headers = {"Authorization": "Bearer " + TOKEN, "Content-Type": "application/json",
               "Accept": "application/json, text/event-stream"}
    if SESSION["id"]:
        headers["Mcp-Session-Id"] = SESSION["id"]
    req = urllib.request.Request(URL, data=json.dumps(body).encode(), headers=headers, method="POST")
    try:
        resp = urllib.request.urlopen(req, timeout=30)
        sid = resp.headers.get("Mcp-Session-Id") or resp.headers.get("mcp-session-id")
        if sid:
            SESSION["id"] = sid
        raw = resp.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        raw = e.read().decode(errors="replace")
    parsed = None
    if "data:" in raw:
        for line in raw.splitlines():
            line = line.strip()
            if line.startswith("data:"):
                try:
                    parsed = json.loads(line[5:].strip())
                except Exception:
                    pass
    if parsed is None:
        try:
            parsed = json.loads(raw)
        except Exception:
            parsed = {"_raw": raw[:300]}
    return parsed


rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "pv-mcp-client", "version": "0.1"}})
rpc("notifications/initialized", notif=True)
tools = ((rpc("tools/list", {}) or {}).get("result") or {}).get("tools") or []
names = [t.get("name", "") for t in tools]
if WHAT == "LIST":
    print("TOOLS " + ", ".join(names))
    sys.exit(0)
match = next((n for n in names if n == WHAT or n.endswith("___" + WHAT)), WHAT)
r = rpc("tools/call", {"name": match, "arguments": ARGS})
if "error" in r:
    print("DENY " + r["error"].get("message", "")[:220])
else:
    res = r.get("result", {})
    if res.get("isError"):
        print("DENY " + json.dumps(res)[:220])
    else:
        txt = res.get("content", [{}])[0].get("text", "") if res.get("content") else json.dumps(res)
        print("ALLOW " + txt[:220])
