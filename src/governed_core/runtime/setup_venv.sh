#!/usr/bin/env bash
set -e
SELF="$(cd "$(dirname "$0")" && pwd)"; cd "$SELF"
if command -v py >/dev/null 2>&1; then PYCMD="py -3.12"; else PYCMD="python3.12"; fi
$PYCMD -m venv .venv
if [ -f .venv/Scripts/python.exe ]; then PY=".venv/Scripts/python.exe"; AC=".venv/Scripts/agentcore.exe"; else PY=".venv/bin/python"; AC=".venv/bin/agentcore"; fi
"$PY" -m pip install --upgrade pip >/dev/null
"$PY" -m pip install "bedrock-agentcore" "bedrock-agentcore-starter-toolkit" "strands-agents" "strands-agents-tools"
echo "=== versions ==="; "$PY" -m pip show bedrock-agentcore bedrock-agentcore-starter-toolkit strands-agents 2>/dev/null | grep -E '^(Name|Version):'
"$AC" --help >/dev/null 2>&1 && echo "agentcore CLI OK" || echo "agentcore CLI NOT found"
echo "SETUP_DONE"
