#!/usr/bin/env bash
SELF="$(cd "$(dirname "$0")" && pwd)"; cd "$SELF"
if [ -f .venv/Scripts/python.exe ]; then PY=".venv/Scripts/python.exe"; AC=".venv/Scripts/agentcore.exe"; else PY=".venv/bin/python"; AC=".venv/bin/agentcore"; fi
echo "=== import smoke ==="
"$PY" -c "from bedrock_agentcore.runtime import BedrockAgentCoreApp; from strands import Agent; from strands.models import BedrockModel; from strands.tools.mcp import MCPClient; from mcp.client.streamable_http import streamablehttp_client; print('IMPORTS_OK')" 2>&1 | tail -10
