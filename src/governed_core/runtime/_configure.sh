#!/usr/bin/env bash
# Configure the AgentCore Runtime for an agent. Usage: _configure.sh <agent_dir>
SELF="$(cd "$(dirname "$0")" && pwd)"
AGENT="$(cd "${1:?usage: _configure.sh <agent_dir>}" && pwd)"; cd "$SELF"; source "$SELF/_env.sh"
[ -f "$STATE" ] || { echo "spine-state not found ($STATE). Deploy the spine first (lib/engine/deploy.sh)."; exit 1; }
source "$STATE"   # DISCOVERY, CLIENT_ID, GW_URL
ACJSON="{\"customJWTAuthorizer\":{\"discoveryUrl\":\"$DISCOVERY\",\"allowedClients\":[\"$CLIENT_ID\"]}}"
echo "runtime=$RUNTIME_NAME"
"$AC" configure -c -e agent.py -n "$RUNTIME_NAME" -rf requirements.txt -ecr auto --disable-memory -ac "$ACJSON" -rha Authorization 2>&1 | tail -40
echo "CONFIGURE_EXIT=${PIPESTATUS[0]}"
