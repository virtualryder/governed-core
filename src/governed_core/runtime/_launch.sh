#!/usr/bin/env bash
# Build + deploy the Runtime for an agent. Usage: _launch.sh <agent_dir>
SELF="$(cd "$(dirname "$0")" && pwd)"
AGENT="$(cd "${1:?usage: _launch.sh <agent_dir>}" && pwd)"; cd "$SELF"; source "$SELF/_env.sh"
[ -f "$STATE" ] || { echo "spine-state not found ($STATE)."; exit 1; }
source "$STATE"
MODEL="${RUNTIME_MODEL_ID:-us.anthropic.claude-sonnet-4-5-20250929-v1:0}"
echo "GATEWAY_URL=$GW_URL runtime=$RUNTIME_NAME"
"$AC" launch \
  --env GATEWAY_URL="$GW_URL" \
  --env GATEWAY_SSM_PARAM="$SSM_PARAM" \
  --env MODEL_ID="$MODEL" \
  --env SYSTEM_PROMPT="$WORKFLOW_PROMPT" \
  --auto-update-on-conflict 2>&1
echo "LAUNCH_EXIT=${PIPESTATUS[0]}"
