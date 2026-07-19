#!/usr/bin/env bash
# Invoke the Runtime. Usage: _invoke.sh <agent_dir> [user] [password]
SELF="$(cd "$(dirname "$0")" && pwd)"; export MSYS_NO_PATHCONV=1
AGENT="$(cd "${1:?usage: _invoke.sh <agent_dir> [user] [password]}" && pwd)"; cd "$SELF"; source "$SELF/_env.sh"
[ -f "$STATE" ] || { echo "spine-state not found ($STATE)."; exit 1; }
source "$STATE"
USER_NAME="${2:-reviewer}"; PASS="${3:-$PV_REVIEWER_PW}"
TOKEN="$(aws cognito-idp initiate-auth --auth-flow USER_PASSWORD_AUTH --client-id "$CLIENT_ID" \
  --auth-parameters "USERNAME=$USER_NAME,PASSWORD=$PASS" --region "$REGION" \
  --query 'AuthenticationResult.AccessToken' --output text | tr -d '\r')"
echo "invoking $RUNTIME_NAME as $USER_NAME (token len ${#TOKEN})"
PAYLOAD="{\"access_token\":\"$TOKEN\",\"case_id\":\"CASE-2026-0500\",\"requester\":\"$USER_NAME\"}"
"$AC" invoke --bearer-token "$TOKEN" "$PAYLOAD" 2>&1
echo "INVOKE_EXIT=${PIPESTATUS[0]}"
