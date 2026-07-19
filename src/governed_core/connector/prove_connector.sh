#!/usr/bin/env bash
# prove_connector.sh — REUSABLE. Prove the governed OAuth connector end to end for any agent.
# Usage: bash lib/connector/prove_connector.sh <agent_dir>
set -uo pipefail
export AWS_PAGER=""
AGENT_DIR="${1:?usage: prove_connector.sh <agent_dir>}"
SELF="$(cd "$(dirname "$0")" && pwd)"; LIB="$(cd "$SELF/.." && pwd)"
AGENT="$(cd "$AGENT_DIR" && pwd)"; BUILD="$AGENT/.build"
mkdir -p "$BUILD"; python "$LIB/engine/render.py" "$AGENT/manifest.yaml" "$BUILD" >/dev/null 2>&1 || true
source "$BUILD/agent.env"; source "$AGENT/spine-state.env"; source "$AGENT/connector-state.env"
CLIENT="$LIB/controls/mcp_client.py"
tok(){ aws cognito-idp initiate-auth --auth-flow USER_PASSWORD_AUTH --client-id "$CLIENT_ID" \
        --auth-parameters "USERNAME=$1,PASSWORD=$2" --region "$REGION" --query 'AuthenticationResult.AccessToken' --output text | tr -d '\r'; }
REV_U="$(awk -F'\t' '$3=="yes"{print $1; exit}' "$BUILD/users.tsv")"; REV_P="$(awk -F'\t' '$3=="yes"{print $2; exit}' "$BUILD/users.tsv")"
OUT_U="$(awk -F'\t' '$3=="no"{print $1; exit}' "$BUILD/users.tsv")"; OUT_P="$(awk -F'\t' '$3=="no"{print $2; exit}' "$BUILD/users.tsv")"
REV="$(tok "$REV_U" "$REV_P")"; OUT="$(tok "$OUT_U" "$OUT_P")"
call(){ python "$CLIENT" "$GW_URL" "$1" "$2" "$3"; }
pass=0; fail=0

echo "=== CONNECTOR PROOF ($SLUG): governed verify_source via AgentCore Identity outbound OAuth ($SOR_LABEL) ==="

echo "-- 1. the system of record REALLY requires OAuth (no token / bad token are rejected) --"
NO_TOK="$(curl -s -o /dev/null -w '%{http_code}' "$SOR_URL?case_id=CASE-1")"
BAD_TOK="$(curl -s -o /dev/null -w '%{http_code}' -H 'Authorization: Bearer not-a-real-token' "$SOR_URL?case_id=CASE-1")"
if [ "$NO_TOK" = "401" ] && { [ "$BAD_TOK" = "401" ] || [ "$BAD_TOK" = "403" ]; }; then
  echo "  PASS | SoR rejects no-token ($NO_TOK) and bad-token ($BAD_TOK) — genuinely OAuth-protected"; pass=$((pass+1))
else echo "  FAIL | SoR did not reject unauthenticated calls (no=$NO_TOK bad=$BAD_TOK)"; fail=$((fail+1)); fi

echo "-- 2. governed tool: reviewer calls verify_source; AgentCore Identity mints the outbound token --"
VI="$(call "$REV" "$TOOL_ID" '{"case_id":"CASE-1"}')"
if echo "$VI" | grep -q '"verified": *true' && echo "$VI" | grep -qi 'AgentCore Identity'; then
  echo "  PASS | verify_source returned an authoritative record via the OAuth-protected SoR (token minted by Identity)"; pass=$((pass+1))
else echo "  FAIL | verify_source -> $VI"; fail=$((fail+1)); fi
if echo "$VI" | grep -q '"tool_holds_secret": *false'; then echo "  PASS | the tool holds NO client secret (it lives in the Identity token vault)"; pass=$((pass+1)); else echo "  FAIL | secret-handling claim missing -> $VI"; fail=$((fail+1)); fi

echo "-- 3. deny-by-default extends to the new connector (outsider denied) --"
OD="$(call "$OUT" "$TOOL_ID" '{"case_id":"CASE-1"}')"
if echo "$OD" | grep -qiE 'denied|not allowed|policy enforcement'; then echo "  PASS | outsider call to verify_source DENIED (Cedar deny-by-default)"; pass=$((pass+1)); else echo "  FAIL | outsider not denied -> $OD"; fail=$((fail+1)); fi

echo "=== CONNECTOR PROOF: $pass passed, $fail failed ==="
[ "$fail" -eq 0 ] && echo "CONNECTOR PROOF: PASS" || { echo "CONNECTOR PROOF: FAIL"; exit 1; }
