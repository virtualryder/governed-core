#!/usr/bin/env bash
# demo.sh — generic governance proof for a manifest agent. Proves the agent-agnostic invariants
# (deny-by-default for an outsider + the human sign-off gate), then sources the agent's optional
# demo_extra.sh for agent-specific payloads/content checks. Usage: bash demo.sh <agent_dir>
set -uo pipefail
export AWS_PAGER=""
AGENT_DIR="${1:?usage: demo.sh <agent_dir>}"
SELF="$(cd "$(dirname "$0")" && pwd)"; LIB="$(cd "$SELF/.." && pwd)"
AGENT="$(cd "$AGENT_DIR" && pwd)"; BUILD="$AGENT/.build"
mkdir -p "$BUILD"; python "$SELF/render.py" "$AGENT/manifest.yaml" "$BUILD" >/dev/null
source "$BUILD/agent.env"
source "$AGENT/spine-state.env"          # GW_URL, CLIENT_ID, REGION...
CLIENT="$LIB/controls/mcp_client.py"

tok(){ aws cognito-idp initiate-auth --auth-flow USER_PASSWORD_AUTH --client-id "$CLIENT_ID" \
        --auth-parameters "USERNAME=$1,PASSWORD=$2" --region "$REGION" \
        --query 'AuthenticationResult.AccessToken' --output text; }
# first in-group user = reviewer-like; the not-in-group user = outsider
REV_U="$(awk -F'\t' '$3=="yes"{print $1; exit}' "$BUILD/users.tsv")"; REV_P="$(awk -F'\t' '$3=="yes"{print $2; exit}' "$BUILD/users.tsv")"
APP_U="$(awk -F'\t' '$3=="yes"{c++} c==2{print $1; exit}' "$BUILD/users.tsv")"; APP_P="$(awk -F'\t' '$3=="yes"{c++} c==2{print $2; exit}' "$BUILD/users.tsv")"
OUT_U="$(awk -F'\t' '$3=="no"{print $1; exit}' "$BUILD/users.tsv")"; OUT_P="$(awk -F'\t' '$3=="no"{print $2; exit}' "$BUILD/users.tsv")"
REV="$(tok "$REV_U" "$REV_P")"; APP="$(tok "$APP_U" "$APP_P")"; OUT="$(tok "$OUT_U" "$OUT_P")"
call(){ python "$CLIENT" "$GW_URL" "$1" "$2" "$3"; }   # <token> <tool_id> <json>
pass=0; fail=0
check(){ local got="${3%% *}"; if [ "$got" = "$2" ]; then echo "  PASS | $1 -> $3"; pass=$((pass+1)); else echo "  FAIL | $1 (expected $2) -> $3"; fail=$((fail+1)); fi; }

# ---- agent-specific checks (deny-by-default read tool, forbids, content) ----
if [ -f "$AGENT/demo_extra.sh" ]; then
  echo "=== agent checks ($SLUG) ==="
  source "$AGENT/demo_extra.sh"
fi

# ---- generic: human sign-off gate (separation of duties; P0-5 verified identity) ----
if [ "$CTRL_SIGNOFF" = "1" ]; then
  echo "=== outsider deny-by-default + human sign-off gate (generic) ==="
  check "outsider  request_signoff"  DENY "$(call "$OUT" "request-signoff___request_signoff" '{"icsr_id":"ICSR-GEN-0001"}')"
  SO_ICSR="ICSR-GEN-$RANDOM"
  # approve is the approver's OUT-OF-BAND action: it derives the approver from a VALIDATED Cognito access
  # token (P0-5), never from an 'approver' string. soapprove passes a real token.
  soapprove(){ aws lambda invoke --function-name "${PREFIX}-approve" --cli-binary-format raw-in-base64-out \
    --payload "{\"icsr_id\":\"$SO_ICSR\",\"access_token\":\"$1\"}" --region "$REGION" /tmp/_soap.json >/dev/null 2>&1; cat /tmp/_soap.json; }
  # request_signoff also binds the requester to the verified token identity (not the event body).
  RSO="$(call "$REV" "request-signoff___request_signoff" "{\"icsr_id\":\"$SO_ICSR\",\"access_token\":\"$REV\"}")"
  check "reviewer  request_signoff"  ALLOW "$RSO"
  EXEC="$(printf '%s' "$RSO" | tr -d '\r' | grep -o 'arn:aws:states:[A-Za-z0-9:_-]*' | head -1)"
  for i in $(seq 1 15); do ST="$(aws dynamodb get-item --table-name "$PENDING_TABLE" --key "{\"case_id\":{\"S\":\"$SO_ICSR\"}}" --region "$REGION" --query "Item.status.S" --output text 2>/dev/null)"; [ "$ST" = "PENDING" ] && break; sleep 2; done
  # P0-5: a spoofed approver STRING with no validated token must be REJECTED (identity is not taken from the body).
  SPOOF="$(aws lambda invoke --function-name "${PREFIX}-approve" --cli-binary-format raw-in-base64-out --payload "{\"icsr_id\":\"$SO_ICSR\",\"approver\":\"$APP_U\"}" --region "$REGION" /tmp/_sospoof.json >/dev/null 2>&1; cat /tmp/_sospoof.json)"
  if echo "$SPOOF" | grep -qi 'not verified' && ! echo "$SPOOF" | grep -q '"approved": *true'; then echo "  PASS | P0-5: spoofed approver string (no validated token) REJECTED"; pass=$((pass+1)); else echo "  FAIL | spoofed approver accepted -> $SPOOF"; fail=$((fail+1)); fi
  SELFA="$(soapprove "$REV")"
  if echo "$SELFA" | grep -qi 'separation-of-duties'; then echo "  PASS | requester CANNOT self-approve (SoD on verified identity)"; pass=$((pass+1)); else echo "  FAIL | self-approval not blocked -> $SELFA"; fail=$((fail+1)); fi
  APPRA="$(soapprove "$APP")"
  if echo "$APPRA" | grep -q '"approved": true'; then echo "  PASS | a DIFFERENT qualified person (verified token) approves"; pass=$((pass+1)); else echo "  FAIL | valid approval failed -> $APPRA"; fail=$((fail+1)); fi
  for i in $(seq 1 20); do S="$(aws stepfunctions describe-execution --execution-arn "$EXEC" --region "$REGION" --query status --output text 2>/dev/null)"; [ "$S" != "RUNNING" ] && break; sleep 2; done
  if [ "$S" = "SUCCEEDED" ]; then echo "  PASS | submission finalized ONLY after approval"; pass=$((pass+1)); else echo "  FAIL | workflow did not finalize (status=$S)"; fail=$((fail+1)); fi
  RESO="$(soapprove "$APP")"
  if echo "$RESO" | grep -qi 'single-use\|already consumed'; then echo "  PASS | approval token is single-use"; pass=$((pass+1)); else echo "  FAIL | token reuse not blocked -> $RESO"; fail=$((fail+1)); fi
fi

# ---- generic: tamper-evident hash-chained audit ----
echo "=== tamper-evident hash-chained audit (generic) ==="
CID="CHAIN-$RANDOM-$RANDOM"
CR1="$(call "$REV" "write_audit" "{\"icsr_id\":\"$CID\",\"action\":\"chain_step_1\",\"phase\":\"INTENT\",\"actor\":\"$REV_U\",\"payload\":\"chain-step-1\"}")"
CH1="$(printf '%s' "$CR1" | grep -o '"chain_hash": *"[0-9a-f]\{64\}"' | grep -o '[0-9a-f]\{64\}' | head -1)"
CR2="$(call "$REV" "write_audit" "{\"icsr_id\":\"$CID\",\"action\":\"chain_step_2\",\"phase\":\"COMMITTED\",\"actor\":\"$REV_U\",\"payload\":\"chain-step-2\"}")"
if [ -n "$CH1" ] && printf '%s' "$CR2" | grep -q "\"prev_hash\": *\"$CH1\""; then
  echo "  PASS | audit record 2 is cryptographically chained to record 1 (prev_hash = record-1 chain_hash) -- editing an earlier record breaks every link after it"
else
  echo "  FAIL | hash chain not linked -> r1=$CR1 r2=$CR2"; fail=$((fail+1))
fi

echo "=== $pass passed, $fail failed ==="
[ "$fail" -eq 0 ] && echo "GOVERNANCE DEMO: PASS" || { echo "GOVERNANCE DEMO: FAIL"; exit 1; }
