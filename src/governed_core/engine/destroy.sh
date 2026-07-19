#!/usr/bin/env bash
# destroy.sh — generic manifest-driven teardown (best-effort, idempotent). Zero residual.
# Usage: bash lib/engine/destroy.sh <agent_dir>
# Leaves the STABLE Cognito identity intact (its own lifecycle).
set -uo pipefail
export AWS_PAGER=""
export MSYS_NO_PATHCONV=1   # so delete-parameter actually hits the /'-leading SSM name
AGENT_DIR="${1:?usage: destroy.sh <agent_dir>}"
SELF="$(cd "$(dirname "$0")" && pwd)"
AGENT="$(cd "$AGENT_DIR" && pwd)"; BUILD="$AGENT/.build"
mkdir -p "$BUILD"; ( unset MSYS_NO_PATHCONV; python "$SELF/render.py" "$AGENT/manifest.yaml" "$BUILD" ) >/dev/null
source "$BUILD/agent.env"
REGION="${REGION:-${AWS_REGION:-us-east-1}}"
ACC="$(aws sts get-caller-identity --query Account --output text 2>/dev/null)"
echo "[destroy] region $REGION agent $SLUG"

GW_ID="$(aws bedrock-agentcore-control list-gateways --region "$REGION" --query "items[?name=='$GATEWAY_NAME'].gatewayId | [0]" --output text 2>/dev/null)"
if [ -n "$GW_ID" ] && [ "$GW_ID" != "None" ]; then
  for t in $(aws bedrock-agentcore-control list-gateway-targets --gateway-identifier "$GW_ID" --region "$REGION" --query "items[].targetId" --output text 2>/dev/null); do
    aws bedrock-agentcore-control delete-gateway-target --gateway-identifier "$GW_ID" --target-id "$t" --region "$REGION" >/dev/null 2>&1 && echo "  deleted target $t"
  done
  sleep 5
  aws bedrock-agentcore-control delete-gateway --gateway-identifier "$GW_ID" --region "$REGION" >/dev/null 2>&1 && echo "  deleted gateway $GW_ID"; sleep 5
fi
ENGINE_ID="$(aws bedrock-agentcore-control list-policy-engines --region "$REGION" --query "policyEngines[?name=='$ENGINE_NAME'].policyEngineId | [0]" --output text 2>/dev/null)"
if [ -n "$ENGINE_ID" ] && [ "$ENGINE_ID" != "None" ]; then
  for p in $(aws bedrock-agentcore-control list-policies --policy-engine-id "$ENGINE_ID" --region "$REGION" --query "policies[].policyId" --output text 2>/dev/null); do
    aws bedrock-agentcore-control delete-policy --policy-engine-id "$ENGINE_ID" --policy-id "$p" --region "$REGION" >/dev/null 2>&1 && echo "  deleted policy $p"
  done
  sleep 3
  aws bedrock-agentcore-control delete-policy-engine --policy-engine-id "$ENGINE_ID" --region "$REGION" >/dev/null 2>&1 && echo "  deleted policy engine $ENGINE_ID"
fi
SM_ARN="$(aws stepfunctions list-state-machines --region "$REGION" --query "stateMachines[?name=='$SM_NAME'].stateMachineArn | [0]" --output text 2>/dev/null)"
if [ -n "$SM_ARN" ] && [ "$SM_ARN" != "None" ]; then
  for ex in $(aws stepfunctions list-executions --state-machine-arn "$SM_ARN" --status-filter RUNNING --region "$REGION" --query "executions[].executionArn" --output text 2>/dev/null); do
    aws stepfunctions stop-execution --execution-arn "$ex" --region "$REGION" >/dev/null 2>&1 || true
  done
  aws stepfunctions delete-state-machine --state-machine-arn "$SM_ARN" --region "$REGION" >/dev/null 2>&1 && echo "  deleted state machine $SM_NAME"
fi
# Every <prefix>-* Lambda, enumerated dynamically (no hardcoded list to drift).
for f in $(aws lambda list-functions --region "$REGION" --query "Functions[?starts_with(FunctionName, '$PREFIX-')].FunctionName" --output text 2>/dev/null | tr -d '\r'); do
  aws lambda delete-function --function-name "$f" --region "$REGION" >/dev/null 2>&1 && echo "  deleted lambda $f"
done
aws dynamodb delete-table --table-name "$PENDING_TABLE" --region "$REGION" >/dev/null 2>&1 && echo "  deleted pending-approvals table"
aws dynamodb delete-table --table-name "$AUDIT_TABLE" --region "$REGION" >/dev/null 2>&1 && echo "  deleted audit ledger $AUDIT_TABLE"
if [ -n "$GUARDRAIL_NAME" ]; then
  GRID="$(aws bedrock list-guardrails --region "$REGION" --query "guardrails[?name=='$GUARDRAIL_NAME'].id | [0]" --output text 2>/dev/null)"
  [ -n "$GRID" ] && [ "$GRID" != "None" ] && aws bedrock delete-guardrail --guardrail-identifier "$GRID" --region "$REGION" >/dev/null 2>&1 && echo "  deleted guardrail $GRID"
fi
BUCKET="${WORM_BUCKET_BASE}-$ACC-$REGION"
if aws s3api head-bucket --bucket "$BUCKET" --region "$REGION" >/dev/null 2>&1; then
  aws s3api list-object-versions --bucket "$BUCKET" --region "$REGION" --query "[Versions[].[Key,VersionId],DeleteMarkers[].[Key,VersionId]][]" --output text 2>/dev/null | tr -d '\r' | \
  while read -r k v; do
    [ -n "$k" ] && [ "$k" != "None" ] && aws s3api delete-object --bucket "$BUCKET" --key "$k" --version-id "$v" --bypass-governance-retention --region "$REGION" >/dev/null 2>&1
  done
  aws s3api delete-bucket --bucket "$BUCKET" --region "$REGION" >/dev/null 2>&1 && echo "  deleted WORM bucket $BUCKET"
fi
aws ssm delete-parameter --name "$SSM_PARAM" --region "$REGION" >/dev/null 2>&1 && echo "  deleted SSM $SSM_PARAM"
# roles
for r in "${PREFIX}-agentcore-gw:${PREFIX}-gw-perms" "${PREFIX}-tool-exec:${PREFIX}-tool-perms" "${PREFIX}-signoff-exec:${PREFIX}-signoff-perms" "${PREFIX}-signoff-sfn:${PREFIX}-signoff-sfn-perms"; do
  role="${r%%:*}"; pol="${r##*:}"
  aws iam delete-role-policy --role-name "$role" --policy-name "$pol" >/dev/null 2>&1 || true
  aws iam detach-role-policy --role-name "$role" --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole >/dev/null 2>&1 || true
  aws iam delete-role --role-name "$role" >/dev/null 2>&1 && echo "  deleted role $role"
done
echo "[destroy] complete"
