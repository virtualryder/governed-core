#!/usr/bin/env bash
# deploy.sh — generic manifest-driven governance-spine deploy for the governed-hero-agent template.
# Usage: bash lib/engine/deploy.sh <agent_dir>          (e.g. agents/pharmacovigilance)
# Reproduces the proven PV spine, parameterized: engine -> gateway(LOG_ONLY) -> targets -> policies -> ENFORCE.
set -euo pipefail
export AWS_PAGER=""
export MSYS_NO_PATHCONV=1   # stop Git-Bash mangling '/'-leading args (SSM param name etc.)
AGENT_DIR="${1:?usage: deploy.sh <agent_dir>}"
SELF="$(cd "$(dirname "$0")" && pwd)"; LIB="$(cd "$SELF/.." && pwd)"
AGENT="$(cd "$AGENT_DIR" && pwd)"; MANIFEST="$AGENT/manifest.yaml"
BUILD="$AGENT/.build"; WORK="$SELF/.work"
rm -rf "$WORK" "$BUILD"; mkdir -p "$WORK" "$BUILD"
# render with MSYS path-conversion ON (so native python gets Windows paths); the rest of the
# script keeps MSYS_NO_PATHCONV=1 for aws '/'-leading args.
( unset MSYS_NO_PATHCONV; python "$SELF/render.py" "$MANIFEST" "$BUILD" )
source "$BUILD/agent.env"
REGION="${REGION:-${AWS_REGION:-us-east-1}}"
cd "$WORK"
ACC="$(aws sts get-caller-identity --query Account --output text)"
STATE="$AGENT/spine-state.env"
log(){ echo "[deploy] $*"; }
wait_active(){ for i in $(seq 1 40); do s="$(eval "$1" 2>/dev/null || echo '')"; [ "$s" = "$2" ] && return 0; case "$s" in *FAILED*) echo "  !! $1 -> $s"; return 1;; esac; sleep 4; done; echo "  !! timeout: $1 -> $2"; return 1; }

GW_ROLE="${PREFIX}-agentcore-gw"; TOOL_ROLE="${PREFIX}-tool-exec"
WORM_BUCKET="${WORM_BUCKET_BASE}-${ACC}-${REGION}"

# ---- P0-6 production network hardening (OPTIONAL, OFF by default; see docs/Production-Network-Hardening.md) ----
# VPC mode: attach every control/tool Lambda to the adopter's private subnets so AWS-service traffic uses
# VPC endpoints (bring your own VPC/subnets/SGs). CMK: encrypt DynamoDB + the S3 WORM bucket with a
# customer-managed KMS key (bring your own key). With neither set, the deploy is byte-for-byte unchanged.
VPC_CFG=""; VPC_ON=0
if [ "${VPC_MODE:-}" = "1" ]; then
  : "${LAMBDA_SUBNET_IDS:?VPC_MODE=1 requires LAMBDA_SUBNET_IDS (comma-separated private-subnet ids)}"
  : "${LAMBDA_SG_IDS:?VPC_MODE=1 requires LAMBDA_SG_IDS (comma-separated security-group ids)}"
  VPC_CFG="SubnetIds=${LAMBDA_SUBNET_IDS},SecurityGroupIds=${LAMBDA_SG_IDS}"; VPC_ON=1
  log "P0-6 VPC mode ON -> lambdas in subnets [$LAMBDA_SUBNET_IDS] sg [$LAMBDA_SG_IDS]"
fi
DDB_SSE=""
if [ -n "${CMK_ARN:-}" ]; then
  DDB_SSE="--sse-specification Enabled=true,SSEType=KMS,KMSMasterKeyId=${CMK_ARN}"
  log "P0-6 CMK ON -> DynamoDB + S3 WORM encrypted with $CMK_ARN"
fi

# ---- guard ----
if [ -n "$(aws bedrock-agentcore-control list-gateways --region "$REGION" --query "items[?name=='$GATEWAY_NAME'].gatewayId" --output text)" ]; then
  echo "A gateway '$GATEWAY_NAME' already exists. Run destroy.sh first."; exit 1
fi

# ---- 1. IAM (create-or-reuse) ----
printf '%s' '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"bedrock-agentcore.amazonaws.com"},"Action":"sts:AssumeRole"}]}' > gw-trust.json
# P0-4 least-privilege: the old policy granted bedrock-agentcore:* on Resource "*" (any AgentCore
# resource in the account). The gateway role actually needs to (a) read/evaluate its OWN policy engine
# and gateway config (the service calls GetPolicyEngine with this role) and (b) invoke this agent's tool
# Lambdas. Scope the AgentCore actions to THIS account/region's policy-engine and gateway resources (no
# longer "*"), and scope lambda:InvokeFunction to this agent's PREFIX-* functions.
printf '%s' '{"Version":"2012-10-17","Statement":[{"Sid":"AgentCoreSelf","Effect":"Allow","Action":"bedrock-agentcore:*","Resource":["arn:aws:bedrock-agentcore:'"$REGION"':'"$ACC"':policy-engine/*","arn:aws:bedrock-agentcore:'"$REGION"':'"$ACC"':gateway/*"]},{"Sid":"InvokeTools","Effect":"Allow","Action":"lambda:InvokeFunction","Resource":"arn:aws:lambda:'"$REGION"':'"$ACC"':function:'"$PREFIX"'-*"}]}' > gw-perms.json
printf '%s' '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}' > lam-trust.json
aws iam get-role --role-name "$GW_ROLE" >/dev/null 2>&1 || { aws iam create-role --role-name "$GW_ROLE" --assume-role-policy-document file://gw-trust.json >/dev/null; log "created role $GW_ROLE"; }
aws iam put-role-policy --role-name "$GW_ROLE" --policy-name "${PREFIX}-gw-perms" --policy-document file://gw-perms.json
GW_ROLE_ARN="arn:aws:iam::$ACC:role/$GW_ROLE"
if ! aws iam get-role --role-name "$TOOL_ROLE" >/dev/null 2>&1; then
  aws iam create-role --role-name "$TOOL_ROLE" --assume-role-policy-document file://lam-trust.json >/dev/null
  aws iam attach-role-policy --role-name "$TOOL_ROLE" --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
  log "created role $TOOL_ROLE"
fi
TOOL_ROLE_ARN="arn:aws:iam::$ACC:role/$TOOL_ROLE"
# Tool perms — P0-4 least-privilege. Every ALLOW is scoped to a specific resource ARN except the two
# Comprehend detect actions, which AWS only supports at Resource "*" (no resource-level ARNs exist for
# them). Bedrock is scoped to Claude inference profiles / foundation models + this account's guardrails
# (not "*"); DynamoDB/S3/States are scoped to THIS agent's audit table, WORM bucket, and state machine.
# The tamper Deny stays broad on purpose (a deny should not be narrow).
printf '%s' '{"Version":"2012-10-17","Statement":[{"Sid":"NLP","Effect":"Allow","Action":["comprehendmedical:DetectPHI","comprehend:DetectPiiEntities"],"Resource":"*"},{"Sid":"BedrockInvoke","Effect":"Allow","Action":["bedrock:InvokeModel","bedrock:InvokeModelWithResponseStream"],"Resource":["arn:aws:bedrock:*:'"$ACC"':inference-profile/*","arn:aws:bedrock:*::foundation-model/anthropic.claude-*"]},{"Sid":"BedrockGuardrail","Effect":"Allow","Action":["bedrock:ApplyGuardrail"],"Resource":"arn:aws:bedrock:'"$REGION"':'"$ACC"':guardrail/*"},{"Sid":"AuditLedgerAppend","Effect":"Allow","Action":["dynamodb:PutItem","dynamodb:GetItem"],"Resource":"arn:aws:dynamodb:'"$REGION"':'"$ACC"':table/'"$AUDIT_TABLE"'"},{"Sid":"AuditWormPut","Effect":"Allow","Action":["s3:PutObject"],"Resource":"arn:aws:s3:::'"$WORM_BUCKET"'/*"},{"Sid":"SignoffStart","Effect":"Allow","Action":["states:StartExecution"],"Resource":"arn:aws:states:'"$REGION"':'"$ACC"':stateMachine:'"$SM_NAME"'"},{"Sid":"AuditTamperDeny","Effect":"Deny","Action":["dynamodb:DeleteItem","dynamodb:UpdateItem","s3:DeleteObject","s3:DeleteObjectVersion","s3:BypassGovernanceRetention","s3:PutObjectRetention","s3:PutObjectLegalHold"],"Resource":"*"}]}' > tool-perms.json
aws iam put-role-policy --role-name "$TOOL_ROLE" --policy-name "${PREFIX}-tool-perms" --policy-document file://tool-perms.json
# P0-6: VPC-attached Lambdas need the managed ENI permissions (least-privilege: this is exactly that set).
[ "$VPC_ON" = "1" ] && aws iam attach-role-policy --role-name "$TOOL_ROLE" --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole >/dev/null 2>&1
sleep 10

# ---- 2. Identity (stable, separate lifecycle) ----
REGION="$REGION" POOL_NAME="$POOL_NAME" CLIENT_NAME="$CLIENT_NAME" REVIEWER_GROUP="$REVIEWER_GROUP" \
  bash "$SELF/deploy_identity.sh" "$AGENT/identity-state.env" "$BUILD/users.tsv"
source "$AGENT/identity-state.env"     # POOL_ID, CLIENT_ID, DISCOVERY
log "using stable pool=$POOL_ID client=$CLIENT_ID"

# ---- 2b. WORM audit stores ----
if [ "$CTRL_WORM" = "1" ]; then
  if ! aws dynamodb describe-table --table-name "$AUDIT_TABLE" --region "$REGION" >/dev/null 2>&1; then
    aws dynamodb create-table --table-name "$AUDIT_TABLE" --attribute-definitions AttributeName=audit_id,AttributeType=S --key-schema AttributeName=audit_id,KeyType=HASH --billing-mode PAY_PER_REQUEST $DDB_SSE --region "$REGION" >/dev/null
    aws dynamodb wait table-exists --table-name "$AUDIT_TABLE" --region "$REGION"
    log "created audit ledger $AUDIT_TABLE${CMK_ARN:+ (CMK SSE)}"
  fi
  if ! aws s3api head-bucket --bucket "$WORM_BUCKET" --region "$REGION" >/dev/null 2>&1; then
    aws s3api create-bucket --bucket "$WORM_BUCKET" --region "$REGION" --object-lock-enabled-for-bucket >/dev/null
    aws s3api put-object-lock-configuration --bucket "$WORM_BUCKET" --region "$REGION" --object-lock-configuration '{"ObjectLockEnabled":"Enabled","Rule":{"DefaultRetention":{"Mode":"'"$OBJECT_LOCK_MODE"'","Days":'"$RETENTION_DAYS"'}}}' >/dev/null
    aws s3api put-public-access-block --bucket "$WORM_BUCKET" --region "$REGION" --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true >/dev/null 2>&1 || true
    # P0-6: customer-managed-key default encryption on the WORM bucket (Object Lock is unchanged; CMK adds
    # revocable confidentiality on top of the WORM integrity/retention control).
    [ -n "${CMK_ARN:-}" ] && aws s3api put-bucket-encryption --bucket "$WORM_BUCKET" --region "$REGION" \
      --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms","KMSMasterKeyID":"'"$CMK_ARN"'"},"BucketKeyEnabled":true}]}' >/dev/null 2>&1 || true
    log "created WORM bucket $WORM_BUCKET ($OBJECT_LOCK_MODE ${RETENTION_DAYS}d)${CMK_ARN:+ + CMK}"
  fi
fi

# ---- 2c. Bedrock Guardrail ----
GUARDRAIL_ID=""
if [ -n "$GUARDRAIL_NAME" ]; then
  GUARDRAIL_ID="$(aws bedrock list-guardrails --region "$REGION" --query "guardrails[?name=='$GUARDRAIL_NAME'].id | [0]" --output text 2>/dev/null)"
  cp "$BUILD/guardrail-pii.json" "$BUILD/guardrail-content.json" .   # into cwd ($WORK) so native aws resolves relative file://
  if [ "$GUARDRAIL_ID" = "None" ] || [ -z "$GUARDRAIL_ID" ]; then
    GUARDRAIL_ID="$(aws bedrock create-guardrail --name "$GUARDRAIL_NAME" --description "$GUARDRAIL_DESC" --blocked-input-messaging "Blocked by the $GUARDRAIL_NAME guardrail." --blocked-outputs-messaging "[Output withheld by the $GUARDRAIL_NAME guardrail.]" --sensitive-information-policy-config file://guardrail-pii.json --content-policy-config file://guardrail-content.json --region "$REGION" --query guardrailId --output text)"
    log "created guardrail $GUARDRAIL_NAME ($GUARDRAIL_ID)"
  fi
  for i in $(seq 1 20); do gs="$(aws bedrock get-guardrail --guardrail-identifier "$GUARDRAIL_ID" --region "$REGION" --query status --output text 2>/dev/null)"; [ "$gs" = "READY" ] && break; sleep 3; done
  log "guardrail $GUARDRAIL_ID $gs"
fi

# ---- 3. Lambdas (loop the manifest tools; source dir by kind) ----
deploy_fn(){ # $1 fn  $2 src.py  [$3 role]
  local role="${3:-$TOOL_ROLE_ARN}"
  cp "$2" lambda_function.py
  _shared="$(dirname "$2")/evidence.py"; if [ -f "$_shared" ]; then cp "$_shared" evidence.py; else rm -f evidence.py; fi
  _prov="$LIB/controls/provenance.py"; if [ -f "$_prov" ]; then cp "$_prov" provenance.py; else rm -f provenance.py; fi
  _idn="$LIB/controls/identity.py"; if [ -f "$_idn" ]; then cp "$_idn" identity.py; else rm -f identity.py; fi
  python -c "import zipfile,os; z=zipfile.ZipFile('$1.zip','w',zipfile.ZIP_DEFLATED); z.write('lambda_function.py'); (os.path.exists('evidence.py') and z.write('evidence.py')); (os.path.exists('provenance.py') and z.write('provenance.py')); (os.path.exists('identity.py') and z.write('identity.py')); z.close()"
  if aws lambda get-function --function-name "$1" --region "$REGION" >/dev/null 2>&1; then
    aws lambda update-function-code --function-name "$1" --zip-file "fileb://$1.zip" --region "$REGION" >/dev/null
    [ "$VPC_ON" = "1" ] && aws lambda update-function-configuration --function-name "$1" --vpc-config "$VPC_CFG" --region "$REGION" >/dev/null
  elif [ "$VPC_ON" = "1" ]; then
    aws lambda create-function --function-name "$1" --runtime python3.12 --role "$role" --handler lambda_function.handler --zip-file "fileb://$1.zip" --timeout 60 --vpc-config "$VPC_CFG" --region "$REGION" >/dev/null
  else
    aws lambda create-function --function-name "$1" --runtime python3.12 --role "$role" --handler lambda_function.handler --zip-file "fileb://$1.zip" --timeout 60 --region "$REGION" >/dev/null
  fi; log "lambda $1 ready"
}
while IFS=$'\t' read -r target lambda handler kind guarded; do
  [ -z "$target" ] && continue
  if [ "$kind" = "control" ]; then srcdir="$LIB/controls"; else srcdir="$AGENT/tools"; fi
  deploy_fn "$lambda" "$srcdir/$handler"
done < "$BUILD/tools.tsv"
# wire guardrail + model env into the guardrailed tool lambda
if [ -n "$GUARDRAIL_LAMBDA" ] && [ -n "$GUARDRAIL_ID" ]; then
  for i in 1 2 3 4 5 6; do
    aws lambda update-function-configuration --function-name "$GUARDRAIL_LAMBDA" --environment "Variables={GUARDRAIL_ID=$GUARDRAIL_ID,GUARDRAIL_VERSION=DRAFT,DRAFT_MODEL_ID=$DRAFT_MODEL_ID}" --region "$REGION" >/dev/null 2>&1 && break
    sleep 5
  done
  log "wired guardrail into $GUARDRAIL_LAMBDA"
fi

# ---- 3b. Human sign-off gate ----
if [ "$CTRL_SIGNOFF" = "1" ]; then
  if ! aws dynamodb describe-table --table-name "$PENDING_TABLE" --region "$REGION" >/dev/null 2>&1; then
    aws dynamodb create-table --table-name "$PENDING_TABLE" --attribute-definitions AttributeName=case_id,AttributeType=S --key-schema AttributeName=case_id,KeyType=HASH --billing-mode PAY_PER_REQUEST $DDB_SSE --region "$REGION" >/dev/null
    aws dynamodb wait table-exists --table-name "$PENDING_TABLE" --region "$REGION"; log "created pending-approvals table${CMK_ARN:+ (CMK SSE)}"
  fi
  SIGNOFF_ROLE="${PREFIX}-signoff-exec"; SFN_ROLE="${PREFIX}-signoff-sfn"
  if ! aws iam get-role --role-name "$SIGNOFF_ROLE" >/dev/null 2>&1; then
    aws iam create-role --role-name "$SIGNOFF_ROLE" --assume-role-policy-document file://lam-trust.json >/dev/null
    aws iam attach-role-policy --role-name "$SIGNOFF_ROLE" --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
    [ "$VPC_ON" = "1" ] && aws iam attach-role-policy --role-name "$SIGNOFF_ROLE" --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole >/dev/null 2>&1
    log "created role $SIGNOFF_ROLE"
  fi
  SIGNOFF_ROLE_ARN="arn:aws:iam::$ACC:role/$SIGNOFF_ROLE"
  printf '%s' '{"Version":"2012-10-17","Statement":[{"Sid":"Pending","Effect":"Allow","Action":["dynamodb:GetItem","dynamodb:PutItem","dynamodb:UpdateItem"],"Resource":"arn:aws:dynamodb:'"$REGION"':'"$ACC"':table/'"$PENDING_TABLE"'"},{"Sid":"AuditPut","Effect":"Allow","Action":["dynamodb:PutItem","dynamodb:GetItem"],"Resource":"arn:aws:dynamodb:'"$REGION"':'"$ACC"':table/'"$AUDIT_TABLE"'"},{"Sid":"AuditWorm","Effect":"Allow","Action":["s3:PutObject"],"Resource":"arn:aws:s3:::'"$WORM_BUCKET"'/*"},{"Sid":"TaskToken","Effect":"Allow","Action":["states:SendTaskSuccess","states:SendTaskFailure"],"Resource":"*"}]}' > signoff-perms.json
  aws iam put-role-policy --role-name "$SIGNOFF_ROLE" --policy-name "${PREFIX}-signoff-perms" --policy-document file://signoff-perms.json
  printf '%s' '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"states.amazonaws.com"},"Action":"sts:AssumeRole"}]}' > sfn-trust.json
  if ! aws iam get-role --role-name "$SFN_ROLE" >/dev/null 2>&1; then
    aws iam create-role --role-name "$SFN_ROLE" --assume-role-policy-document file://sfn-trust.json >/dev/null; log "created role $SFN_ROLE"
  fi
  SFN_ROLE_ARN="arn:aws:iam::$ACC:role/$SFN_ROLE"
  printf '%s' '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["lambda:InvokeFunction"],"Resource":["arn:aws:lambda:'"$REGION"':'"$ACC"':function:'"$PREFIX"'-signoff-register","arn:aws:lambda:'"$REGION"':'"$ACC"':function:'"$PREFIX"'-finalize"]}]}' > sfn-perms.json
  aws iam put-role-policy --role-name "$SFN_ROLE" --policy-name "${PREFIX}-signoff-sfn-perms" --policy-document file://sfn-perms.json
  sleep 8
  deploy_fn "${PREFIX}-signoff-register" "$LIB/controls/signoff_register.py" "$SIGNOFF_ROLE_ARN"
  deploy_fn "${PREFIX}-approve"          "$LIB/controls/approve_signoff.py"  "$SIGNOFF_ROLE_ARN"
  deploy_fn "${PREFIX}-finalize"         "$LIB/controls/finalize_signoff.py" "$SIGNOFF_ROLE_ARN"
  if ! aws stepfunctions list-state-machines --region "$REGION" --query "stateMachines[?name=='$SM_NAME'].stateMachineArn | [0]" --output text | grep -q arn; then
    sed "s/{{PREFIX}}/$PREFIX/g" "$SELF/signoff.asl.json.tmpl" > signoff.asl.json
    aws stepfunctions create-state-machine --name "$SM_NAME" --type STANDARD --role-arn "$SFN_ROLE_ARN" --definition file://signoff.asl.json --region "$REGION" >/dev/null
    log "created state machine $SM_NAME"
  fi
fi

# ---- 3c. Wire resource-name env into the control + sign-off-gate lambdas. They read AUDIT_TABLE /
# AUDIT_BUCKET / PENDING_TABLE / SM_NAME from env (defaults are pv-*), so this makes them point at
# THIS agent's resources. The guardrailed lambda keeps its guardrail env (set above). ----
# P0-3: a per-deploy PROVENANCE_SECRET signs authoritative-source lookups (lookup_income_limit) and
# verifies them downstream (assess). Both Lambdas must share the SAME value, so it is generated once,
# persisted to SSM (reused on re-deploys), and injected into every control/tool lambda env below.
PROV_PARAM="/${PREFIX}/provenance-secret"
PROV_SECRET="$(aws ssm get-parameter --name "$PROV_PARAM" --with-decryption --region "$REGION" --query Parameter.Value --output text 2>/dev/null || true)"
if [ -z "$PROV_SECRET" ] || [ "$PROV_SECRET" = "None" ]; then
  PROV_SECRET="$(python -c 'import secrets;print(secrets.token_hex(32))')"
  aws ssm put-parameter --name "$PROV_PARAM" --type SecureString --value "$PROV_SECRET" --overwrite --region "$REGION" >/dev/null 2>&1 || true
  log "generated provenance signing secret -> SSM $PROV_PARAM"
fi
# P0-5: the sign-off gate derives requester/approver identity from a validated Cognito access token
# (identity.py). The verifier needs the trusted issuer, the expected app client, and the reviewer group —
# injected here so request_signoff/approve reject a spoofed identity and enforce SoD on verified usernames.
COGNITO_ISS="https://cognito-idp.${REGION}.amazonaws.com/${POOL_ID}"
CTRL_ENV="Variables={AUDIT_TABLE=$AUDIT_TABLE,AUDIT_BUCKET=$WORM_BUCKET,PENDING_TABLE=$PENDING_TABLE,SM_NAME=$SM_NAME,DRAFT_MODEL_ID=$DRAFT_MODEL_ID,SOURCE=${PREFIX}-evidence,TENANT_ID=$PREFIX,MODEL_ID=$DRAFT_MODEL_ID,POLICY_VERSION=v1,RULE_VERSION=v1,DEPLOYMENT_VERSION=v1,PROVENANCE_SECRET=$PROV_SECRET,COGNITO_ISS=$COGNITO_ISS,CLIENT_ID=$CLIENT_ID,REVIEWER_GROUP=$REVIEWER_GROUP}"
wire_env(){ for i in 1 2 3 4 5 6; do aws lambda update-function-configuration --function-name "$1" --environment "$CTRL_ENV" --region "$REGION" >/dev/null 2>&1 && { log "wired resource env into $1"; return; }; sleep 4; done; }
while IFS=$'\t' read -r target lambda handler kind guarded; do
  [ -z "$target" ] && continue
  [ "$guarded" = "1" ] && continue
  wire_env "$lambda"
done < "$BUILD/tools.tsv"
if [ "$CTRL_SIGNOFF" = "1" ]; then
  wire_env "${PREFIX}-signoff-register"; wire_env "${PREFIX}-approve"; wire_env "${PREFIX}-finalize"
fi

# ---- 4. Policy Engine ----
ENGINE_ID="$(aws bedrock-agentcore-control create-policy-engine --name "$ENGINE_NAME" --description "$ENGINE_DESC" --region "$REGION" --query policyEngineId --output text)"
ENGINE_ARN="arn:aws:bedrock-agentcore:$REGION:$ACC:policy-engine/$ENGINE_ID"
wait_active "aws bedrock-agentcore-control get-policy-engine --policy-engine-id $ENGINE_ID --region $REGION --query status --output text" ACTIVE
log "policy engine $ENGINE_ID ACTIVE"

# ---- 5. Gateway (LOG_ONLY) + SSM discovery ----
printf '%s' '{"customJWTAuthorizer":{"discoveryUrl":"'"$DISCOVERY"'","allowedClients":["'"$CLIENT_ID"'"]}}' > authz.json
printf '%s' '{"arn":"'"$ENGINE_ARN"'","mode":"LOG_ONLY"}' > pe-log.json
GW_ID="$(aws bedrock-agentcore-control create-gateway --name "$GATEWAY_NAME" --role-arn "$GW_ROLE_ARN" --protocol-type MCP --authorizer-type CUSTOM_JWT --authorizer-configuration file://authz.json --policy-engine-configuration file://pe-log.json --description "$GATEWAY_DESC" --region "$REGION" --query gatewayId --output text)"
wait_active "aws bedrock-agentcore-control get-gateway --gateway-identifier $GW_ID --region $REGION --query status --output text" READY
GW_ARN="$(aws bedrock-agentcore-control get-gateway --gateway-identifier $GW_ID --region $REGION --query gatewayArn --output text)"
GW_URL="$(aws bedrock-agentcore-control get-gateway --gateway-identifier $GW_ID --region $REGION --query gatewayUrl --output text)"
log "gateway $GW_ID READY"
aws ssm put-parameter --name "$SSM_PARAM" --type String --overwrite --value "$GW_URL" --region "$REGION" >/dev/null 2>&1 && log "published gateway URL to SSM $SSM_PARAM"

# ---- 6. Targets (loop; inject account into the lambda ARN) ----
printf '%s' '[{"credentialProviderType":"GATEWAY_IAM_ROLE"}]' > cred.json
LAST_T=""
while IFS=$'\t' read -r target lambda handler kind guarded; do
  [ -z "$target" ] && continue
  sed "s/__ACCOUNT__/$ACC/g" "$BUILD/targets/$target.json" > "t-$target.json"
  LAST_T="$(aws bedrock-agentcore-control create-gateway-target --gateway-identifier "$GW_ID" --name "$target" --target-configuration file://"t-$target.json" --credential-provider-configurations file://cred.json --region "$REGION" --query targetId --output text)"
done < "$BUILD/tools.tsv"
[ -n "$LAST_T" ] && wait_active "aws bedrock-agentcore-control get-gateway-target --gateway-identifier $GW_ID --target-id $LAST_T --region $REGION --query status --output text" READY
log "targets ready"

# ---- 7. Cedar policies (loop; inject the gateway ARN into forbids) ----
while IFS=$'\t' read -r pname mode stmt; do
  [ -z "$pname" ] && continue
  stmt="${stmt//__GW_ARN__/$GW_ARN}"
  python -c "import json,sys;open('pol.json','w').write(json.dumps({'cedar':{'statement':sys.argv[1]}}))" "$stmt"
  pid="$(aws bedrock-agentcore-control create-policy --policy-engine-id "$ENGINE_ID" --name "$pname" --definition file://pol.json --validation-mode "$mode" --region "$REGION" --query policyId --output text)"
  wait_active "aws bedrock-agentcore-control get-policy --policy-engine-id $ENGINE_ID --policy-id $pid --region $REGION --query status --output text" ACTIVE
  log "policy $pname ACTIVE"
done < "$BUILD/policies.tsv"

# ---- 8. Flip to ENFORCE ----
printf '%s' '{"arn":"'"$ENGINE_ARN"'","mode":"ENFORCE"}' > pe-enf.json
aws bedrock-agentcore-control update-gateway --gateway-identifier "$GW_ID" --name "$GATEWAY_NAME" --role-arn "$GW_ROLE_ARN" --protocol-type MCP --authorizer-type CUSTOM_JWT --authorizer-configuration file://authz.json --policy-engine-configuration file://pe-enf.json --region "$REGION" >/dev/null
wait_active "aws bedrock-agentcore-control get-gateway --gateway-identifier $GW_ID --region $REGION --query status --output text" READY
log "engine flipped to ENFORCE"

# ---- 9. state ----
cat > "$STATE" <<EOF
REGION=$REGION
ACCOUNT=$ACC
POOL_ID=$POOL_ID
CLIENT_ID=$CLIENT_ID
DISCOVERY=$DISCOVERY
ENGINE_ID=$ENGINE_ID
GW_ID=$GW_ID
GW_ARN=$GW_ARN
GW_URL=$GW_URL
EOF
log "DONE. State -> $STATE"
echo "Gateway URL: $GW_URL   (mode ENFORCE)"
