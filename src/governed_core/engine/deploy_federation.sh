#!/usr/bin/env bash
# deploy_federation.sh — REFERENCE. Federate an EXTERNAL IdP (Okta / Entra / any OIDC or SAML) into the
# agent's existing Cognito pool, so real employees sign in with their corporate identity and land on the
# SAME Cedar deny-by-default policy as the built-in test users — WITHOUT changing a single policy.
#
# How: the IdP's group/role claim is mapped to a Cognito user attribute; a Pre-Token-Generation (V2_0)
# Lambda (lib/controls/idp_group_mapper.py) maps those external groups to the agent's Cedar role and
# overrides `cognito:groups`; the existing `<role>_permit` then authorizes federated users unchanged.
#
#   OIDC:  IDP_TYPE=oidc IDP_NAME=Okta OIDC_ISSUER=https://<org>.okta.com OIDC_CLIENT_ID=... \
#          OIDC_CLIENT_SECRET=... [OIDC_SCOPES="openid email profile groups"] [GROUPS_CLAIM=groups] \
#          GROUP_MAP='{"FinancialAidOfficers":"aid_officer"}' bash lib/engine/deploy_federation.sh agents/financial-aid
#   SAML:  IDP_TYPE=saml IDP_NAME=Entra SAML_METADATA_URL=https://login.microsoftonline.com/<tenant>/federationmetadata/... \
#          [GROUPS_CLAIM=http://schemas.microsoft.com/ws/2008/06/identity/claims/groups] \
#          GROUP_MAP='{"<entra-group-id>":"aid_officer"}' bash lib/engine/deploy_federation.sh agents/financial-aid
#   Teardown: DESTROY=1 IDP_NAME=Okta bash lib/engine/deploy_federation.sh agents/financial-aid
#
# This is a REFERENCE the adopter validates in their own account against their own IdP. It is OPTIONAL and
# independent of the base spine/runtime deploy. Idempotent + best-effort.
set -uo pipefail
export AWS_PAGER=""
SELF="$(cd "$(dirname "$0")" && pwd)"; LIB="$(cd "$SELF/.." && pwd)"
AGENT="$(cd "${1:?usage: deploy_federation.sh <agent_dir>}" && pwd)"; BUILD="$AGENT/.build"
mkdir -p "$BUILD"; ( unset MSYS_NO_PATHCONV; python "$SELF/render.py" "$AGENT/manifest.yaml" "$BUILD" >/dev/null )
source "$BUILD/agent.env"                       # PREFIX, REVIEWER_GROUP, REGION, ...
# pool id: prefer the spine state, fall back to identity state
for s in "$AGENT/spine-state.env" "$AGENT/identity-state.env"; do [ -f "$s" ] && source "$s"; done
: "${REGION:?}" "${POOL_ID:?need a deployed pool (run deploy.sh first)}" "${REVIEWER_GROUP:?}"
ACC="$(aws sts get-caller-identity --query Account --output text | tr -d '\r')"
IDP_NAME="${IDP_NAME:?set IDP_NAME (e.g. Okta / Entra)}"
log(){ echo "[federation] $*"; }

if [ "${DESTROY:-}" = "1" ]; then
  log "tearing down federation for IdP $IDP_NAME on pool $POOL_ID"
  aws cognito-idp delete-identity-provider --user-pool-id "$POOL_ID" --provider-name "$IDP_NAME" --region "$REGION" 2>/dev/null || true
  aws cognito-idp update-user-pool --user-pool-id "$POOL_ID" --lambda-config '{}' --region "$REGION" >/dev/null 2>&1 || true
  aws lambda delete-function --function-name "${PREFIX}-idp-mapper" --region "$REGION" 2>/dev/null || true
  for p in $(aws iam list-role-policies --role-name "${PREFIX}-idp-mapper-exec" --query 'PolicyNames[]' --output text 2>/dev/null); do
    aws iam delete-role-policy --role-name "${PREFIX}-idp-mapper-exec" --policy-name "$p" 2>/dev/null || true; done
  aws iam detach-role-policy --role-name "${PREFIX}-idp-mapper-exec" --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole 2>/dev/null || true
  aws iam delete-role --role-name "${PREFIX}-idp-mapper-exec" 2>/dev/null || true
  log "federation removed (the custom:idp_roles attribute stays — Cognito attributes can't be deleted)."
  exit 0
fi

IDP_TYPE="${IDP_TYPE:?set IDP_TYPE=oidc|saml}"
GROUPS_CLAIM="${GROUPS_CLAIM:-groups}"
GROUP_MAP="${GROUP_MAP:-{\"$REVIEWER_GROUP\":\"$REVIEWER_GROUP\"}}"

# 1) a custom attribute to carry the IdP's group claim (idempotent — already-exists is fine).
aws cognito-idp add-custom-attributes --user-pool-id "$POOL_ID" --region "$REGION" \
  --custom-attributes "Name=idp_roles,AttributeDataType=String,Mutable=true" >/dev/null 2>&1 || true
log "custom attribute custom:idp_roles ensured"

# 2) the external IdP + attribute mapping (email + the group claim -> custom:idp_roles).
MAP="email=email,custom:idp_roles=$GROUPS_CLAIM"
if [ "$IDP_TYPE" = "oidc" ]; then
  : "${OIDC_ISSUER:?}" "${OIDC_CLIENT_ID:?}" "${OIDC_CLIENT_SECRET:?}"
  DETAILS="client_id=$OIDC_CLIENT_ID,client_secret=$OIDC_CLIENT_SECRET,attributes_request_method=GET,oidc_issuer=$OIDC_ISSUER,authorize_scopes=${OIDC_SCOPES:-openid email profile groups}"
  aws cognito-idp create-identity-provider --user-pool-id "$POOL_ID" --provider-name "$IDP_NAME" \
    --provider-type OIDC --provider-details "$DETAILS" --attribute-mapping "$MAP" --region "$REGION" >/dev/null 2>&1 \
   || aws cognito-idp update-identity-provider --user-pool-id "$POOL_ID" --provider-name "$IDP_NAME" \
        --provider-details "$DETAILS" --attribute-mapping "$MAP" --region "$REGION" >/dev/null
else
  : "${SAML_METADATA_URL:?}"
  aws cognito-idp create-identity-provider --user-pool-id "$POOL_ID" --provider-name "$IDP_NAME" \
    --provider-type SAML --provider-details "MetadataURL=$SAML_METADATA_URL" --attribute-mapping "$MAP" --region "$REGION" >/dev/null 2>&1 \
   || aws cognito-idp update-identity-provider --user-pool-id "$POOL_ID" --provider-name "$IDP_NAME" \
        --provider-details "MetadataURL=$SAML_METADATA_URL" --attribute-mapping "$MAP" --region "$REGION" >/dev/null
fi
log "identity provider $IDP_NAME ($IDP_TYPE) mapped: $GROUPS_CLAIM -> custom:idp_roles"

# 3) the Pre-Token-Generation Lambda that maps IdP groups -> cognito:groups (Cedar unchanged).
ROLE="${PREFIX}-idp-mapper-exec"
ROLE_ARN="$(aws iam get-role --role-name "$ROLE" --query Role.Arn --output text 2>/dev/null | tr -d '\r')"
if [ -z "$ROLE_ARN" ] || [ "$ROLE_ARN" = "None" ]; then
  ROLE_ARN="$(aws iam create-role --role-name "$ROLE" --assume-role-policy-document \
    '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}' \
    --query Role.Arn --output text | tr -d '\r')"
  aws iam attach-role-policy --role-name "$ROLE" --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole >/dev/null
  sleep 8
fi
WORK="$(mktemp -d)"; cp "$LIB/controls/idp_group_mapper.py" "$WORK/lambda_function.py"
( cd "$WORK" && python -c "import zipfile; z=zipfile.ZipFile('f.zip','w'); z.write('lambda_function.py'); z.close()" )
FN="${PREFIX}-idp-mapper"
ENVJSON="Variables={GROUP_MAP=$GROUP_MAP,SOURCE_ATTR=custom:idp_roles,ROLE_GROUP=$REVIEWER_GROUP,STRICT=1}"
if aws lambda get-function --function-name "$FN" --region "$REGION" >/dev/null 2>&1; then
  aws lambda update-function-code --function-name "$FN" --zip-file "fileb://$WORK/f.zip" --region "$REGION" >/dev/null
  aws lambda update-function-configuration --function-name "$FN" --environment "$ENVJSON" --region "$REGION" >/dev/null
else
  for i in 1 2 3 4 5; do aws lambda create-function --function-name "$FN" --runtime python3.12 --role "$ROLE_ARN" \
    --handler lambda_function.handler --zip-file "fileb://$WORK/f.zip" --timeout 5 --environment "$ENVJSON" \
    --region "$REGION" >/dev/null 2>&1 && break; sleep 5; done
fi
FN_ARN="$(aws lambda get-function --function-name "$FN" --region "$REGION" --query Configuration.FunctionArn --output text | tr -d '\r')"
aws lambda add-permission --function-name "$FN" --statement-id cognito-invoke --action lambda:InvokeFunction \
  --principal cognito-idp.amazonaws.com --source-arn "arn:aws:cognito-idp:$REGION:$ACC:userpool/$POOL_ID" --region "$REGION" >/dev/null 2>&1 || true
log "pre-token-generation mapper deployed: $FN_ARN"

# 4) attach the trigger (V2_0 is required for group override in the ACCESS token).
aws cognito-idp update-user-pool --user-pool-id "$POOL_ID" --region "$REGION" \
  --lambda-config "PreTokenGenerationConfig={LambdaArn=$FN_ARN,LambdaVersion=V2_0}" >/dev/null
log "trigger attached to pool $POOL_ID (PreTokenGeneration V2_0)"

# 5) hosted-UI app client + domain so users can actually do the federated login (SPA/redirect flow).
DOMAIN="${DOMAIN_PREFIX:-${PREFIX}-auth-$ACC}"
aws cognito-idp create-user-pool-domain --user-pool-id "$POOL_ID" --domain "$DOMAIN" --region "$REGION" >/dev/null 2>&1 || true
if [ -n "${CLIENT_ID:-}" ]; then
  aws cognito-idp update-user-pool-client --user-pool-id "$POOL_ID" --client-id "$CLIENT_ID" --region "$REGION" \
    --supported-identity-providers "$IDP_NAME" COGNITO \
    --callback-urls "${CALLBACK_URL:-https://example.com/callback}" \
    --logout-urls "${LOGOUT_URL:-https://example.com/logout}" \
    --allowed-o-auth-flows code --allowed-o-auth-scopes openid email profile \
    --allowed-o-auth-flows-user-pool-client >/dev/null 2>&1 || log "note: app-client hosted-UI update skipped (set CALLBACK_URL/LOGOUT_URL for your app)"
fi

cat <<EOF

[federation] DONE. External IdP '$IDP_NAME' federated into pool $POOL_ID.
  Sign-in (hosted UI): https://$DOMAIN.auth.$REGION.amazoncognito.com/oauth2/authorize?identity_provider=$IDP_NAME&client_id=${CLIENT_ID:-<client-id>}&response_type=code&scope=openid+email+profile&redirect_uri=${CALLBACK_URL:-https://example.com/callback}
  Group mapping: $GROUP_MAP   (external group -> Cedar role '$REVIEWER_GROUP')
  A federated user in a mapped group now passes the SAME '${REVIEWER_GROUP}_permit' as the built-in users.
  Cedar policies were NOT changed. Deny-by-default still holds for anyone whose groups map to nothing.
EOF
