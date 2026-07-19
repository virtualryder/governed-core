#!/usr/bin/env bash
# deploy_identity.sh — generic STABLE identity stack (own lifecycle; not torn down by the spine).
# Idempotent: reuse pool/client/users by name, create if missing. Writes <state_file>.
# Driven by env (from agent.env) + a users.tsv (name<TAB>password<TAB>yes|no in-group).
#   args: $1 = state file path   $2 = users.tsv path
# env required: REGION, POOL_NAME, CLIENT_NAME, REVIEWER_GROUP
set -uo pipefail
export AWS_PAGER=""
: "${REGION:?}" "${POOL_NAME:?}" "${CLIENT_NAME:?}" "${REVIEWER_GROUP:?}"
STATE="${1:?state file}"; USERS="${2:?users.tsv}"
log(){ echo "[identity] $*"; }

POOL_ID="$(aws cognito-idp list-user-pools --max-results 60 --region "$REGION" --query "UserPools[?Name=='$POOL_NAME'].Id | [0]" --output text)"
if [ "$POOL_ID" = "None" ] || [ -z "$POOL_ID" ]; then
  POOL_ID="$(aws cognito-idp create-user-pool --pool-name "$POOL_NAME" --region "$REGION" --query UserPool.Id --output text)"; log "created stable cognito pool $POOL_ID"
else
  log "reusing stable cognito pool $POOL_ID"
fi
CLIENT_ID="$(aws cognito-idp list-user-pool-clients --user-pool-id "$POOL_ID" --region "$REGION" --query "UserPoolClients[?ClientName=='$CLIENT_NAME'].ClientId | [0]" --output text)"
if [ "$CLIENT_ID" = "None" ] || [ -z "$CLIENT_ID" ]; then
  CLIENT_ID="$(aws cognito-idp create-user-pool-client --user-pool-id "$POOL_ID" --client-name "$CLIENT_NAME" --explicit-auth-flows ALLOW_USER_PASSWORD_AUTH ALLOW_REFRESH_TOKEN_AUTH --region "$REGION" --query UserPoolClient.ClientId --output text)"; log "created app client"
fi
aws cognito-idp create-group --user-pool-id "$POOL_ID" --group-name "$REVIEWER_GROUP" --region "$REGION" >/dev/null 2>&1 || true
while IFS=$'\t' read -r un pw grp; do
  [ -z "$un" ] && continue
  aws cognito-idp admin-create-user --user-pool-id "$POOL_ID" --username "$un" --message-action SUPPRESS --region "$REGION" >/dev/null 2>&1 || true
  aws cognito-idp admin-set-user-password --user-pool-id "$POOL_ID" --username "$un" --password "$pw" --permanent --region "$REGION" >/dev/null 2>&1 || true
  [ "$grp" = "yes" ] && aws cognito-idp admin-add-user-to-group --user-pool-id "$POOL_ID" --username "$un" --group-name "$REVIEWER_GROUP" --region "$REGION" >/dev/null 2>&1 || true
done < "$USERS"
DISCOVERY="https://cognito-idp.$REGION.amazonaws.com/$POOL_ID/.well-known/openid-configuration"
cat > "$STATE" <<EOF
REGION=$REGION
POOL_ID=$POOL_ID
CLIENT_ID=$CLIENT_ID
DISCOVERY=$DISCOVERY
EOF
log "identity ready. pool=$POOL_ID client=$CLIENT_ID -> $STATE"
