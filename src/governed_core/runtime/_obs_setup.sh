#!/usr/bin/env bash
# Grant the Runtime exec role ssm:GetParameter for gateway discovery. Usage: _obs_setup.sh <agent_dir>
SELF="$(cd "$(dirname "$0")" && pwd)"; export MSYS_NO_PATHCONV=1
AGENT="$(cd "${1:?usage: _obs_setup.sh <agent_dir>}" && pwd)"; cd "$SELF"; source "$SELF/_env.sh"
ACC="$(aws sts get-caller-identity --query Account --output text | tr -d '\r')"
ROLE="$(aws iam list-roles --query "Roles[?starts_with(RoleName,'AmazonBedrockAgentCoreSDKRuntime')].RoleName | [0]" --output text | tr -d '\r')"
echo "runtime exec role: $ROLE"
SSM_ROOT="$(printf '%s' "$SSM_PARAM" | sed 's#/[^/]*$##')"   # /<root>/gateway-url -> /<root>
printf '%s' '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["ssm:GetParameter"],"Resource":"arn:aws:ssm:'"$REGION"':'"$ACC"':parameter'"$SSM_ROOT"'/*"}]}' > ssm-pol.json
if [ -n "$ROLE" ] && [ "$ROLE" != "None" ]; then
  aws iam put-role-policy --role-name "$ROLE" --policy-name agent-runtime-ssm --policy-document file://ssm-pol.json --region "$REGION" && echo "  attached ssm:GetParameter to $ROLE"
fi
aws xray update-trace-segment-destination --destination CloudWatchLogs --region "$REGION" >/dev/null 2>&1 && echo "  enabled Transaction Search" || echo "  (Transaction Search skipped)"
echo "OBS_SETUP_DONE"
