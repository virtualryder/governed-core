#!/usr/bin/env bash
# End-to-end verify. Usage: _verify_rt.sh <agent_dir>
SELF="$(cd "$(dirname "$0")" && pwd)"
AGENT="$(cd "${1:?usage: _verify_rt.sh <agent_dir>}" && pwd)"; source "$SELF/_env.sh"
echo "########## OUTSIDER (expect ACCESS DENIED, tools_available: []) ##########"
bash "$SELF/_invoke.sh" "$AGENT" outsider "$PV_OUTSIDER_PW" 2>&1 | grep -E '"result"|tools_available|INVOKE_EXIT|Response'
echo
echo "########## REVIEWER (expect full governed workflow) ##########"
bash "$SELF/_invoke.sh" "$AGENT" reviewer "$PV_REVIEWER_PW" 2>&1 | grep -E '"result"|tools_available|INVOKE_EXIT|Response'
