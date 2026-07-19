# _env.sh — runtime resolver for the template. Caller sets SELF (this dir) and AGENT (agent dir).
REGION="${AWS_REGION:-us-east-1}"; export AWS_REGION="$REGION" AWS_DEFAULT_REGION="$REGION" AWS_PAGER=""
export PYTHONIOENCODING=utf-8 PYTHONUTF8=1 AGENTCORE_SUPPRESS_RECOMMENDATION=1 COLUMNS=140 TERM=dumb
if [ -f "$SELF/.venv/Scripts/python.exe" ]; then PY="$SELF/.venv/Scripts/python.exe"; AC="$SELF/.venv/Scripts/agentcore.exe"; else PY="$SELF/.venv/bin/python"; AC="$SELF/.venv/bin/agentcore"; fi
# render the agent manifest -> agent.env (RUNTIME_NAME, WORKFLOW_PROMPT, RUNTIME_MODEL_ID, SSM_PARAM, ...)
BUILD="$AGENT/.build"; mkdir -p "$BUILD"
( unset MSYS_NO_PATHCONV; python "$SELF/../engine/render.py" "$AGENT/manifest.yaml" "$BUILD" >/dev/null )
source "$BUILD/agent.env"
STATE="${PV_SPINE_STATE:-$AGENT/spine-state.env}"   # written by deploy.sh at the agent dir
PV_REVIEWER_PW="${PV_REVIEWER_PW:-ChangeMe-Reviewer1!}"; PV_OUTSIDER_PW="${PV_OUTSIDER_PW:-ChangeMe-Outsider1!}"
