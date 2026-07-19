"""Generic governed intake agent — runs natively on Amazon Bedrock AgentCore Runtime.

Reusable across agents: the workflow prompt, model, and gateway discovery all come from the manifest
(passed in as env vars by the launch step). Identity: the human authenticates and their ACCESS token
is the bearer for every governed Gateway (MCP) tool call, so Cedar evaluates the real human principal.
The agent never commits the consequential action; it requests human sign-off (separation of duties).
"""
import os
import logging
import boto3
from bedrock_agentcore.runtime import BedrockAgentCoreApp
from strands import Agent
from strands.models import BedrockModel
from strands.tools.mcp import MCPClient
from mcp.client.streamable_http import streamablehttp_client

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s agent %(message)s")
log = logging.getLogger("agent")

app = BedrockAgentCoreApp()

MODEL_ID = os.environ.get("MODEL_ID", "us.anthropic.claude-sonnet-4-5-20250929-v1:0")
REGION = os.environ.get("AWS_REGION", "us-east-1")
GATEWAY_URL_ENV = os.environ.get("GATEWAY_URL", "")
GATEWAY_SSM_PARAM = os.environ.get("GATEWAY_SSM_PARAM", "")

# The governed workflow prompt is manifest-driven (passed via --env at launch). Fallback below keeps
# the agent safe/generic if it is missing.
SYSTEM = os.environ.get("SYSTEM_PROMPT") or (
    "You are an intake agent running under strict governance on Amazon Bedrock AgentCore. Your tools "
    "are exposed via a governed gateway; every call is authorized by policy against the human identity "
    "you act for. Use the available tools in a sensible order, never commit a consequential submission "
    "directly (that is owned by the human sign-off gate), and if any tool is denied by policy, STOP and "
    "report exactly which control blocked you. End with a short summary and the sign-off status."
)


def _gateway_url():
    if GATEWAY_SSM_PARAM:
        try:
            p = boto3.client("ssm", region_name=REGION).get_parameter(Name=GATEWAY_SSM_PARAM)
            log.info("gateway_url source=SSM param=%s", GATEWAY_SSM_PARAM)
            return p["Parameter"]["Value"]
        except Exception as exc:
            log.warning("SSM gateway lookup failed (%s); falling back to GATEWAY_URL env", type(exc).__name__)
    return GATEWAY_URL_ENV


@app.entrypoint
def invoke(payload, context=None):
    p = payload or {}
    token = p.get("access_token") or ""
    requester = p.get("requester", "reviewer")
    case_id = p.get("case_id") or p.get("icsr_id") or "CASE-0001"
    prompt = p.get("prompt") or (
        "Process the intake for case %s (requester %s). Run the governed workflow end to end and "
        "request human sign-off with the case id and requester." % (case_id, requester)
    )
    log.info("invocation requester=%s case_id=%s token_present=%s", requester, case_id, bool(token))
    if not token:
        return {"error": "no access_token provided; a human identity is required to drive governed tools"}

    gw = _gateway_url()
    if not gw:
        return {"error": "gateway URL not available (SSM and env both empty)"}

    model = BedrockModel(model_id=MODEL_ID, region_name=REGION, temperature=0.2)
    mcp_client = MCPClient(lambda: streamablehttp_client(gw, headers={"Authorization": "Bearer %s" % token}))
    with mcp_client:
        tools = mcp_client.list_tools_sync()
        names = [getattr(t, "tool_name", str(t)) for t in tools]
        log.info("authorized_tools requester=%s count=%d names=%s", requester, len(names), names)
        if not tools:
            log.warning("ACCESS DENIED requester=%s (no authorized tools)", requester)
            return {
                "result": "ACCESS DENIED - your identity is not authorized for any governed tool at the "
                          "gateway (Cedar deny-by-default). No workflow was run and nothing was drafted, "
                          "masked, audited, or submitted.",
                "tools_available": [], "governed": True,
            }
        agent = Agent(model=model, tools=tools, system_prompt=SYSTEM)
        result = agent(prompt)
    log.info("invocation_complete requester=%s case_id=%s result_chars=%d", requester, case_id, len(str(result)))
    return {"result": str(result), "tools_available": names}


if __name__ == "__main__":
    app.run()
