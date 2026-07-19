import json
import os
import urllib.request
import urllib.parse
import urllib.error
import boto3

# verify_source — a reusable GOVERNED connector tool that verifies a case against a REAL, OAuth2-protected
# external system of record (mock). It retires the "labeled stub" caveat: it is a real authenticated call.
# The outbound OAuth2 token is minted by **AgentCore Identity** — this tool holds NO client secret. Flow
# (client_credentials / 2-legged M2M):
#   1. get_workload_access_token(workloadName)         -> a workload identity token
#   2. get_resource_oauth2_token(..., oauth2Flow=M2M)  -> an OAuth2 access token from the Identity
#      credential provider (which holds the SoR's client_id/secret in the token vault)
#   3. call the system-of-record with Authorization: Bearer <token>
# Cedar-authorized at the Gateway like every other tool (deny-by-default). Fails soft (verified:false).

SOR_URL = os.environ.get("SOR_URL", "")
PROVIDER_NAME = os.environ.get("PROVIDER_NAME", "")
WI_NAME = os.environ.get("WI_NAME", "")
SCOPE = os.environ.get("SCOPE", "")
REGION = os.environ.get("AWS_REGION", "us-east-1")


def _coerce(e):
    e = e or {}
    if isinstance(e, str):
        try:
            e = json.loads(e)
        except Exception:
            e = {"case_id": e}
    return e


def _oauth_token():
    dp = boto3.client("bedrock-agentcore", region_name=REGION)
    wt = dp.get_workload_access_token(workloadName=WI_NAME)["workloadAccessToken"]
    r = dp.get_resource_oauth2_token(
        workloadIdentityToken=wt,
        resourceCredentialProviderName=PROVIDER_NAME,
        scopes=[SCOPE],
        oauth2Flow="M2M",
    )
    return r.get("accessToken")


def handler(event, context):
    e = _coerce(event)
    case_id = e.get("case_id") or "_default"
    if not SOR_URL:
        return {"verified": False, "error": "connector not configured (SOR_URL missing)"}

    try:
        token = _oauth_token()
    except Exception as ex:
        return {"verified": False, "error": "AgentCore Identity token fetch failed: %s" % type(ex).__name__,
                "detail": str(ex)[:200]}
    if not token:
        return {"verified": False, "error": "no OAuth token returned by the AgentCore Identity credential provider"}

    url = SOR_URL.rstrip("/") + "?" + urllib.parse.urlencode({"case_id": case_id})
    req = urllib.request.Request(url, headers={"Authorization": "Bearer " + token,
                                               "User-Agent": "governed-connector/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as ex:
        return {"verified": False, "error": "system-of-record returned HTTP %s" % ex.code,
                "sor_auth_enforced": ex.code in (401, 403)}
    except (urllib.error.URLError, TimeoutError, ValueError) as ex:
        return {"verified": False, "error": "system-of-record call failed: %s" % type(ex).__name__}

    return {
        "verified": bool(data.get("verified")),
        "tool_holds_secret": False,
        "case_id": case_id,
        "connector": {
            "system_of_record": data.get("system_of_record"),
            "outbound_auth": "AgentCore Identity OAuth2 credential provider (%s), client_credentials/M2M" % PROVIDER_NAME,
            "token_minted_by_identity": True,
            "tool_holds_secret": False,
            "authorized_via": data.get("authorized_via"),
        },
        "note": "verified against an OAuth-protected system of record; the outbound OAuth token was minted by AgentCore Identity, not stored in this tool.",
    }
