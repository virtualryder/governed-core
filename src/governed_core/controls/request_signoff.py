import json
import os
import boto3
from botocore.exceptions import ClientError, BotoCoreError
import evidence
import identity

# request_signoff — the SANCTIONED path to commit. The agent/reviewer NEVER finalizes directly (Cedar
# forbids it). This tool records an INTENT event through the CANONICAL evidence service, then starts the
# sign-off Step Functions execution, which pauses until a DIFFERENT qualified person approves.
#
# P0-5: the requester's identity is derived from a cryptographically-VALIDATED Cognito access token
# (identity.verify_access_token), never from a `requester` string in the event body — so the requester
# stored for the separation-of-duties check is a verified identity, not a caller-chosen label. The token
# is the same one that authenticated the caller to the governed Gateway; the tool re-verifies it to bind
# the verified identity into the audit and the SoD gate.

SM_NAME = os.environ.get("SM_NAME", "governed-signoff")


def handler(event, context):
    e = evidence._coerce(event)
    region = os.environ.get("AWS_REGION", "us-east-1")
    acct = context.invoked_function_arn.split(":")[4]
    case_id = e.get("case_id") or e.get("icsr_id", "")
    if not case_id:
        return {"requested": False, "error": "case_id (or icsr_id) is required"}

    claims, err = identity.verify_access_token(e.get("access_token"), require_group=True)
    if err:
        return {"requested": False,
                "error": "requester identity not verified: %s (P0-5: a signed access token is required, not a 'requester' field)" % err}
    requester = identity.identity_of(claims)
    if not requester:
        return {"requested": False, "error": "verified token carries no usable identity"}

    evidence.record_event({
        "case_id": case_id, "action": "request_signoff", "phase": "INTENT", "actor": requester,
        "deidentified": True, "payload": {"requester": requester,
                                          "requester_identity": "cognito-access-token (RS256/JWKS verified)"},
    }, context, source=os.environ.get("SOURCE", "request_signoff"))

    sm_arn = "arn:aws:states:%s:%s:stateMachine:%s" % (region, acct, SM_NAME)
    try:
        r = boto3.client("stepfunctions", region_name=region).start_execution(
            stateMachineArn=sm_arn,
            input=json.dumps({"case_id": case_id, "icsr_id": case_id, "requester": requester}),
        )
        return {"requested": True, "phase": "PENDING_APPROVAL", "execution_arn": r["executionArn"],
                "case_id": case_id, "requester": requester,
                "note": "awaiting a DIFFERENT qualified person's approval (separation of duties)"}
    except (ClientError, BotoCoreError) as exc:
        return {"requested": False, "error": "start_execution failed: " + type(exc).__name__}
