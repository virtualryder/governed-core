import json
import os
import boto3
from botocore.exceptions import ClientError
import evidence
import identity

# approve_signoff — the human approver's OUT-OF-BAND action (a console/app, NOT an agent tool). Enforces
# separation of duties (approver must differ from requester) and single-use approval, then releases the
# Step Functions task token. Both the APPROVED decision and a blocked/denied attempt are recorded through
# the CANONICAL evidence service, so approvals and rejections are in the hash-chained ledger too.
#
# P0-5: the approver's identity is derived from a cryptographically-VALIDATED Cognito access token
# (identity.verify_access_token: RS256/JWKS + issuer + client + exp + reviewer-group), never from an
# `approver` string in the event body. A spoofed `{"approver":"dr_x"}` with no valid token is rejected and
# recorded as DENIED; a token that verifies but belongs to the requester is rejected (SoD).

PENDING_TABLE = os.environ.get("PENDING_TABLE", "governed-pending-approvals")


def _deny(context, src, case_id, actor, reason):
    evidence.record_event({
        "case_id": case_id or "_unknown", "action": "approve", "phase": "DENIED",
        "actor": actor or "unverified", "deidentified": True, "payload": {"reason": reason},
    }, context, source=src)
    return {"approved": False, "case_id": case_id, "reason": reason}


def handler(event, context):
    e = evidence._coerce(event)
    region = os.environ.get("AWS_REGION", "us-east-1")
    src = os.environ.get("SOURCE", "approve")
    case_id = e.get("case_id") or e.get("icsr_id")
    if not case_id:
        return {"approved": False, "reason": "case_id (or icsr_id) is required"}

    # P0-5: identity from the verified token ONLY. No token / bad token / wrong client / not in the
    # reviewer group -> rejected and recorded. The body 'approver' is not trusted for the decision.
    claims, err = identity.verify_access_token(e.get("access_token"), require_group=True)
    if err:
        return _deny(context, src, case_id, e.get("approver"),
                     "approver identity not verified: %s (P0-5: a signed access token is required, not an 'approver' field)" % err)
    approver = identity.identity_of(claims)
    if not approver:
        return _deny(context, src, case_id, None, "verified token carries no usable identity")

    tbl = boto3.resource("dynamodb", region_name=region).Table(PENDING_TABLE)
    sfn = boto3.client("stepfunctions", region_name=region)

    item = tbl.get_item(Key={"case_id": case_id}).get("Item")
    if not item:
        return _deny(context, src, case_id, approver, "no pending approval for this case (never requested)")
    requester = item.get("requester")
    token = item.get("task_token")

    if approver == requester:
        return _deny(context, src, case_id, approver,
                     "separation-of-duties: approver must differ from requester (%s)" % requester)

    try:
        tbl.update_item(
            Key={"case_id": case_id},
            UpdateExpression="SET #s = :c, approver = :a",
            ConditionExpression="#s = :p",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={":c": "CONSUMED", ":p": "PENDING", ":a": approver},
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            return {"approved": False, "case_id": case_id, "reason": "approval already consumed (single-use)"}
        raise

    sfn.send_task_success(taskToken=token, output=json.dumps({"approved": True, "approver": approver}))
    evidence.record_event({
        "case_id": case_id, "action": "approve", "phase": "APPROVED", "actor": approver,
        "deidentified": True, "payload": {"requester": requester, "approver": approver,
                                          "approver_identity": "cognito-access-token (RS256/JWKS verified)"},
    }, context, source=src)
    return {"approved": True, "approver": approver, "requester": requester, "case_id": case_id,
            "approver_identity": "verified"}
