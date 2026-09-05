import json
import os
import boto3
from botocore.exceptions import ClientError
import telemetry
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


@telemetry.instrument('approve_signoff')
def handler(event, context):
    e = evidence._coerce(event)
    evidence.bind_tenant(e)   # core 1.6.0: interceptor-injected signed tenant (gateway tool)
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

    tbl = boto3.resource("dynamodb", region_name=region).Table(
        evidence.route_table(PENDING_TABLE, "pending-approvals"))
    sfn = boto3.client("stepfunctions", region_name=region)

    item = tbl.get_item(Key={"case_id": case_id}).get("Item")
    if not item:
        return _deny(context, src, case_id, approver, "no pending approval for this case (never requested)")
    requester = item.get("requester")
    token = item.get("task_token")

    if approver == requester:
        return _deny(context, src, case_id, approver,
                     "separation-of-duties: approver must differ from requester (%s)" % requester)

    # 1.10.1 UN-STRANDABLE, EVIDENCE-BEFORE-SIDE-EFFECT SAGA. The prior order CONSUMED the approval,
    # released the task token (the side effect), THEN wrote APPROVED evidence and IGNORED its result — so
    # evidence could fail after the case had already moved on, and a consume-then-send-failure stranded
    # the case permanently. New order:
    #   (1) RESERVE the approval idempotently — a retry by the SAME approver that has not yet released is
    #       allowed back in (so a transient failure downstream can be reconciled, not stranded);
    #   (2) write APPROVED evidence and REQUIRE it durable (ledger + WORM) — NO token release otherwise;
    #   (3) release the task token, idempotently (an already-released/timed-out token counts as released);
    #   (4) mark released.
    # A failure at (2) or (3) leaves the row CONSUMED/released=false, so a retry re-enters, re-writes the
    # (idempotent, WORM-repairing) evidence and releases — never stranded, never released without evidence.
    try:
        tbl.update_item(
            Key={"case_id": case_id},
            UpdateExpression="SET #s = :c, approver = :a",
            ConditionExpression="#s = :p OR (#s = :c AND approver = :a AND (attribute_not_exists(released) OR released = :f))",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={":c": "CONSUMED", ":p": "PENDING", ":a": approver, ":f": False},
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            # CONSUMED by a DIFFERENT approver, or already released -> single-use
            return {"approved": False, "case_id": case_id, "reason": "approval already consumed (single-use)"}
        raise

    # (2) durable APPROVED evidence BEFORE any side effect
    res = evidence.record_event({
        "case_id": case_id, "action": "approve", "phase": "APPROVED", "actor": approver,
        "deidentified": True, "payload": {"requester": requester, "approver": approver,
                                          "approver_identity": "cognito-access-token (RS256/JWKS verified)"},
    }, context, source=src)
    if not evidence.is_durable(res):
        return {"approved": False, "case_id": case_id, "approver": approver, "requester": requester,
                "reason": "APPROVED evidence not durable (ledger + WORM required); task token NOT released (fail-closed); retry to reconcile",
                "evidence": {k: res.get(k) for k in ("stored", "replay", "worm", "reason", "error")}}

    # (3) release the task token, idempotently
    release_note = "released"
    try:
        sfn.send_task_success(taskToken=token, output=json.dumps({"approved": True, "approver": approver}))
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code in ("TaskDoesNotExist", "TaskTimedOut"):
            release_note = "already released/timed out (idempotent)"
        else:
            return {"approved": False, "case_id": case_id, "approver": approver, "requester": requester,
                    "reason": "task-token release failed (%s); APPROVED evidence is durable; retry to reconcile" % code}

    # (4) mark released (best effort; a failure here only causes a benign idempotent re-release on retry)
    try:
        tbl.update_item(Key={"case_id": case_id}, UpdateExpression="SET released = :t",
                        ExpressionAttributeValues={":t": True})
    except ClientError:
        pass

    return {"approved": True, "approver": approver, "requester": requester, "case_id": case_id,
            "approver_identity": "verified", "release": release_note}
