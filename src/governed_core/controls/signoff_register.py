import os
import time
import boto3
import evidence

# signoff_register — invoked by the sign-off state machine via the waitForTaskToken integration. Persists
# the task token (bound to this case + requester) into the pending-approvals table and returns; the
# execution stays PAUSED until an out-of-band approver releases the token.

PENDING_TABLE = os.environ.get("PENDING_TABLE", "governed-pending-approvals")


def handler(event, context):
    region = os.environ.get("AWS_REGION", "us-east-1")
    e = evidence._coerce(event)
    evidence.bind_tenant(e)   # core 1.6.0: signed tenant pair carried in the execution input
    case_id = e.get("case_id") or e.get("icsr_id")
    requester = e.get("requester")
    token = e.get("taskToken")
    # Promoted into the core 2026-08-03. This control was implemented in the financial-aid and
    # housing verticals and existed in NEITHER this package nor the pharmacovigilance and benefits
    # agents — the same failure shape as the exactly-once FINAL# gap, and again with the verticals
    # AHEAD of the source they are supposed to derive from. Upstreamed so all four gain it.
    #
    # GA-5: DUPLICATE-SUBMISSION protection — a second concurrent execution for the same case must
    # not silently overwrite the first pending approval (that would strand the first execution's task
    # token). Conditional put: an existing PENDING registration makes this a duplicate -> fail loud,
    # the duplicate execution fails closed. content_hash (of the assessment the approver will see)
    # binds the approval to the exact content (approval-after-change evidence).
    from botocore.exceptions import ClientError
    item = {"case_id": case_id, "requester": requester, "task_token": token,
            "status": "PENDING", "created": int(time.time())}
    if e.get("content_hash"):
        item["content_hash"] = e["content_hash"]
    try:
        boto3.resource("dynamodb", region_name=region).Table(
            evidence.route_table(PENDING_TABLE, "pending-approvals")).put_item(
            Item=item,
            ConditionExpression="attribute_not_exists(case_id) OR #s <> :pending",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={":pending": "PENDING"},
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            raise RuntimeError(
                "duplicate submission: case %s already has a PENDING approval (fail-closed; "
                "resolve or expire the first request before re-submitting)" % case_id)
        raise
    return {"registered": True, "case_id": case_id, "content_hash": item.get("content_hash")}
