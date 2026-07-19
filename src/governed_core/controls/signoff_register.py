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
    case_id = e.get("case_id") or e.get("icsr_id")
    requester = e.get("requester")
    token = e.get("taskToken")
    boto3.resource("dynamodb", region_name=region).Table(PENDING_TABLE).put_item(
        Item={"case_id": case_id, "requester": requester, "task_token": token,
              "status": "PENDING", "created": int(time.time())}
    )
    return {"registered": True, "case_id": case_id}
