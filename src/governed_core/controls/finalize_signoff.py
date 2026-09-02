import os
import hashlib
import boto3
import evidence

# finalize_signoff — the PRIVILEGED commit task, invoked by the sign-off state machine ONLY after a
# valid separation-of-duties approval. The agent can never reach it (Cedar forbids the direct finalize
# tool and this Lambda is not on the Gateway). It records the COMMITTED decision through the CANONICAL
# evidence service (hash-chained + WORM), fail-loud — no raw put_item, no swallowed errors.
#
# 1.5.0 — APPROVAL-PATH VERIFICATION (G2). 1.4.0 trusted the `approver` string delivered with the
# task token. That is sound only while approve_signoff (Cognito-token-verified, SoD-enforced,
# single-use) is the ONLY way to release the token — but an operator with
# stepfunctions:SendTaskSuccess can release the token directly with any approver string, and this
# was demonstrated LIVE on a benefits deployment (a raw CLI send-task-success committed a case,
# including requester==approver). Finalize is the last line of defense, so it now verifies the
# APPROVAL PATH, not just the approval:
#   1. separation of duties: approver must differ from requester — always, no override;
#   2. the pending-approvals row must show the single-use approval was CONSUMED by approve_signoff
#      AND recorded the SAME approver. A row still PENDING at finalize time means the token was
#      released around the identity-verifying path -> REFUSE (fail-closed), recorded as DENIED in
#      the hash-chained ledger.
# Sandbox escape: SIGNOFF_ALLOW_UNVERIFIED=true commits anyway but stamps the COMMITTED evidence
# with approval_path=UNVERIFIED-OVERRIDE, so the ledger can never claim a verified approval that
# did not happen. Deployments must either invoke approvals through approve_signoff or set the
# escape explicitly; the default is strict.

PENDING_TABLE = os.environ.get("PENDING_TABLE", "governed-pending-approvals")


def _refuse(context, case_id, requester, approver, reason):
    evidence.record_event({
        "case_id": case_id or "_unknown", "action": "finalize", "phase": "DENIED",
        "actor": approver or "unverified", "deidentified": True,
        "payload": {"reason": reason, "requester": requester, "approver": approver},
    }, context, source=os.environ.get("SOURCE", "finalize"))
    return {"committed": False, "refused": True, "case_id": case_id, "requester": requester,
            "approver": approver, "reason": reason}


def _pending_table(region):
    # core 1.6.0: the pending-approvals register is per tenant in the hybrid model (fail-closed in MT).
    return boto3.resource("dynamodb", region_name=region).Table(
        evidence.route_table(PENDING_TABLE, "pending-approvals"))


def _approval_path(case_id, approver, region):
    """Return (verified: bool, detail: str) for how this approval reached finalize."""
    try:
        tbl = _pending_table(region)
        row = tbl.get_item(Key={"case_id": str(case_id)}).get("Item") or {}
    except Exception as exc:  # table unreadable -> cannot verify -> not verified (fail-closed)
        return False, "pending-approvals row unreadable: %s" % type(exc).__name__
    status = row.get("status")
    recorded = row.get("approver")
    if not row:
        return False, "no pending-approvals row for this case"
    if status != "CONSUMED":
        return False, "approval row status is %r (token released around approve_signoff?)" % status
    if recorded != approver:
        return False, "approver %r does not match the identity-verified approver %r" % (approver, recorded)
    return True, "verified (approve_signoff: Cognito-token-verified, SoD-checked, single-use CONSUMED)"


def _exactly_once_marker(case_id, submission_id, approver, region):
    """EXACTLY-ONCE finalization (GA-5) — preserved verbatim from governed-core 1.4.0."""
    from botocore.exceptions import ClientError
    table = os.environ.get("AUDIT_TABLE", "governed-audit-ledger")
    table = evidence.route_table(table, "audit-ledger")   # core 1.6.0: per-tenant ledger (fail-closed in MT)
    cli = boto3.resource("dynamodb", region_name=region).Table(table)
    try:
        cli.put_item(Item={"audit_id": "FINAL#" + str(case_id), "submission_id": submission_id,
                           "approver": approver, "kind": "finalize-marker"},
                     ConditionExpression="attribute_not_exists(audit_id)")
        return True, submission_id
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            prior = cli.get_item(Key={"audit_id": "FINAL#" + str(case_id)}).get("Item") or {}
            return False, prior.get("submission_id", submission_id)
        raise


def handler(event, context):
    evidence.bind_tenant(event)   # core 1.6.0: signed tenant pair from the workflow input
    case_id = event.get("case_id") or event.get("icsr_id")
    requester = event.get("requester")
    approver = event.get("approver")
    commit_action = event.get("commit_action") or os.environ.get("COMMIT_ACTION", "finalize")
    region = os.environ.get("AWS_REGION", "us-east-1")

    # ---- G2: approval-path verification (last line of defense) ----------------------------------
    if not approver:
        return _refuse(context, case_id, requester, approver, "no approver identity on the approval")
    if approver == requester:
        return _refuse(context, case_id, requester, approver,
                       "separation-of-duties: approver must differ from requester")
    verified, path_detail = _approval_path(case_id, approver, region)
    if not verified:
        if os.environ.get("SIGNOFF_ALLOW_UNVERIFIED", "").lower() == "true":
            path_detail = "UNVERIFIED-OVERRIDE (SIGNOFF_ALLOW_UNVERIFIED=true): " + path_detail
        else:
            return _refuse(context, case_id, requester, approver,
                           "approval path not verified: " + path_detail)

    # ---- core behavior (governed-core 1.4.0), with approval_path added to the evidence ----------
    submission_id = "SUB-" + hashlib.sha256(
        ("%s|%s" % (case_id, approver)).encode("utf-8")).hexdigest()[:12].upper()
    first, submission_id = _exactly_once_marker(case_id, submission_id, approver, region)
    if not first:
        return {"committed": True, "idempotent": True, "submission_id": submission_id,
                "case_id": case_id, "requester": requester, "approver": approver,
                "note": "case already finalized; returning the original submission (exactly-once)"}

    res = evidence.record_event({
        "case_id": case_id, "action": commit_action, "phase": "COMMITTED", "actor": approver,
        "deidentified": True,
        "payload": {"requester": requester, "approver": approver, "submission_id": submission_id,
                    "approval_path": path_detail},
    }, context, source=os.environ.get("SOURCE", "finalize"))

    committed = bool(res.get("stored")) or "already recorded" in (res.get("reason") or "")
    out = {"committed": committed, "submission_id": submission_id, "case_id": case_id,
           "requester": requester, "approver": approver, "approval_path": path_detail,
           "evidence": {k: res.get(k) for k in ("audit_id", "chain_hash", "seq", "worm", "stored", "reason", "error")}}
    if not committed:
        out["error"] = res.get("error", "the COMMITTED evidence record could not be written")
    return out
