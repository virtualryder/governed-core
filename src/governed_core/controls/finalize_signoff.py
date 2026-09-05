import os
import hashlib
import boto3
import telemetry
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


def _approval_path(case_id, approver, region, expected_binding=None):
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
    # ACTION BINDING (2026-09-05): the approval was bound to a specific action (agent/tool/purpose/args)
    # at request time. This finalize must be committing THAT action — otherwise a CONSUMED approval is
    # being reused to commit something different. Recompute from what is being finalized and compare.
    bound = row.get("approval_binding")
    if bound:
        if not expected_binding:
            return False, "approval was bound to a specific action but this finalize carries no binding (fail-closed)"
        if expected_binding != bound:
            return False, ("approval-binding mismatch: this finalize commits a different action "
                           "(agent/tool/purpose/args) than the one approved (fail-closed)")
    return True, "verified (approve_signoff: Cognito-token-verified, SoD-checked, single-use CONSUMED%s)" % (
        "; action-bound" if bound else "")


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


@telemetry.instrument('finalize_signoff')
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
    # Re-derive the approval binding from what is ACTUALLY being finalized (the execution input carries
    # the agent/tool/purpose/args threaded from request_signoff); _approval_path refuses a mismatch.
    expected_binding = evidence.approval_binding({
        "case_id": case_id, "requester": requester,
        "agent": event.get("agent") or "",
        "action": event.get("action") or commit_action or "finalize",
        "purpose": event.get("purpose") or "",
        "args_sha256": event.get("args_sha256") or event.get("content_hash") or "",
    })
    verified, path_detail = _approval_path(case_id, approver, region, expected_binding)
    if not verified:
        if os.environ.get("SIGNOFF_ALLOW_UNVERIFIED", "").lower() == "true":
            path_detail = "UNVERIFIED-OVERRIDE (SIGNOFF_ALLOW_UNVERIFIED=true): " + path_detail
        else:
            return _refuse(context, case_id, requester, approver,
                           "approval path not verified: " + path_detail)

    # ---- AUTHORITATIVE COMMIT (fail-closed ordering) --------------------------------------------
    # The WORM + hash-chained COMMITTED evidence is written FIRST and is the source of truth. NO side
    # effect precedes a durable audit record: the exactly-once FINAL# marker (and any downstream commit
    # keyed off it) is set only AFTER the evidence is durable. If the audit cannot be written the
    # finalize is REFUSED and NOTHING is marked finalized, so a retry re-commits cleanly. This fixes the
    # audit-failure-before-side-effect fail-open (found 2026-09-04): the previous order set the FINAL#
    # marker first, so an evidence-write failure left the case marked finalized with no audit and every
    # retry returned idempotent:committed with no record. The second-approver double-finalize the marker
    # used to guard is already refused by G2 above (the pending-approvals row records ONE approver and is
    # single-use CONSUMED), so evidence-first loses no protection.
    submission_id = "SUB-" + hashlib.sha256(
        ("%s|%s" % (case_id, approver)).encode("utf-8")).hexdigest()[:12].upper()
    res = evidence.record_event({
        "case_id": case_id, "action": commit_action, "phase": "COMMITTED", "actor": approver,
        "deidentified": True,
        "payload": {"requester": requester, "approver": approver, "submission_id": submission_id,
                    "approval_path": path_detail},
    }, context, source=os.environ.get("SOURCE", "finalize"))
    # 1.10.1: DURABLE means the hash-chained ledger write AND the S3 Object-Lock WORM copy both landed
    # (evidence.is_durable). The prior predicate accepted `stored` alone, so a WORM-copy failure
    # (stored=True, worm=False) still wrote the FINAL# marker and returned committed=True — the exact
    # fail-open a consequential commit must never have. A retry re-runs record_event, which now REPAIRS
    # the WORM copy on replay, so a transient S3 failure heals on the next attempt instead of committing
    # without immutable evidence.
    committed = evidence.is_durable(res)
    if not committed:
        # The audit is not durable -> REFUSE. Nothing was marked finalized; a retry re-commits/repairs.
        return {"committed": False, "refused": True, "case_id": case_id, "requester": requester,
                "approver": approver, "approval_path": path_detail,
                "reason": "COMMITTED evidence not durable (ledger + WORM required); finalize refused (fail-closed)",
                "error": res.get("error", "the COMMITTED evidence record could not be written"),
                "evidence": {k: res.get(k) for k in ("audit_id", "chain_hash", "seq", "worm", "stored", "reason", "error")}}

    # Durable evidence exists -> now the exactly-once marker (a replay / already-finalized case reads it
    # and returns the original submission id; the evidence layer is itself append-only + idempotent).
    first, submission_id = _exactly_once_marker(case_id, submission_id, approver, region)
    out = {"committed": True, "submission_id": submission_id, "case_id": case_id,
           "requester": requester, "approver": approver, "approval_path": path_detail,
           "evidence": {k: res.get(k) for k in ("audit_id", "chain_hash", "seq", "worm", "stored", "reason", "error")}}
    if not first:
        out["idempotent"] = True
        out["note"] = "case already finalized; COMMITTED evidence is append-only (exactly-once)"
    return out
