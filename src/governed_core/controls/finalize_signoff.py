import os
import hashlib
import evidence

# finalize_signoff — the PRIVILEGED commit task, invoked by the sign-off state machine ONLY after a
# valid separation-of-duties approval. The agent can never reach it (Cedar forbids the direct finalize
# tool and this Lambda is not on the Gateway). It records the COMMITTED decision through the CANONICAL
# evidence service (hash-chained + WORM), fail-loud — no raw put_item, no swallowed errors.


def handler(event, context):
    case_id = event.get("case_id") or event.get("icsr_id")
    requester = event.get("requester")
    approver = event.get("approver")
    commit_action = event.get("commit_action") or os.environ.get("COMMIT_ACTION", "finalize")
    submission_id = "SUB-" + hashlib.sha256(
        ("%s|%s" % (case_id, approver)).encode("utf-8")).hexdigest()[:12].upper()

    res = evidence.record_event({
        "case_id": case_id, "action": commit_action, "phase": "COMMITTED", "actor": approver,
        "deidentified": True,
        "payload": {"requester": requester, "approver": approver, "submission_id": submission_id},
    }, context, source=os.environ.get("SOURCE", "finalize"))

    committed = bool(res.get("stored")) or "already recorded" in (res.get("reason") or "")
    out = {"committed": committed, "submission_id": submission_id, "case_id": case_id,
           "requester": requester, "approver": approver,
           "evidence": {k: res.get(k) for k in ("audit_id", "chain_hash", "seq", "worm", "stored", "reason", "error")}}
    if not committed:
        out["error"] = res.get("error", "the COMMITTED evidence record could not be written")
    return out
