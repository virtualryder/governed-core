"""governed-core 1.10.1 — request_signoff and approve_signoff are FAIL-CLOSED and UN-STRANDABLE on the
audit path (deep-dive critical blocker #2).

  request_signoff: the INTENT evidence must be DURABLE (ledger + WORM) BEFORE the Step Functions
                   execution starts. A non-durable INTENT starts NO execution.
  approve_signoff: the APPROVED evidence must be DURABLE BEFORE the task token is released, and a
                   consume-then-failure must be reconcilable (a retry by the same approver re-enters),
                   never stranded.

Offline: identity, evidence and the boto3 clients are stubbed at the module seam (no AWS).
"""
import types
import json

from botocore.exceptions import ClientError

import governed_core  # noqa: F401  (installs the flat-import path the handlers use)
import request_signoff  # noqa: E402
import approve_signoff  # noqa: E402
import identity  # noqa: E402


class _Ctx:
    invoked_function_arn = "arn:aws:lambda:us-east-1:123456789012:function:x"


def _cond_fail():
    return ClientError({"Error": {"Code": "ConditionalCheckFailedException"}}, "UpdateItem")


# ---------- request_signoff -----------------------------------------------------------------------

def _wire_request(monkeypatch, *, durable):
    monkeypatch.setattr(request_signoff.evidence, "bind_tenant", lambda e: None)
    monkeypatch.setattr(identity, "verify_access_token",
                        lambda tok, require_group=True: ({"sub": "alice"}, None))
    monkeypatch.setattr(identity, "identity_of", lambda claims: "alice")
    monkeypatch.setattr(request_signoff, "_tenant_binding", lambda: {})
    started = {"n": 0}

    def _rec(e, c, source=None):
        return {"stored": True, "worm": True} if durable else {"stored": True, "worm": False, "worm_error": "AccessDenied"}
    monkeypatch.setattr(request_signoff.evidence, "record_event", _rec)

    class _SFN:
        def start_execution(self, **kw):
            started["n"] += 1
            return {"executionArn": "arn:aws:states:us-east-1:1:execution:x:1"}
    monkeypatch.setattr(request_signoff.boto3, "client", lambda *a, **k: _SFN())
    return started


def test_request_starts_no_execution_when_intent_not_durable(monkeypatch):
    started = _wire_request(monkeypatch, durable=False)
    out = request_signoff.handler({"case_id": "C1", "access_token": "t"}, _Ctx())
    assert out["requested"] is False and started["n"] == 0
    assert out["evidence"]["worm"] is False


def test_request_starts_execution_when_intent_durable(monkeypatch):
    started = _wire_request(monkeypatch, durable=True)
    out = request_signoff.handler({"case_id": "C1", "access_token": "t"}, _Ctx())
    assert out["requested"] is True and started["n"] == 1


# ---------- approve_signoff -----------------------------------------------------------------------

class _Tbl:
    """Fake pending-approvals row that honours the 1.10.1 reserve condition + the released marker."""
    def __init__(self, row):
        self.row = dict(row)
        self.updates = []

    def get_item(self, Key):
        return {"Item": dict(self.row)} if self.row else {}

    def update_item(self, Key, UpdateExpression, ExpressionAttributeValues=None,
                    ConditionExpression=None, ExpressionAttributeNames=None):
        vals = ExpressionAttributeValues or {}
        self.updates.append(UpdateExpression)
        if ExpressionAttributeNames:                     # the RESERVE update (references #s = status)
            st, appr = self.row.get("status"), self.row.get("approver")
            a = vals.get(":a")
            ok = (st == "PENDING") or (st == "CONSUMED" and appr == a and not self.row.get("released", False))
            if not ok:
                raise _cond_fail()
            self.row["status"] = "CONSUMED"
            self.row["approver"] = a
        else:                                            # the mark-released update
            if ":t" in vals:
                self.row["released"] = vals[":t"]
        return {}


class _SFN:
    def __init__(self, fail=None):
        self.sent = 0
        self.fail = fail

    def send_task_success(self, taskToken, output):
        self.sent += 1
        if self.fail:
            raise self.fail


def _wire_approve(monkeypatch, *, durable=True, sfn=None, tbl=None, order=None):
    tbl = tbl or _Tbl({"case_id": "C1", "requester": "alice", "task_token": "tok", "status": "PENDING"})
    sfn = sfn or _SFN()
    order = order if order is not None else []
    monkeypatch.setattr(approve_signoff.evidence, "bind_tenant", lambda e: None)
    monkeypatch.setattr(approve_signoff.evidence, "route_table", lambda name, logical: name)
    monkeypatch.setattr(identity, "verify_access_token",
                        lambda tok, require_group=True: ({"sub": "bob"}, None))
    monkeypatch.setattr(identity, "identity_of", lambda claims: "bob")
    monkeypatch.setattr(approve_signoff.boto3, "resource",
                        lambda *a, **k: types.SimpleNamespace(Table=lambda n: tbl))
    monkeypatch.setattr(approve_signoff.boto3, "client", lambda *a, **k: sfn)

    def _rec(e, c, source=None):
        order.append("evidence")
        return {"stored": True, "worm": True} if durable else {"stored": True, "worm": False}
    monkeypatch.setattr(approve_signoff.evidence, "record_event", _rec)

    _orig = sfn.send_task_success
    def _send(taskToken, output):
        order.append("release")
        return _orig(taskToken, output)
    sfn.send_task_success = _send
    return tbl, sfn, order


def test_approve_writes_durable_evidence_before_releasing_token(monkeypatch):
    tbl, sfn, order = _wire_approve(monkeypatch, durable=True)
    out = approve_signoff.handler({"case_id": "C1", "access_token": "t"}, _Ctx())
    assert out["approved"] is True
    assert order == ["evidence", "release"]              # evidence BEFORE the side effect
    assert sfn.sent == 1 and tbl.row.get("released") is True


def test_approve_does_not_release_when_evidence_not_durable_then_retry_reconciles(monkeypatch):
    tbl = _Tbl({"case_id": "C1", "requester": "alice", "task_token": "tok", "status": "PENDING"})
    # attempt 1: evidence not durable -> token NOT released, row CONSUMED/released=false
    _wire_approve(monkeypatch, durable=False, tbl=tbl)
    out1 = approve_signoff.handler({"case_id": "C1", "access_token": "t"}, _Ctx())
    assert out1["approved"] is False and tbl.row["status"] == "CONSUMED" and not tbl.row.get("released")
    # attempt 2 (retry by the SAME approver): evidence now durable -> re-enters, releases, reconciles
    sfn2 = _SFN()
    _wire_approve(monkeypatch, durable=True, tbl=tbl, sfn=sfn2)
    out2 = approve_signoff.handler({"case_id": "C1", "access_token": "t"}, _Ctx())
    assert out2["approved"] is True and sfn2.sent == 1 and tbl.row.get("released") is True


def test_approve_reconciles_after_token_release_failure(monkeypatch):
    tbl = _Tbl({"case_id": "C1", "requester": "alice", "task_token": "tok", "status": "PENDING"})
    # attempt 1: evidence durable, but send_task_success throws a transient error -> not marked released
    throttle = ClientError({"Error": {"Code": "ThrottlingException"}}, "SendTaskSuccess")
    _wire_approve(monkeypatch, durable=True, tbl=tbl, sfn=_SFN(fail=throttle))
    out1 = approve_signoff.handler({"case_id": "C1", "access_token": "t"}, _Ctx())
    assert out1["approved"] is False and not tbl.row.get("released")
    # attempt 2: retry re-enters (same approver, not released) and releases idempotently
    sfn2 = _SFN()
    _wire_approve(monkeypatch, durable=True, tbl=tbl, sfn=sfn2)
    out2 = approve_signoff.handler({"case_id": "C1", "access_token": "t"}, _Ctx())
    assert out2["approved"] is True and sfn2.sent == 1 and tbl.row.get("released") is True


def test_approve_already_released_token_is_idempotent(monkeypatch):
    tbl = _Tbl({"case_id": "C1", "requester": "alice", "task_token": "tok", "status": "PENDING"})
    gone = ClientError({"Error": {"Code": "TaskDoesNotExist"}}, "SendTaskSuccess")
    _wire_approve(monkeypatch, durable=True, tbl=tbl, sfn=_SFN(fail=gone))
    out = approve_signoff.handler({"case_id": "C1", "access_token": "t"}, _Ctx())
    assert out["approved"] is True and "idempotent" in out["release"]
