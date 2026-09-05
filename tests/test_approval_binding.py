"""governed-core — single-use SoD approvals are cryptographically bound to the EXACT action.

Gap (2026-09-05): approvals were bound only to case_id + requester, so a released/CONSUMED approval
could authorize a DIFFERENT agent/tool/purpose/arguments. request_signoff now computes an
approval_binding over (case_id, requester, agent, action, purpose, args_sha256), signoff_register
stores it on the pending row, and finalize RE-DERIVES it from what is actually being committed and
refuses any mismatch (fail-closed). A legacy row with no binding still verifies (back-compat).
"""
import governed_core  # noqa: F401
import evidence  # noqa: E402
import finalize_signoff  # noqa: E402


def test_binding_is_deterministic_and_field_sensitive():
    f = {"case_id": "C1", "requester": "alice", "agent": "agentA",
         "action": "finalize", "purpose": "disburse", "args_sha256": "abc"}
    b = evidence.approval_binding(f)
    assert b == evidence.approval_binding(dict(f))                       # deterministic
    assert b != evidence.approval_binding({**f, "action": "refund"})      # tool/action change
    assert b != evidence.approval_binding({**f, "args_sha256": "xyz"})    # arguments change
    assert b != evidence.approval_binding({**f, "purpose": "other"})      # purpose change
    assert b != evidence.approval_binding({**f, "agent": "agentB"})       # agent change
    assert b != evidence.approval_binding({**f, "requester": "carol"})    # requester change


class _Tbl:
    def __init__(self, row):
        self._row = row

    def get_item(self, Key):
        return {"Item": self._row}


def _row(binding=None):
    r = {"case_id": "C1", "status": "CONSUMED", "approver": "bob"}
    if binding is not None:
        r["approval_binding"] = binding
    return r


def test_finalize_refuses_a_binding_mismatch(monkeypatch):
    monkeypatch.setattr(finalize_signoff, "_pending_table", lambda region: _Tbl(_row("APPROVED")))
    ok, detail = finalize_signoff._approval_path("C1", "bob", "us-east-1", expected_binding="DIFFERENT")
    assert ok is False and "mismatch" in detail


def test_finalize_accepts_a_matching_binding(monkeypatch):
    monkeypatch.setattr(finalize_signoff, "_pending_table", lambda region: _Tbl(_row("B123")))
    ok, detail = finalize_signoff._approval_path("C1", "bob", "us-east-1", expected_binding="B123")
    assert ok is True and "action-bound" in detail


def test_finalize_refuses_when_bound_but_finalize_supplies_no_binding(monkeypatch):
    monkeypatch.setattr(finalize_signoff, "_pending_table", lambda region: _Tbl(_row("B123")))
    ok, detail = finalize_signoff._approval_path("C1", "bob", "us-east-1", expected_binding=None)
    assert ok is False


def test_finalize_backcompat_row_without_binding_still_verifies(monkeypatch):
    monkeypatch.setattr(finalize_signoff, "_pending_table", lambda region: _Tbl(_row(None)))
    ok, detail = finalize_signoff._approval_path("C1", "bob", "us-east-1", expected_binding="anything")
    assert ok is True
