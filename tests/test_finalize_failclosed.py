"""governed-core — finalize is FAIL-CLOSED on the audit path.

Regression for the audit-failure-before-side-effect fail-open (found 2026-09-04): finalize wrote the
exactly-once FINAL# marker (the "case is finalized" side effect) BEFORE the WORM / hash-chained
COMMITTED evidence and never rolled it back, so an evidence-write failure left the case marked
finalized with no audit and every retry returned idempotent:committed with no record. The commit now
writes the durable evidence FIRST and executes the marker side effect ONLY after the evidence is
stored; an audit failure REFUSES the finalize and sets no marker.

Offline: the evidence writer and the exactly-once marker are stubbed at the module seam (no AWS).
"""
import governed_core  # noqa: F401  (installs the flat-import path the handlers use)
import finalize_signoff  # noqa: E402


class _Ctx:
    invoked_function_arn = "arn:aws:lambda:us-east-1:123456789012:function:x"


def _event(approver="bob", requester="alice"):
    return {"case_id": "C-1", "requester": requester, "approver": approver}


def _wire(monkeypatch, *, evidence_stored, marker_first=True):
    calls = {"marker": 0, "evidence": 0}
    monkeypatch.setattr(finalize_signoff.evidence, "bind_tenant", lambda e: None)
    monkeypatch.setattr(finalize_signoff, "_approval_path",
                        lambda case_id, approver, region, expected_binding=None: (True, "verified (test)"))

    def _rec(logical, context, source=None):
        calls["evidence"] += 1
        calls["last_phase"] = logical.get("phase")
        if evidence_stored:
            return {"stored": True, "audit_id": "A1", "chain_hash": "H1", "seq": 0, "worm": True}
        return {"stored": False, "reason": "worm put failed", "error": "AccessDenied"}
    monkeypatch.setattr(finalize_signoff.evidence, "record_event", _rec)

    def _marker(case_id, submission_id, approver, region):
        calls["marker"] += 1
        return (marker_first, submission_id)
    monkeypatch.setattr(finalize_signoff, "_exactly_once_marker", _marker)
    return calls


def test_audit_failure_refuses_and_executes_no_side_effect(monkeypatch):
    """Evidence write fails -> finalize REFUSED, and the FINAL# marker (side effect) is never set."""
    calls = _wire(monkeypatch, evidence_stored=False)
    out = finalize_signoff.handler(_event(), _Ctx())
    assert out["committed"] is False and out["refused"] is True
    assert calls["evidence"] == 1          # the COMMITTED evidence was ATTEMPTED first
    assert calls["marker"] == 0            # the side effect is NOT executed when the audit fails


def test_commit_writes_durable_evidence_before_the_marker(monkeypatch):
    calls = _wire(monkeypatch, evidence_stored=True, marker_first=True)
    out = finalize_signoff.handler(_event(), _Ctx())
    assert out["committed"] is True and out.get("refused") is not True
    assert calls["evidence"] == 1 and calls["marker"] == 1
    assert out["evidence"]["worm"] is True and out["evidence"]["stored"] is True


def test_idempotent_replay_when_already_finalized(monkeypatch):
    calls = _wire(monkeypatch, evidence_stored=True, marker_first=False)
    out = finalize_signoff.handler(_event(), _Ctx())
    assert out["committed"] is True and out.get("idempotent") is True


def test_separation_of_duties_refused_before_any_commit(monkeypatch):
    calls = _wire(monkeypatch, evidence_stored=True)
    out = finalize_signoff.handler(_event(approver="alice", requester="alice"), _Ctx())
    assert out["committed"] is False and out["refused"] is True
    assert calls["marker"] == 0                     # no commit side effect on an SoD refusal
    assert calls.get("last_phase") == "DENIED"      # the refusal itself is audited


# --- 1.10.1: WORM-copy failure must NOT commit (deep-dive critical blocker #1) --------------------

def _wire_worm(monkeypatch, rec_result):
    """Wire finalize with a record_event that returns `rec_result` (to inject stored/worm/replay)."""
    calls = {"marker": 0, "evidence": 0}
    monkeypatch.setattr(finalize_signoff.evidence, "bind_tenant", lambda e: None)
    monkeypatch.setattr(finalize_signoff, "_approval_path",
                        lambda case_id, approver, region, expected_binding=None: (True, "verified (test)"))

    def _rec(logical, context, source=None):
        calls["evidence"] += 1
        return dict(rec_result)
    monkeypatch.setattr(finalize_signoff.evidence, "record_event", _rec)

    def _marker(case_id, submission_id, approver, region):
        calls["marker"] += 1
        return (True, submission_id)
    monkeypatch.setattr(finalize_signoff, "_exactly_once_marker", _marker)
    return calls


def test_worm_failure_refuses_commit_even_when_ledger_stored(monkeypatch):
    """stored=True, worm=False (the S3 Object-Lock copy failed) MUST NOT commit. This is the exact
    fault the reviewer reproduced: the old predicate accepted `stored` alone and wrote the FINAL#
    marker with worm=False. Now: refused, and the marker side effect is never executed."""
    calls = _wire_worm(monkeypatch, {"stored": True, "worm": False, "worm_error": "AccessDenied", "audit_id": "A1"})
    out = finalize_signoff.handler(_event(), _Ctx())
    assert out["committed"] is False and out["refused"] is True
    assert calls["marker"] == 0                          # NO side effect without ledger + WORM
    assert out["evidence"]["worm"] is False


def test_retry_with_repaired_worm_commits(monkeypatch):
    """A retry after a transient WORM failure: record_event returns replay=True, worm=True (the WORM
    copy was repaired from the authoritative stored item). is_durable is satisfied -> commit."""
    calls = _wire_worm(monkeypatch, {"stored": False, "replay": True, "worm": True,
                                     "reason": "append-only: this exact record is already recorded (immutable)", "audit_id": "A1"})
    out = finalize_signoff.handler(_event(), _Ctx())
    assert out["committed"] is True and calls["marker"] == 1


def test_replay_without_worm_still_refuses(monkeypatch):
    """replay=True but worm=False (WORM still unavailable on retry) -> not durable -> still refused."""
    calls = _wire_worm(monkeypatch, {"stored": False, "replay": True, "worm": False, "audit_id": "A1"})
    out = finalize_signoff.handler(_event(), _Ctx())
    assert out["committed"] is False and out["refused"] is True and calls["marker"] == 0


def test_worm_not_required_override_commits_when_explicit(monkeypatch):
    """EVIDENCE_WORM_REQUIRED=false is the explicit, deployment-level relaxation (e.g. a WORM-less
    sandbox). Then stored alone is durable enough. Secure default is strict; this must be opt-in."""
    monkeypatch.setenv("EVIDENCE_WORM_REQUIRED", "false")
    calls = _wire_worm(monkeypatch, {"stored": True, "worm": False, "audit_id": "A1"})
    out = finalize_signoff.handler(_event(), _Ctx())
    assert out["committed"] is True and calls["marker"] == 1
