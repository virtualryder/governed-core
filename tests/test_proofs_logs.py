"""The shared audit-line reader (PAR-4).

Every assertion here corresponds to a defect that reached a live gate before this code was shared:
a query engine that dropped rows without saying so, a swallowed throttle that turned a short read
into an accusation, and correlation logic that got weaker the more join keys it was given.
"""
import pytest

from governed_core.proofs import logs as L

CASE = "LIN-E02DBE"
TRACE = "6a9e99c2a2d110c3facef6271573ff14"
EXEC = "arn:aws:states:us-east-1:1234:execution:pack-workflow:lineage-lin-e02dbe"

AUDIT = ('{"aegis": "call", "args_sha256": "a992", "case_id": "%s", "execution_arn": "%s", '
         '"tool": "write_audit", "trace_id": "%s", "ts": 3}' % (CASE, EXEC, TRACE))
EARLIER = ('{"aegis": "call", "args_sha256": "bbbb", "case_id": "%s", "tool": "mask_pii", '
           '"trace_id": "%s", "ts": 1}' % (CASE, TRACE))
OTHER_CASE = ('{"aegis": "call", "args_sha256": "ffff", "case_id": "OTHER-1", "tool": "mask_pii", '
              '"trace_id": "deadbeef", "ts": 2}')
PLATFORM = "START RequestId: 6b3106ce-1d3e-492c-9ea8-b7ef2e4c4f35 Version: $LATEST"


class Throttled(Exception):
    pass


Throttled.__name__ = "ThrottlingException"


class ResourceNotFoundException(Exception):
    pass


class FakeLogs:
    def __init__(self, messages, fail_times=0, missing=False):
        self.messages, self.fail_times, self.missing = messages, fail_times, missing
        self.calls = 0

    def filter_log_events(self, **kw):
        self.calls += 1
        if self.missing:
            raise ResourceNotFoundException("no such group")
        if self.calls <= self.fail_times:
            raise Throttled("slow down")
        return {"events": [{"message": m} for m in self.messages]}

    def start_query(self, **kw):                       # pragma: no cover
        raise AssertionError("the audit reader must not use Insights")


# L39: a real window. These fixtures used (0, 1), which is 1970 and is now refused on purpose -
# an impossible window must raise rather than quietly return "no audit lines".
WINDOW = (1788818472000, 1788818935000)


def _read(msgs, keys=None, **kw):
    logs = FakeLogs(msgs, **kw)
    return L.read_lambda_calls(logs, ["/aws/lambda/pack-write-audit"], CASE,
                               keys if keys is not None else {}, *WINDOW), logs


def test_correlates_when_every_join_key_is_present():
    """The shape that returned nothing when the keys were pushed into the query language."""
    rows, _ = _read([AUDIT], {"trace_id": [TRACE], "execution_arn": [EXEC], "session_id": []})
    assert [r["tool"] for r in rows] == ["write_audit"]


def test_each_key_alone_still_correlates():
    for keys in ({"trace_id": [TRACE]}, {"execution_arn": [EXEC]}, {}):
        rows, _ = _read([AUDIT], keys)
        assert [r["tool"] for r in rows] == ["write_audit"], keys


def test_unrelated_and_non_json_lines_are_excluded():
    rows, _ = _read([AUDIT, OTHER_CASE, PLATFORM], {"trace_id": [TRACE]})
    assert [r["tool"] for r in rows] == ["write_audit"]


def test_rows_come_back_in_timestamp_order():
    rows, _ = _read([AUDIT, EARLIER], {"trace_id": [TRACE]})
    assert [r["ts"] for r in rows] == [1, 3]


def test_a_throttle_is_retried_not_swallowed(monkeypatch):
    """A short read of audit lines is indistinguishable from a tool that never audited itself."""
    monkeypatch.setattr(L.time, "sleep", lambda *_: None)
    rows, logs = _read([AUDIT], {"trace_id": [TRACE]}, fail_times=2)
    assert [r["tool"] for r in rows] == ["write_audit"]
    assert logs.calls == 3


def test_a_throttle_that_outlives_its_retries_raises(monkeypatch):
    monkeypatch.setattr(L.time, "sleep", lambda *_: None)
    with pytest.raises(Exception) as e:
        _read([AUDIT], {"trace_id": [TRACE]}, fail_times=99)
    assert type(e.value).__name__ == "ThrottlingException"


def test_a_missing_log_group_is_benign():
    rows, _ = _read([AUDIT], {"trace_id": [TRACE]}, missing=True)
    assert rows == []


def test_a_non_retryable_error_propagates():
    class Boom(Exception):
        pass

    class Bad(FakeLogs):
        def filter_log_events(self, **kw):
            raise Boom("access denied")

    with pytest.raises(Boom):
        L.read_lambda_calls(Bad([]), ["/g"], CASE, {}, *WINDOW)
