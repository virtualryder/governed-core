"""L39: the two CloudWatch time units, and the window that silently found nothing.

filter_log_events takes epoch MILLISECONDS. start_query takes epoch SECONDS. This module offers
both, read_lambda_calls was moved from one to the other (L33) without converting the callers'
seconds, and the result was a scan of 1970 that returned nothing on every run - reported as
"lambda_calls_logged: false", i.e. as a governed tool that never audited itself.

Live proof of the defect and the fix, taken against a standing environment before teardown: a raw
scan found 7 aegis.call lines carrying the case id in 7 distinct log groups, for each of two
tenants; read_lambda_calls returned 0 before the fix and 7 after, on the same inputs.
"""
import pytest

from governed_core.proofs import window_ms

_2026_S = 1788818472
_2026_MS = 1788818472000


def test_seconds_are_promoted_to_milliseconds():
    assert window_ms(_2026_S, _2026_S + 400) == (_2026_MS, _2026_MS + 400000)


def test_milliseconds_pass_through_unchanged():
    assert window_ms(_2026_MS, _2026_MS + 400000) == (_2026_MS, _2026_MS + 400000)


def test_the_exact_window_that_returned_nothing_is_now_correct():
    """The obs proof's real window from gate attempt 20. Interpreted as ms it is 1970-01-21."""
    a, b = window_ms(1788818472, 1788818935)
    assert a == 1788818472000 and b == 1788818935000


def test_a_pre_2020_window_raises_instead_of_returning_empty():
    """The whole point. A caller unit bug must not look like an absence of evidence."""
    # A 2019 window, expressed in milliseconds so it is not promoted, is refused outright.
    with pytest.raises(ValueError) as e:
        window_ms(1_500_000_000_000, 1_500_000_400_000)     # 2017, in ms
    assert "before 2020" in str(e.value)


def test_an_inverted_or_empty_window_raises():
    with pytest.raises(ValueError) as e:
        window_ms(_2026_MS, _2026_MS)
    assert "empty log window" in str(e.value)
    with pytest.raises(ValueError):
        window_ms(_2026_MS + 1000, _2026_MS)


def test_scan_log_events_refuses_an_impossible_window():
    """End to end through the scanner: it must raise, not return []."""
    from governed_core.proofs import scan_log_events

    class _Boom:
        def filter_log_events(self, **kw):        # must never be reached
            raise AssertionError("the scanner called AWS with an impossible window")

    with pytest.raises(ValueError):
        scan_log_events(_Boom(), "/aws/lambda/anything", 1_000_000, 2_000_000)


def test_scan_log_events_passes_milliseconds_to_the_api():
    seen = {}

    class _Rec:
        def filter_log_events(self, **kw):
            seen.update(kw)
            return {"events": []}

    from governed_core.proofs import scan_log_events
    scan_log_events(_Rec(), "/aws/lambda/x", _2026_S, _2026_S + 60)
    assert seen["startTime"] == _2026_MS, "seconds reached filter_log_events - the L39 defect"
    assert seen["endTime"] == _2026_MS + 60000
