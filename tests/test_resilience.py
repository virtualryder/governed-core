"""Unit tests for the governed-core resilience primitives (Workstream B). Deterministic — the clock and
sleep are injected, so no test ever waits on wall-clock time."""
import governed_core  # noqa: F401  (installs the package + sets up the flat-import path)
from governed_core.controls import resilience


# ---- retry with bounded backoff ----

def test_retry_succeeds_after_transient_failures():
    calls = {"n": 0}
    slept = []

    @resilience.retry(attempts=3, base_delay=0.1, sleep=slept.append)
    def flaky():
        calls["n"] += 1
        if calls["n"] < 3:
            raise ConnectionError("transient")
        return "ok"

    assert flaky() == "ok"
    assert calls["n"] == 3
    assert slept == [0.1, 0.2]  # exponential backoff between the two retries


def test_retry_exhausts_and_raises_last():
    slept = []

    @resilience.retry(attempts=3, base_delay=0.1, sleep=slept.append)
    def always_fails():
        raise TimeoutError("still down")

    try:
        always_fails()
        assert False, "should have raised"
    except TimeoutError as ex:
        assert "still down" in str(ex)
    assert len(slept) == 2  # slept between attempts 1->2 and 2->3, not after the last


def test_retry_give_up_skips_retry():
    calls = {"n": 0}

    def is_fatal(ex):
        return isinstance(ex, ValueError)

    @resilience.retry(attempts=5, base_delay=0.0, exceptions=(Exception,), give_up=is_fatal)
    def fatal():
        calls["n"] += 1
        raise ValueError("deterministic — do not retry")

    try:
        fatal()
        assert False
    except ValueError:
        pass
    assert calls["n"] == 1  # gave up immediately, no retries


# ---- circuit breaker ----

def test_breaker_opens_then_short_circuits():
    clock = {"t": 0.0}
    cb = resilience.CircuitBreaker(failure_threshold=3, reset_timeout=30.0, clock=lambda: clock["t"])

    def boom():
        raise ConnectionError("down")

    for _ in range(3):
        try:
            cb.call(boom)
        except ConnectionError:
            pass
    assert cb.state == "open"

    # while open, the call is short-circuited without invoking the function
    invoked = {"n": 0}

    def probe():
        invoked["n"] += 1
        return "ok"

    try:
        cb.call(probe)
        assert False, "expected CircuitOpen"
    except resilience.CircuitOpen:
        pass
    assert invoked["n"] == 0


def test_breaker_half_opens_and_recovers():
    clock = {"t": 0.0}
    cb = resilience.CircuitBreaker(failure_threshold=2, reset_timeout=30.0, clock=lambda: clock["t"])
    for _ in range(2):
        try:
            cb.call(lambda: (_ for _ in ()).throw(ConnectionError()))
        except ConnectionError:
            pass
    assert cb.state == "open"

    clock["t"] = 31.0  # cooldown elapsed -> half-open probe allowed
    assert cb.call(lambda: "recovered") == "recovered"
    assert cb.state == "closed"


# ---- resilient_call composition ----

def test_resilient_call_one_sequence_is_one_breaker_failure():
    clock = {"t": 0.0}
    cb = resilience.CircuitBreaker(failure_threshold=2, reset_timeout=30.0, clock=lambda: clock["t"])

    def always_down():
        raise ConnectionError("down")

    # each resilient_call runs a full 3-attempt retry sequence = ONE logical breaker failure
    for _ in range(2):
        try:
            resilience.resilient_call(always_down, breaker=cb, attempts=3, base_delay=0.0,
                                      exceptions=(ConnectionError,), sleep=lambda d: None)
        except ConnectionError:
            pass
    assert cb.state == "open"

    # now open: short-circuits immediately with CircuitOpen (no further attempts)
    try:
        resilience.resilient_call(always_down, breaker=cb, attempts=3, base_delay=0.0,
                                  exceptions=(ConnectionError,), sleep=lambda d: None)
        assert False
    except resilience.CircuitOpen:
        pass
