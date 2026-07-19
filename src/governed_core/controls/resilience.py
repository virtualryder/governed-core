"""Resilience primitives for governed external calls (Workstream B — circuit breakers + retry/backoff).

A slow or flaky external authoritative source (HUD income limits, College Scorecard, openFDA, or the
OAuth-protected system of record) must never hang a tool Lambda or push the agent toward fabricating an
answer. These primitives make an external call degrade to a *fast, controlled* failure so the governed
tool falls soft to `verified: false` / `NEEDS_REVIEW` — the same fail-closed posture the provenance gate
already enforces, extended to availability.

- `CircuitBreaker` trips open after N consecutive logical failures and short-circuits further calls until
  a cooldown elapses (then half-opens to probe recovery). This stops a dead upstream from being hammered
  every invocation and bounds tail latency.
- `retry` adds bounded exponential backoff for transient errors, with an optional `give_up` predicate so
  deterministic errors (e.g. an HTTP 401/403) are NOT retried.
- `resilient_call` composes the two: one breaker "call" wraps a whole retry sequence.

Pure stdlib. `clock` and `sleep` are injectable, so behavior is unit-tested deterministically with no real
waiting and no wall-clock dependence.
"""
import functools
import time as _time


class CircuitOpen(Exception):
    """Raised when the breaker is open and the call is short-circuited (no downstream call attempted)."""


class CircuitBreaker:
    """A minimal three-state circuit breaker: closed -> open -> half_open -> (closed | open)."""

    def __init__(self, failure_threshold=5, reset_timeout=30.0, *, clock=_time.monotonic):
        if failure_threshold < 1:
            raise ValueError("failure_threshold must be >= 1")
        self.failure_threshold = failure_threshold
        self.reset_timeout = reset_timeout
        self._clock = clock
        self._failures = 0
        self._opened_at = None
        self.state = "closed"

    def _allow(self):
        if self.state == "open":
            if self._clock() - self._opened_at >= self.reset_timeout:
                self.state = "half_open"  # allow a single probe
                return True
            return False
        return True

    def record_success(self):
        self._failures = 0
        self._opened_at = None
        self.state = "closed"

    def record_failure(self):
        self._failures += 1
        if self._failures >= self.failure_threshold:
            self.state = "open"
            self._opened_at = self._clock()

    def call(self, fn, *args, **kwargs):
        if not self._allow():
            raise CircuitOpen("circuit open (upstream unhealthy); short-circuited")
        try:
            result = fn(*args, **kwargs)
        except Exception:
            self.record_failure()
            raise
        self.record_success()
        return result


def retry(fn=None, *, attempts=3, base_delay=0.2, max_delay=5.0, exceptions=(Exception,),
          give_up=None, sleep=_time.sleep, jitter=None):
    """Bounded exponential-backoff retry.

    Retries a call up to `attempts` times on `exceptions`, sleeping `min(max_delay, base_delay*2**i)` (+
    optional `jitter(i)`) between tries. If `give_up(ex)` returns True the error is re-raised immediately
    (use it to skip retrying deterministic errors). `sleep`/`jitter` are injectable for deterministic tests.
    """
    def deco(f):
        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            last = None
            for i in range(attempts):
                try:
                    return f(*args, **kwargs)
                except exceptions as ex:
                    if give_up is not None and give_up(ex):
                        raise
                    last = ex
                    if i == attempts - 1:
                        break
                    delay = min(max_delay, base_delay * (2 ** i))
                    if jitter is not None:
                        delay += jitter(i)
                    if delay > 0:
                        sleep(delay)
            raise last
        return wrapper
    return deco(fn) if fn is not None else deco


def resilient_call(fn, *args, breaker=None, attempts=3, base_delay=0.2, max_delay=5.0,
                   exceptions=(Exception,), give_up=None, sleep=_time.sleep, **kwargs):
    """Run one external call with retry+backoff, optionally guarded by a circuit breaker.

    The breaker sees a whole retry sequence as a single logical call: `attempts` transient failures in a
    row count as ONE breaker failure; a success resets it. If the breaker is open, raises `CircuitOpen`
    immediately without attempting the call.
    """
    retried = retry(attempts=attempts, base_delay=base_delay, max_delay=max_delay,
                    exceptions=exceptions, give_up=give_up, sleep=sleep)(lambda: fn(*args, **kwargs))
    if breaker is not None:
        return breaker.call(retried)
    return retried()
