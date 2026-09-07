"""CloudWatch Logs readers for the governance proofs.

The audit-line reader here replaced a CloudWatch Logs Insights query after that query was shown to
drop rows silently. The evidence, taken against one log group and one window on 2026-09-07:

    Insights, filter `aegis` AND `args_sha256`          -> 0 rows
    the same filter over a window widened by 120s       -> 0 rows
    Insights with NO filter                             -> the line is right there
    filter_log_events over the exact same window        -> 11 rows, including the missing one

Two full gate cycles were spent on that, first blaming a settle window and then a three-term `or`
chain. The conclusion is not "avoid that filter shape" - it is that a query engine whose omissions
are invisible has no place between a governance claim and its evidence.
"""
import json
import time

_RETRYABLE = ("ThrottlingException", "LimitExceededException", "TooManyRequestsException",
              "ServiceUnavailableException", "RequestLimitExceeded")
_MAX_ATTEMPTS = 6


def parse_json_message(message):
    """A log line as a dict, or None when it is not JSON (START/END/REPORT and friends)."""
    try:
        return json.loads(message)
    except (ValueError, TypeError):
        return None


def _call_with_retry(fn, **kw):
    """Retry the retryable and RAISE the rest.

    A swallowed throttle is a silent truncation, and a short read of audit lines looks exactly like
    a governed tool that never audited itself - that is how a green transparency proof turned red
    with no defect behind it. Failing loudly beats reporting a clean-looking absence.
    """
    for attempt in range(_MAX_ATTEMPTS):
        try:
            return fn(**kw)
        except Exception as exc:                       # noqa: BLE001 - re-raised below
            if type(exc).__name__ not in _RETRYABLE or attempt == _MAX_ATTEMPTS - 1:
                raise
            time.sleep(1.5 * (2 ** attempt))


# ---- L39: filter_log_events takes MILLISECONDS; start_query takes SECONDS -----------------------
# These two CloudWatch APIs disagree on units, and this module offers both. read_lambda_calls was
# converted from the query engine to a plain scan (L33) without converting the callers' seconds, so
# a 2026 timestamp became 1970-01-21 and the scan asked for a window 56 years wide of nothing -
# silently, on every run. It survived because the callers disagree and only one is wrong: the
# lineage proof computes milliseconds and was correct, the transparency proof computes seconds and
# reported "no audit lines" for both tenants.
#
# The unit is normalized here, once, and an impossible window RAISES. The raise matters more than
# the conversion: an unlabelled unit that silently answers "no evidence" is the L25/L29/L31/L33/L33b
# family, and the answer to that family is always to fail loudly rather than report an absence.
_YEAR_2020_MS = 1577836800000
_SECONDS_CEILING = 100000000000        # anything smaller was seconds, not milliseconds


def window_ms(start, end):
    """Normalize a (start, end) log window to epoch milliseconds. Accepts seconds or milliseconds."""
    def _ms(t):
        t = int(t)
        return t * 1000 if t < _SECONDS_CEILING else t
    a, b = _ms(start), _ms(end)
    if a >= b:
        raise ValueError("empty log window: start=%r end=%r (normalized %d..%d)" % (start, end, a, b))
    if a < _YEAR_2020_MS:
        raise ValueError(
            "log window starts before 2020 (normalized %d ms). That is a caller unit bug, not an "
            "empty result - refusing to report an absence of evidence from an impossible window." % a)
    return a, b


def scan_log_events(logs, group, start, end, keep=None):
    """Every event in [start, end] for one log group, paginated, as a plain scan.

    `keep(message) -> bool` filters in Python. A missing log group is not an error - a pack may not
    deploy every function - but any other failure propagates.
    """
    start_ms, end_ms = window_ms(start, end)        # L39
    out, token = [], None
    while True:
        kw = {"logGroupName": group, "startTime": start_ms, "endTime": end_ms, "limit": 1000}
        if token:
            kw["nextToken"] = token
        try:
            r = _call_with_retry(logs.filter_log_events, **kw)
        except Exception as exc:                       # noqa: BLE001
            if _is_missing_group(exc):
                return out                             # a pack need not deploy every function
            raise
        for ev in r.get("events", []):
            msg = ev.get("message", "")
            if keep is None or keep(msg):
                out.append(msg)
        token = r.get("nextToken")
        if not token:
            return out


def _is_missing_group(exc):
    """Matched on the class NAME so this works for botocore's generated errors and for test stubs.

    Deliberately narrow: ONLY a missing log group is benign. Everything else - throttles that
    outlived their retries, permission errors, malformed queries - must propagate, because the cost
    of a swallowed error here is a governance claim built on a short read.
    """
    return type(exc).__name__ == "ResourceNotFoundException"


def read_lambda_calls(logs, groups, case_id, keys, start, end):
    """The `aegis.call` audit lines for one case, correlated in Python.

    `keys` is the join-key bundle from the WORM ledger (trace_id, execution_arn, session_id). A line
    counts when it carries ANY of those or the case id: the audit record and the invoke that produced
    it are written by different systems, and the only honest way to tie them together is a key both
    sides recorded.
    """
    needles = [n for n in ([case_id]
                           + list(keys.get("trace_id", []) or [])
                           + list(keys.get("execution_arn", []) or [])
                           + list(keys.get("session_id", []) or [])) if n]

    def _keep(msg):
        if '"aegis"' not in msg or "args_sha256" not in msg:
            return False
        return not needles or any(n in msg for n in needles)

    out = []
    for g in [g for g in groups if g]:
        for msg in scan_log_events(logs, g, start, end, keep=_keep):
            m = parse_json_message(msg)
            if m and m.get("aegis") == "call":
                out.append(m)
    return sorted(out, key=lambda m: m.get("ts") or 0)


def insights_query(logs, groups, query, start, end, limit=1000, poll_sec=1, max_polls=60):
    """Run an Insights query. Use ONLY where a plain scan is impractical (a whole-account trail).

    Anything that decides PASS/FAIL on the ABSENCE of rows must corroborate a filtered Insights
    result before reporting a gap - see `cloudtrail.verify_cloudtrail_capture`.
    """
    groups = [g for g in groups if g]
    if not groups:
        return []
    try:
        qid = _call_with_retry(logs.start_query, logGroupNames=groups, startTime=start,
                               endTime=end, queryString=query, limit=limit)["queryId"]
    except Exception as exc:                           # noqa: BLE001
        if _is_missing_group(exc):
            return []
        raise
    r = {}
    for _ in range(max_polls):
        time.sleep(poll_sec)
        r = logs.get_query_results(queryId=qid)
        if r.get("status") in ("Complete", "Failed", "Cancelled", "Timeout"):
            break
    return [{f["field"]: f["value"] for f in row} for row in r.get("results", [])]
