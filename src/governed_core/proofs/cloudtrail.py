"""CloudTrail capture-trail readers for the lineage proof.

The capture-all trail records every API call in the account, so a plain scan of it is impractical
and this module does use Insights. That makes it the one place where the L33 defect - Insights
silently dropping rows for `like` predicates - still has reach, and the design answers it directly:
the filtered query is a HINT, and any result that would become an ACCUSATION is corroborated by an
unfiltered re-read of the same window before it is reported.

The corroboration is keyed on `eventID`. An earlier attempt merged on
(eventTime, eventName, functionName) and took a run's invoke count from 10 to 21, because CloudTrail
stamps `eventTime` to one-second resolution and distinct invokes legitimately share a second.
Merging on a non-unique key does not deduplicate; it fabricates.
"""
from governed_core.proofs.logs import insights_query

_FIELDS = ("fields @timestamp, eventID, eventTime, eventSource, eventName, "
           "requestParameters.functionName as fn, requestParameters.bucketName as bkt, "
           "userIdentity.arn as who, requestParameters.stateMachineArn as sm ")


def _keep_event(prefix, src, name, fn, bkt):
    """The governed surface: this pack's Lambdas, this pack's buckets, and Step Functions."""
    return ((src == "lambda.amazonaws.com" and "Invoke" in name and prefix in fn)
            or (src == "s3.amazonaws.com"
                and name in ("PutObject", "CompleteMultipartUpload") and prefix in bkt)
            or src == "states.amazonaws.com")


def _row(r, ts):
    return {"ts": ts, "event_id": r.get("eventID") or "",
            "event_source": r.get("eventSource", ""), "event_name": r.get("eventName", ""),
            "target": r.get("fn") or r.get("bkt") or r.get("sm") or "",
            "principal": r.get("who", "")}


def _window(start, end):
    """Snap to CloudTrail's own resolution.

    `eventTime` has ONE-SECOND granularity while the case window is measured in milliseconds, so the
    invoke that STARTS a case is stamped at the enclosing second and a strict comparison drops it.
    The window is widened to the resolution of the SOURCE - not by an arbitrary fudge - and applied
    identically wherever it is used, because widening one side of a two-sided comparison turns a
    missing record into a disagreement instead of fixing it.
    """
    return (start // 1000) * 1000, -(-end // 1000) * 1000


def read_cloudtrail_capture(logs, capture_log_group, prefix, start, end, query_end, iso_ms):
    """Governed invokes recorded by CloudTrail, deduplicated on eventID.

    CloudTrail delivers to CloudWatch Logs minutes after the API call, so the QUERY window runs to
    `query_end` (now) while events are kept only if their own `eventTime` falls in the semantic
    window [start, end] - the execution window.
    """
    q = (_FIELDS
         + '| filter (eventSource="lambda.amazonaws.com" and eventName like /Invoke/ and fn like /'
         + prefix + '/) '
         + 'or (eventSource="s3.amazonaws.com" and (eventName="PutObject" or '
           'eventName="CompleteMultipartUpload") and bkt like /' + prefix + '/) '
         + 'or (eventSource="states.amazonaws.com") '
         + '| sort @timestamp asc | limit 5000')
    rows = insights_query(logs, [capture_log_group], q, start, max(end, query_end), 5000)
    w_start, w_end = _window(start, end)
    out, seen = [], set()
    for r in rows:
        eid = r.get("eventID") or ""
        if eid and eid in seen:
            continue
        ts = iso_ms(r.get("eventTime"))
        if ts and not (w_start <= ts <= w_end):
            continue
        if eid:
            seen.add(eid)
        out.append(_row(r, ts or iso_ms(r.get("@timestamp"))))
    return out


def verify_cloudtrail_capture(logs, capture_log_group, prefix, start, end, known, query_end, iso_ms):
    """Re-read the window with NO predicates and merge whatever the filtered query missed.

    Called only when a tool would otherwise be reported audited-but-never-invoked, so the expensive
    scan happens when the answer would otherwise be an accusation. Returns (rows, recovered_count);
    callers record the count, so a run that needed corroboration can never be read as one that did not.
    """
    raw = insights_query(logs, [capture_log_group],
                         _FIELDS + "| sort @timestamp asc | limit 10000",
                         start, max(end, query_end), 10000)
    w_start, w_end = _window(start, end)
    seen = {r.get("event_id") for r in known if r.get("event_id")}
    added = []
    for r in raw:
        eid = r.get("eventID") or ""
        if not eid or eid in seen:
            continue
        if not _keep_event(prefix, r.get("eventSource") or "", r.get("eventName") or "",
                           r.get("fn") or "", r.get("bkt") or ""):
            continue
        ts = iso_ms(r.get("eventTime"))
        if ts and not (w_start <= ts <= w_end):
            continue
        seen.add(eid)
        added.append(_row(r, ts or iso_ms(r.get("@timestamp"))))
    return known + added, len(added)
