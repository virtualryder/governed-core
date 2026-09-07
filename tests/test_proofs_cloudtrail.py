"""The shared CloudTrail reader (PAR-4).

`eventID` is the only identity used here. An earlier version merged on
(eventTime, eventName, functionName) and took a run's invoke count from 10 to 21, because CloudTrail
stamps eventTime to one-second resolution and distinct invokes legitimately share a second. Merging
on a non-unique key does not deduplicate; it fabricates evidence of calls that never happened.
"""
from governed_core.proofs import cloudtrail as CT

PREFIX = "pack-fp"
START, END = 1_788_788_783_602, 1_788_788_821_602
QEND = END


def iso_ms(ts):
    """Stand-in for the caller's ISO-8601 parser; the tests only need ordering and windows."""
    table = {"2026-09-07T13:46:31Z": 1_788_788_791_000,
             "2026-09-07T23:59:59Z": 1_788_838_799_000}
    return table.get(ts)


def ev(eid, name="Invoke", fn="arn:aws:lambda:us-east-1:1234:function:pack-fp-write-audit",
       src="lambda.amazonaws.com", when="2026-09-07T13:46:31Z"):
    return {"eventID": eid, "eventTime": when, "eventSource": src, "eventName": name,
            "fn": fn, "bkt": "", "who": "arn:aws:sts::1234:assumed-role/r/s", "sm": ""}


class FakeLogs:
    """Returns `filtered` for the query that carries a filter, `raw` for the unfiltered one."""

    def __init__(self, filtered, raw):
        self.filtered, self.raw, self.queries = filtered, raw, []

    def start_query(self, **kw):
        self.queries.append(kw["queryString"])
        return {"queryId": "q%d" % len(self.queries)}

    def get_query_results(self, queryId):
        rows = self.filtered if "| filter" in self.queries[int(queryId[1:]) - 1] else self.raw
        return {"status": "Complete",
                "results": [[{"field": k, "value": v} for k, v in r.items()] for r in rows]}


def _read(logs):
    return CT.read_cloudtrail_capture(logs, "/trail", PREFIX, START, END, QEND, iso_ms)


def _verify(logs, known):
    return CT.verify_cloudtrail_capture(logs, "/trail", PREFIX, START, END, known, QEND, iso_ms)


def test_two_distinct_invokes_in_the_same_second_are_both_kept():
    """The exact shape that fabricated eleven invokes when the key was a timestamp tuple."""
    rows = _read(FakeLogs([ev("id-1"), ev("id-2")], []))
    assert {r["event_id"] for r in rows} == {"id-1", "id-2"}


def test_a_repeated_eventid_is_counted_once():
    rows = _read(FakeLogs([ev("id-1"), ev("id-1")], []))
    assert [r["event_id"] for r in rows] == ["id-1"]


def test_verify_recovers_a_row_the_filtered_query_dropped():
    logs = FakeLogs([ev("id-1")], [ev("id-1"), ev("id-2")])
    known = _read(logs)
    assert len(known) == 1
    merged, recovered = _verify(logs, known)
    assert recovered == 1
    assert {r["event_id"] for r in merged} == {"id-1", "id-2"}


def test_verify_never_double_counts_what_is_already_known():
    rows = [ev("id-1"), ev("id-2")]
    logs = FakeLogs(rows, rows)
    known = _read(logs)
    merged, recovered = _verify(logs, known)
    assert recovered == 0 and len(merged) == 2


def test_verify_excludes_out_of_window_and_foreign_prefixes():
    raw = [ev("id-in"),
           ev("id-late", when="2026-09-07T23:59:59Z"),
           ev("id-other", fn="arn:aws:lambda:us-east-1:1234:function:someone-else")]
    merged, recovered = _verify(FakeLogs([], raw), [])
    assert recovered == 1
    assert [r["event_id"] for r in merged] == ["id-in"]


def test_step_functions_events_count_without_a_prefix_match():
    rows = _read(FakeLogs([ev("id-sfn", name="StartExecution", fn="",
                              src="states.amazonaws.com")], []))
    assert [r["event_id"] for r in rows] == ["id-sfn"]
