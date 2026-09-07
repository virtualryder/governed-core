"""Shared proof primitives — the readers every pack's governance proofs depend on.

Why this package exists (PAR-4). Until now each pack carried its own copy of the log readers, and
the copies drifted: on 2026-09-07 the benefits pack was three fixes ahead of pharmacovigilance and
EDU, which still contained defects that had already produced false gate failures elsewhere. Parity
was being measured on CONTROLS while the code that VERIFIES the controls was forked four ways.

Five of that campaign's findings were cases where the platform was right and the proof was wrong
(L25, L29, L31, L33, L33b). Every one of them lived in this kind of code. Versioning it with the
wheel means a fix lands once and reaches every pack that pins the version, and means these readers
get the same review discipline as the controls they check.

Design rules for anything added here:

  * Read with the plainest API that answers the question. CloudWatch Logs Insights silently drops
    rows for `like` filters (L33), so predicates belong in Python where they can be unit-tested,
    not in a query language whose optimizer cannot be inspected.
  * Never swallow an error into an empty result. A truncated read of audit lines is indistinguishable
    from a governed tool that never audited itself (L33b). Retry what is retryable; raise the rest.
  * Identity comes from the source's own unique id, never a reconstructed tuple. Merging CloudTrail
    events on (eventTime, name, target) fabricated eleven invokes that never happened, because
    eventTime is second-granular (L34/L21c).
  * A fix to one side of a two-sided comparison is not a fix (L21e).
"""
from governed_core.proofs.logs import (  # noqa: F401
    insights_query,
    parse_json_message,
    read_lambda_calls,
    window_ms,
    scan_log_events,
)
from governed_core.proofs.cloudtrail import (  # noqa: F401
    read_cloudtrail_capture,
    verify_cloudtrail_capture,
)

__all__ = [
    "insights_query", "parse_json_message", "read_lambda_calls", "scan_log_events",
    "window_ms",
    "read_cloudtrail_capture", "verify_cloudtrail_capture",
]
