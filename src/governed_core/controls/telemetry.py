"""telemetry.py — request-scoped CORRELATION context (phase 110: full transparency).

THE GAP THIS CLOSES: every signal already existed — AgentCore Runtime spans (the model's reasoning and
every tool call, keyed by session.id / traceId), the Gateway's vended request logs, Bedrock model-
invocation logs (the exact request/response bodies), each tool Lambda's log, the Step Functions
execution, and the hash-chained WORM record — but none of them carried the others' keys, so "show me
everything that touched this case, in this tenant" was a manual reconstruction. This module carries ONE
correlation set through every hop and stamps it on every row the platform writes:

  tenant · session_id · trace_id/span_id · mcp_session_id · execution_arn · request_id · case_id

How it arrives at a tool Lambda (all DERIVED at a trusted boundary, never typed by the model/caller):
  * gateway hop — the REQUEST interceptor (tenant_interceptor.py) reads the request headers ADOT put on
    the runtime's outbound MCP call (`traceparent` / `X-Amzn-Trace-Id`, `baggage: session.id=…`,
    `mcp-session-id`) and injects them as the reserved `__aegis_trace` argument (JSON string);
  * workflow hop — every Lambda payload carries `__aegis_execution` = $$.Execution.Id;
  * the Lambda itself — aws_request_id from the context, _X_AMZN_TRACE_ID from the environment.
`__aegis_trace` is OBSERVABILITY context, not authorization: the tenant remains the only signed, trusted
field (tenancy.py). A forged trace id can only mis-file a row's correlation, never widen access.

What consumes it:
  * evidence.build_logical -> `correlation` (stable keys, hashed into audit_id) and build_record ->
    `invocation` (per-invocation keys, in the chain hash) — the WORM row proves its own join keys;
  * instrument()/log_call() -> ONE structured JSON line per tool invocation (`"aegis": "call"`) with the
    same keys, the tool name, a digest of the (reserved-field-stripped) arguments and the outcome — every
    API call the platform makes is visible in CloudWatch under the same keys, per tenant.
Pure stdlib; offline-testable."""
import contextvars
import functools
import hashlib
import json
import os
import re
import time

TRACE_FIELD = "__aegis_trace"          # injected by the gateway interceptor (JSON string or dict)
EXEC_FIELD = "__aegis_execution"       # injected by the workflow: $$.Execution.Id
RESERVED = (TRACE_FIELD, EXEC_FIELD, "__aegis_tenant", "__aegis_tenant_sig")
STABLE_KEYS = ("trace_id", "session_id", "mcp_session_id", "execution_arn")   # same across a retry
INVOCATION_KEYS = ("span_id", "request_id")                                    # per invocation

_CTX = contextvars.ContextVar("aegis_correlation", default=None)
_TRACEPARENT = re.compile(r"^[0-9a-f]{2}-([0-9a-f]{32})-([0-9a-f]{16})-[0-9a-f]{2}$")
_XRAY_ROOT = re.compile(r"Root=1-([0-9a-f]{8})-([0-9a-f]{24})")
_XRAY_PARENT = re.compile(r"Parent=([0-9a-f]{16})")


def parse_traceparent(value):
    """W3C traceparent -> (trace_id, span_id) or (None, None)."""
    m = _TRACEPARENT.match((value or "").strip().lower())
    return (m.group(1), m.group(2)) if m else (None, None)


def parse_xray(value):
    """X-Amzn-Trace-Id 'Root=1-<8hex>-<24hex>;Parent=<16hex>;Sampled=1' -> (trace_id as the 32-hex W3C
    form ADOT uses, parent span id or None). (None, None) if absent."""
    v = (value or "").strip()
    m = _XRAY_ROOT.search(v)
    if not m:
        return None, None
    p = _XRAY_PARENT.search(v)
    return m.group(1) + m.group(2), (p.group(1) if p else None)


def _baggage(value):
    out = {}
    for part in (value or "").split(","):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip()] = v.strip().split(";")[0]
    return out


def from_headers(headers):
    """Correlation keys from an inbound HTTP request's headers (the gateway interceptor sees the
    runtime's outbound MCP call). Case-insensitive. Only non-empty keys are returned."""
    h = {str(k).lower(): v for k, v in (headers or {}).items()}
    out = {}
    tid, sid = parse_traceparent(h.get("traceparent"))
    if not tid:
        tid, sid = parse_xray(h.get("x-amzn-trace-id"))
    if tid:
        out["trace_id"] = tid
    if sid:
        out["span_id"] = sid
    bag = _baggage(h.get("baggage"))
    session = (h.get("x-amzn-bedrock-agentcore-runtime-session-id") or bag.get("session.id") or "").strip()
    if session:
        out["session_id"] = session
    if bag.get("tenant"):
        out["baggage_tenant"] = bag["tenant"]     # informational only; NEVER used for routing
    if bag.get("case_id"):
        out["case_id"] = bag["case_id"]           # the runtime's case (tool args often carry none)
    mcp = (h.get("mcp-session-id") or "").strip()
    if mcp:
        out["mcp_session_id"] = mcp
    return out


def _coerce(event):
    e = event or {}
    if isinstance(e, str):
        try:
            e = json.loads(e)
        except Exception:
            e = {}
    return e if isinstance(e, dict) else {}


def bind(event, context=None):
    """Lambda-entry: build the request-scoped correlation context from the event's reserved fields,
    the Lambda context and the environment. Returns the dict (also readable via current())."""
    e = _coerce(event)
    ctx = {}
    raw = e.get(TRACE_FIELD)
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except Exception:
            raw = {}
    if isinstance(raw, dict):
        for k in ("trace_id", "span_id", "session_id", "mcp_session_id", "case_id"):
            v = raw.get(k)
            if isinstance(v, str) and v.strip():
                ctx[k] = v.strip()
    if not ctx.get("trace_id"):
        tid, _ = parse_xray(os.environ.get("_X_AMZN_TRACE_ID", ""))
        if tid:
            ctx["trace_id"] = tid
    ex = e.get(EXEC_FIELD)
    if isinstance(ex, str) and ex.strip():
        ctx["execution_arn"] = ex.strip()
    rid = getattr(context, "aws_request_id", None)
    if rid:
        ctx["request_id"] = str(rid)
    cid = e.get("case_id") or e.get("icsr_id")
    if isinstance(cid, str) and cid.strip():
        ctx["case_id"] = cid.strip()              # the tool's own case id wins over the baggage one
    _CTX.set(ctx)
    return ctx


def current():
    return dict(_CTX.get() or {})


def clear():
    _CTX.set(None)


def _tenant():
    """The DERIVED tenant for tagging: the request-bound one in multi-tenant mode, else the pinned silo
    id. Never raises (tagging must not change control flow)."""
    try:
        import tenancy
        if tenancy.multitenant_enabled():
            try:
                return tenancy.resolve_tenant()
            except Exception:
                return None
        return os.environ.get("TENANT_ID") or tenancy.DEFAULT_TENANT
    except ImportError:
        return os.environ.get("TENANT_ID") or "default"


def correlation_for_record():
    """The STABLE join keys (+ tenant) to hash into a WORM record. Empty values omitted."""
    c = current()
    out = {k: c[k] for k in STABLE_KEYS if c.get(k)}
    t = _tenant()
    if t:
        out["tenant"] = t
    return out


def invocation_for_record():
    c = current()
    return {k: c[k] for k in INVOCATION_KEYS if c.get(k)}


def args_digest(event):
    """sha256 over the canonical arguments with the reserved fields stripped — lets a reviewer match a
    log line to a gateway row / evidence payload without the log ever carrying the (possibly raw) args."""
    e = {k: v for k, v in _coerce(event).items() if k not in RESERVED}
    return hashlib.sha256(json.dumps(e, sort_keys=True, separators=(",", ":"), default=str)
                          .encode("utf-8")).hexdigest()


def _outcome(out):
    if not isinstance(out, dict):
        return "ok"
    for k in ("stored", "approved", "committed", "requested", "registered", "ingested", "deidentified", "ok"):
        if k in out:
            return "%s=%s" % (k, out[k])
    if out.get("error"):
        return "error"
    return "ok"


def log_call(tool, event, outcome, duration_ms=None, emit=print):
    """Emit ONE structured JSON line for this invocation ("aegis": "call") — CloudWatch-searchable by
    every correlation key. Never includes argument values."""
    e = _coerce(event)
    line = {"aegis": "call", "ts": int(time.time() * 1000), "tool": tool, "outcome": outcome,
            "tenant": _tenant(), "arg_keys": sorted(k for k in e if k not in RESERVED),
            "args_sha256": args_digest(e)}
    line.update({k: v for k, v in current().items() if v})
    if duration_ms is not None:
        line["duration_ms"] = int(duration_ms)
    emit(json.dumps(line, sort_keys=True, default=str))
    return line


def instrument(tool):
    """Handler decorator: bind the correlation context, run, log ONE aegis.call line (also on
    exception, then re-raise), clear. Tenant binding stays the handler's own first line."""
    def deco(fn):
        @functools.wraps(fn)
        def wrapped(event, context=None):
            bind(event, context)
            t0 = time.time()
            try:
                out = fn(event, context)
            except Exception as exc:
                log_call(tool, event, "exception:" + type(exc).__name__, (time.time() - t0) * 1000)
                clear()
                raise
            log_call(tool, event, _outcome(out), (time.time() - t0) * 1000)
            clear()
            return out
        return wrapped
    return deco
