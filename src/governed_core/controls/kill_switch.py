"""kill_switch — the named, one-command CONTAINMENT control for the AgentCore agent path (core 1.8.0).

WHAT IT IS: one SSM Parameter Store flag per deployment (`/<prefix>/kill-switch`, JSON
`{"engaged": bool, "actor": "<IAM ARN>", "reason": "...", "at": <epoch>}`) that every component on the
request path reads FIRST — before tenancy, before Cedar, before masking, before budgets, before the
human sign-off gate. Containment precedes evaluation. When engaged:

  * the AgentCore Gateway REQUEST interceptor short-circuits every `tools/call` and `tools/list` with a
    403 JSON-RPC error (the target is never invoked) and writes a DENIED record into the acting
    tenant's WORM ledger — the denial is evidence;
  * every governed tool Lambda refuses at `telemetry.instrument` (defense in depth for the workflow hop,
    which has no interceptor, and for a direct invoke) by raising KillSwitchEngaged — an in-flight
    Step Functions execution stops at its next state;
  * the runtime agent refuses the session before its first model call (lib/runtime/agent.py).

DESIGN RULES (mirrors the platform reference gateway, docs/ops/KILL-SWITCH.md):
  * FAIL-CLOSED. If a configured parameter cannot be read and no fresh cached value exists, the switch is
    treated as ENGAGED (reason `unreadable`). No component ever guesses "probably fine".
  * SHORT-TTL CACHE per execution environment (KILL_SWITCH_TTL_SECONDS, default 15 s): time-to-effect is
    bounded by the TTL, Parameter Store traffic stays far under the 40 TPS default account throughput
    (each warm Lambda environment reads at most once per TTL). AWS documents caching parameter reads
    from Lambda as the cost/latency best practice (AWS Parameters and Secrets Lambda Extension, default
    TTL 300 s); the in-process cache here is the same idea with a containment-grade TTL.
  * MANY-TO-ONE. KILL_SWITCH_PARAMS is a comma-separated list: a deployment reads its own switch AND,
    optionally, the platform-wide `/aegis/kill-switch`. Engaged if ANY is engaged.
  * The switch is READ here only. State changes go through the controller (kill_switch_control.py):
    engage-only / disengage-only IAM identities (function URLs with AWS_IAM auth), the IAM-verified caller
    ARN recorded in the parameter and the WORM ledger, and separation of duties on release enforced on
    that verified identity — the engaging ARN can never disengage.

Pure stdlib + boto3 at the seam (offline unit-testable: tests stub `_ssm`)."""
import json
import os
import threading
import time

PARAMS_ENV = "KILL_SWITCH_PARAMS"          # comma-separated SSM parameter names (empty => not configured)
TTL_ENV = "KILL_SWITCH_TTL_SECONDS"
DEFAULT_TTL = 15
GUARDRAIL_ACTION = "KILL_SWITCH"           # the same guardrail_action the platform reference gateway emits
CASE_ID = "KILL-SWITCH"                    # ledger chain for state changes + denials without a case
_UNREADABLE = "unreadable"


class KillSwitchEngaged(Exception):
    """Raised by enforce() / telemetry.instrument when containment is engaged. The message is the
    customer-visible refusal; `state` carries the parsed switch record."""

    def __init__(self, state):
        self.state = state
        super().__init__("kill switch ENGAGED (%s): %s" % (state.get("source", "?"), state.get("reason", "")))


# ---- configuration --------------------------------------------------------------------------------
def configured_params():
    raw = os.environ.get(PARAMS_ENV, "")
    return [p.strip() for p in raw.split(",") if p.strip()]


def ttl_seconds():
    try:
        return max(1, int(os.environ.get(TTL_ENV, DEFAULT_TTL)))
    except ValueError:
        return DEFAULT_TTL


# ---- SSM seam + cache ------------------------------------------------------------------------------
_lock = threading.Lock()
_cache = {}          # param name -> (fetched_at, parsed dict)
_client = None


def _ssm():
    global _client
    if _client is None:
        import boto3
        _client = boto3.client("ssm", region_name=os.environ.get("AWS_REGION", "us-east-1"))
    return _client


def parse_value(raw):
    """Parse the parameter value. Accepts the JSON record or the bare words true/false/engaged/
    disengaged (an operator typing into the console still works). Unparseable => engaged (fail-closed)."""
    s = (raw or "").strip()
    if not s:
        return {"engaged": True, "reason": "empty kill-switch value (fail-closed)"}
    low = s.lower()
    if low in ("true", "engaged", "on", "1"):
        return {"engaged": True, "reason": "engaged (bare value)"}
    if low in ("false", "disengaged", "off", "0"):
        return {"engaged": False, "reason": ""}
    try:
        d = json.loads(s)
    except ValueError:
        return {"engaged": True, "reason": "unparseable kill-switch value (fail-closed)"}
    if not isinstance(d, dict) or not isinstance(d.get("engaged"), bool):
        return {"engaged": True, "reason": "malformed kill-switch record (fail-closed)"}
    return d


def _read(name, now):
    """Read one parameter through the TTL cache. Returns the parsed record (+ `source`)."""
    with _lock:
        hit = _cache.get(name)
    if hit and now - hit[0] < ttl_seconds():
        return hit[1]
    try:
        raw = _ssm().get_parameter(Name=name)["Parameter"]["Value"]
        rec = parse_value(raw)
    except Exception as exc:   # AccessDenied, ParameterNotFound, throttling, no network: FAIL-CLOSED
        rec = {"engaged": True, "reason": "%s: %s %s" % (_UNREADABLE, type(exc).__name__, exc)}
    rec = dict(rec)
    rec["source"] = name
    with _lock:
        _cache[name] = (now, rec)
    return rec


def clear_cache():
    with _lock:
        _cache.clear()


# ---- the check ------------------------------------------------------------------------------------
def state():
    """The effective switch state: the FIRST engaged record among the configured parameters, else a
    disengaged record. Not configured (no KILL_SWITCH_PARAMS) => disengaged with source 'unconfigured'
    — the CDK always sets it; the deployment tests assert it."""
    params = configured_params()
    if not params:
        return {"engaged": False, "source": "unconfigured", "reason": ""}
    now = time.time()
    last = None
    for name in params:
        rec = _read(name, now)
        if rec.get("engaged"):
            return rec
        last = rec
    return last


def check():
    """Return the engaged record, or None when calls may proceed."""
    s = state()
    return s if s.get("engaged") else None


def enforce():
    """Raise KillSwitchEngaged if engaged (the tool-Lambda / runtime entry gate)."""
    s = check()
    if s:
        raise KillSwitchEngaged(s)
    return None


def refusal(s):
    """The structured refusal every component returns/logs — never argument values, never secrets."""
    return {"refused": True, "reason": "kill_switch_engaged", "guardrail_action": GUARDRAIL_ACTION,
            "source": s.get("source"), "engaged_by": s.get("actor", ""), "engaged_reason": s.get("reason", ""),
            "engaged_at": s.get("at"), "message": "containment engaged: every agent action is refused"}


def record_denial(s, event=None, context=None, component="kill_switch"):
    """Write the DENIED record into the acting tenant's ledger + WORM vault via the canonical evidence
    writer (route_* applies: multi-tenant routing must already be bound by the caller). Never raises —
    a denial must not depend on the audit path being writable; the outcome is returned for the log."""
    try:
        import evidence
        e = event if isinstance(event, dict) else {}
        case_id = e.get("case_id")
        if not case_id:
            try:
                import telemetry
                case_id = telemetry.current().get("case_id")     # the runtime's case (baggage)
            except Exception:
                case_id = None
        rec = {"case_id": case_id or CASE_ID,
               "action": "kill_switch.deny", "phase": "DENIED", "actor": component,
               "deidentified": True,
               "payload": {"guardrail_action": GUARDRAIL_ACTION, "source": s.get("source"),
                           "engaged_by": s.get("actor", ""), "engaged_reason": s.get("reason", ""),
                           "engaged_at": s.get("at"), "tool": e.get("tool") or e.get("name") or ""}}
        return evidence.record_event(rec, context, source=component)
    except Exception as exc:
        return {"stored": False, "error": "%s: %s" % (type(exc).__name__, exc)}


def log_line(s, component, outcome="denied:kill_switch", audit=None, emit=print):
    """One structured line ("aegis": "kill_switch") for CloudWatch / trace_case."""
    line = {"aegis": "kill_switch", "ts": int(time.time() * 1000), "component": component, "outcome": outcome,
            "source": s.get("source"), "engaged_by": s.get("actor", ""), "engaged_reason": s.get("reason", "")}
    try:
        import telemetry
        line.update({k: v for k, v in telemetry.current().items() if v})
        t = telemetry._tenant()
        if t:
            line["tenant"] = t
    except Exception:
        pass
    if audit is not None:
        line["audit"] = {k: audit.get(k) for k in ("stored", "worm", "audit_id", "table", "error") if k in audit}
    emit(json.dumps(line, sort_keys=True, default=str))
    return line
