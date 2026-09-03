"""budget — the LIVE per-tenant token + USD budget meter on the AgentCore agent path (core 1.9.0, task 128).

WHAT IT IS: one DynamoDB table per deployment (`<prefix>-budgets`, partition key `budget_key` =
`<tenant>#<YYYY-MM>`) holding, per tenant per month, the running `used` tokens, `tokens_in`, `tokens_out`,
`usd_micro` (spend estimate in micro-dollars from the PINNED price table) and, optionally, per-tenant
overrides `cap_tokens` / `cap_usd_micro` / `behavior` (an operator lowers one tenant's cap with a single
PutItem — nothing redeploys). The deployment-wide defaults come from the agent manifest's `budget:` block
through the CDK (BUDGET_CAP_TOKENS, BUDGET_CAP_USD_MICRO, BUDGET_BEHAVIOR).

WHERE IT RUNS:
  * the Runtime, BEFORE every model call: reserve(tenant, estimate) — ONE conditional UpdateItem
    (`ADD used :n` with `used <= cap - :n`), so concurrent sessions can never oversell; DynamoDB serializes
    conditional writes per item. AFTER every model call: commit(tenant, usage) with the REAL Converse
    `usage` {inputTokens, outputTokens} (Bedrock Converse API reference), which replaces the estimate and
    adds the USD estimate. A tenant whose next call would breach a HARD cap is refused before the spend,
    mid-session if necessary (same stop path as the kill switch).
  * the gateway REQUEST interceptor, BEFORE every tools/call: check(tenant) — a tenant at or over its cap
    is refused at the gateway (403 + DENIED WORM record) even for tool calls that spend no tokens.
  * governed tools that call Bedrock server-side (draft_notice): commit() after their Converse.

RULES (mirroring the offline platform_core meter + the Kill Switch):
  * FAIL-CLOSED on budget: a HARD cap that cannot be evaluated (table unreadable, throttled) DENIES.
    SOFT behaviour never denies; it only flags and alerts.
  * The reservation ESTIMATE (BUDGET_RESERVE_TOKENS, default 4000) is a ceiling on what one model call may
    spend before its real usage is known; commit() corrects the meter by (actual - reserved), so the meter
    converges on the truth and the only over-count is the in-flight estimate.
  * USD is an ESTIMATE from a price table committed with the release (price_version is recorded on every
    commit and in every alarm). The financial truth is the AWS Cost and Usage Report; AWS Budgets is the
    account backstop and is NOT real-time (AWS: "updated up to three times a day ... 8-12 hours").
  * Every commit publishes CloudWatch metrics (namespace Aegis/Budget, dimension Tenant + Deployment):
    TokensUsedPct, UsdUsedPct, TokensUsed — the 60/85/100 % alarms hang off these.

Pure stdlib + boto3 at the seam (offline unit-testable: tests stub `_ddb` / `_cw`)."""
import json
import os
import threading
import time

TABLE_ENV = "BUDGET_TABLE"
CAP_TOKENS_ENV = "BUDGET_CAP_TOKENS"          # deployment default (from the manifest budget: block)
CAP_USD_MICRO_ENV = "BUDGET_CAP_USD_MICRO"    # 0 / unset => no USD cap
BEHAVIOR_ENV = "BUDGET_BEHAVIOR"              # hard | soft
RESERVE_ENV = "BUDGET_RESERVE_TOKENS"         # per-model-call reservation estimate
PRICES_ENV = "BUDGET_PRICES_JSON"             # inline JSON price table (see DEFAULT_PRICES)
DEPLOYMENT_ENV = "BUDGET_DEPLOYMENT"          # metric dimension (the stack prefix)
ALERT_STEPS = (0.6, 0.85, 1.0)
GUARDRAIL_ACTION = "BUDGET"
DEFAULT_RESERVE = 4000
MICRO = 1_000_000

# Pinned price table. usd per 1M tokens. PROVENANCE MATTERS: Anthropic models are not in the AWS Price List
# API and the Bedrock pricing page is not machine-readable, so the numbers below are pinned from the
# Anthropic platform pricing page on the stated date and MUST be confirmed against
# https://aws.amazon.com/bedrock/pricing/ for the customer's region before production. The CDK passes a
# deployment-specific table (BUDGET_PRICES_JSON) that overrides this default; its version is recorded on
# every commit so the evidence shows which prices produced which USD figure.
DEFAULT_PRICES = {
    "price_version": "anthropic-platform-2026-09-03-UNCONFIRMED-ON-BEDROCK",
    "models": {
        "anthropic.claude-sonnet-4-5": {"input_per_m": 3.0, "output_per_m": 15.0},
        "anthropic.claude-haiku-4-5": {"input_per_m": 1.0, "output_per_m": 5.0},
    },
}


class BudgetExceeded(Exception):
    """Raised by reserve()/check()/enforce() when a HARD cap refuses the call (or cannot be evaluated)."""

    def __init__(self, decision):
        self.decision = decision
        super().__init__("budget exceeded for tenant %s: %s" % (decision.get("tenant"), decision.get("reason")))


# ---- configuration --------------------------------------------------------------------------------
def _int_env(name, default):
    try:
        return int(os.environ.get(name, "") or default)
    except ValueError:
        return default


def configured():
    return bool(os.environ.get(TABLE_ENV, "").strip())


def defaults():
    return {"cap_tokens": _int_env(CAP_TOKENS_ENV, 0), "cap_usd_micro": _int_env(CAP_USD_MICRO_ENV, 0),
            "behavior": (os.environ.get(BEHAVIOR_ENV, "hard") or "hard").strip().lower(),
            "reserve": _int_env(RESERVE_ENV, DEFAULT_RESERVE)}


def prices():
    raw = os.environ.get(PRICES_ENV, "").strip()
    if raw:
        try:
            p = json.loads(raw)
            if isinstance(p, dict) and isinstance(p.get("models"), dict):
                return p
        except ValueError:
            pass
    return DEFAULT_PRICES


def period(now=None):
    return time.strftime("%Y-%m", time.gmtime(now if now is not None else time.time()))


def key(tenant, now=None):
    return "%s#%s" % (tenant or "default", period(now))


def usd_micro(model_id, usage, table=None):
    """Micro-dollars for one call from the pinned table. Unknown model => 0 with 'unpriced' flagged by the
    caller (the token cap still applies)."""
    table = table or prices()
    mid = (model_id or "").lower()
    row = None
    for name, r in table["models"].items():
        if name.lower() in mid:
            row = r
            break
    if not row:
        return 0, False
    tin = int((usage or {}).get("inputTokens", 0) or 0)
    tout = int((usage or {}).get("outputTokens", 0) or 0)
    return int(round(tin * row["input_per_m"] / 1e6 * MICRO + tout * row["output_per_m"] / 1e6 * MICRO)), True


# ---- AWS seams + caches ---------------------------------------------------------------------------
_lock = threading.Lock()
_caps_cache = {}     # budget_key -> (fetched_at, caps dict)
_ddb = None
_cw = None


def _client():
    global _ddb
    if _ddb is None:
        import boto3
        _ddb = boto3.client("dynamodb", region_name=os.environ.get("AWS_REGION", "us-east-1"))
    return _ddb


def _cloudwatch():
    global _cw
    if _cw is None:
        import boto3
        _cw = boto3.client("cloudwatch", region_name=os.environ.get("AWS_REGION", "us-east-1"))
    return _cw


def clear_cache():
    with _lock:
        _caps_cache.clear()


def _n(item, name, default=0):
    try:
        return int(item[name]["N"])
    except (KeyError, ValueError, TypeError):
        return default


def read_item(tenant, now=None):
    r = _client().get_item(TableName=os.environ[TABLE_ENV], Key={"budget_key": {"S": key(tenant, now)}},
                           ConsistentRead=True)
    return r.get("Item") or {}


def caps(tenant, now=None, ttl=30):
    """Effective caps for the tenant this period: item overrides > deployment defaults. Cached per process."""
    k = key(tenant, now)
    with _lock:
        hit = _caps_cache.get(k)
    if hit and time.time() - hit[0] < ttl:
        return hit[1]
    d = defaults()
    item = read_item(tenant, now)
    out = {"cap_tokens": _n(item, "cap_tokens", d["cap_tokens"]) if "cap_tokens" in item else d["cap_tokens"],
           "cap_usd_micro": _n(item, "cap_usd_micro", d["cap_usd_micro"]) if "cap_usd_micro" in item else d["cap_usd_micro"],
           "behavior": (item.get("behavior", {}).get("S") or d["behavior"]).lower()}
    with _lock:
        _caps_cache[k] = (time.time(), out)
    return out


# ---- the meter --------------------------------------------------------------------------------------
def _decision(tenant, allowed, reason, caps_, used=None, usd=None, extra=None):
    d = {"tenant": tenant, "allowed": allowed, "reason": reason, "behavior": caps_["behavior"],
         "cap_tokens": caps_["cap_tokens"], "cap_usd_micro": caps_["cap_usd_micro"],
         "guardrail_action": GUARDRAIL_ACTION}
    if used is not None:
        d["used_tokens"] = used
    if usd is not None:
        d["used_usd_micro"] = usd
    d.update(extra or {})
    return d


def reserve(tenant, tokens=None, now=None):
    """Before a model call: atomically add the estimate to `used` if it fits under the token cap AND the
    USD spend is still under the USD cap. Returns the decision; raises BudgetExceeded on a HARD refusal."""
    if not configured():
        return {"tenant": tenant, "allowed": True, "reason": "unconfigured", "reserved": 0}
    tokens = int(tokens if tokens is not None else defaults()["reserve"])
    try:
        c = caps(tenant, now)
    except Exception as exc:                      # caps unreadable: fail-closed for HARD, allow for SOFT
        c = dict(defaults())
        d = _decision(tenant, c["behavior"] != "hard", "budget meter unreadable (%s %s) - fail-closed" % (type(exc).__name__, exc), c,
                      extra={"reserved": 0, "soft_breach": c["behavior"] != "hard"})
        if c["behavior"] == "hard":
            raise BudgetExceeded(d)
        return d
    vals = {":n": {"N": str(tokens)}}
    if c["cap_tokens"] <= 0:                      # cap 0 = the tenant is switched off for this period
        cond = ["attribute_exists(never_true_sentinel)"]
    else:
        cond = ["(attribute_not_exists(used) OR used <= :room)"]
        vals[":room"] = {"N": str(c["cap_tokens"] - tokens)}
        if c["cap_usd_micro"] > 0:
            cond.append("(attribute_not_exists(usd_micro) OR usd_micro < :usd_cap)")
            vals[":usd_cap"] = {"N": str(c["cap_usd_micro"])}
    try:
        r = _client().update_item(TableName=os.environ[TABLE_ENV], Key={"budget_key": {"S": key(tenant, now)}},
                                  UpdateExpression="ADD used :n, reserved :n", ConditionExpression=" AND ".join(cond),
                                  ExpressionAttributeValues=vals, ReturnValues="ALL_NEW")
        it = r.get("Attributes") or {}
        return _decision(tenant, True, "reserved", c, _n(it, "used"), _n(it, "usd_micro"), {"reserved": tokens})
    except Exception as exc:
        code = getattr(exc, "response", {}).get("Error", {}).get("Code", "") if hasattr(exc, "response") else ""
        if code == "ConditionalCheckFailedException" or "ConditionalCheckFailed" in type(exc).__name__:
            reason = "cap reached: reserving %d tokens would exceed the tenant's period cap (tokens %d, usd_micro %d)" % (
                tokens, c["cap_tokens"], c["cap_usd_micro"])
        else:
            reason = "budget meter unreadable (%s %s) - fail-closed" % (type(exc).__name__, exc)
        d = _decision(tenant, c["behavior"] != "hard", reason, c, extra={"reserved": 0, "soft_breach": c["behavior"] != "hard"})
        if c["behavior"] == "hard":
            raise BudgetExceeded(d)
        return d


def commit(tenant, usage, model_id="", reserved=0, now=None, emit_metrics=True):
    """After a model call: replace the reservation with the real usage and add the USD estimate. Never
    refuses (the spend already happened) and never raises (a metering failure must not fail the call);
    returns the decision with the new totals + pct, and 'metered': False if the write failed."""
    if not configured():
        return {"tenant": tenant, "metered": False, "reason": "unconfigured"}
    tin = int((usage or {}).get("inputTokens", 0) or 0)
    tout = int((usage or {}).get("outputTokens", 0) or 0)
    total = tin + tout
    micro, priced = usd_micro(model_id, usage)
    table = prices()
    try:
        r = _client().update_item(
            TableName=os.environ[TABLE_ENV], Key={"budget_key": {"S": key(tenant, now)}},
            UpdateExpression="ADD used :delta, reserved :neg, tokens_in :tin, tokens_out :tout, usd_micro :usd, calls :one "
                             "SET price_version = :pv, model_id = :mid, updated_at = :ts",
            ExpressionAttributeValues={":delta": {"N": str(total - int(reserved))}, ":neg": {"N": str(-int(reserved))},
                                       ":tin": {"N": str(tin)}, ":tout": {"N": str(tout)}, ":usd": {"N": str(micro)},
                                       ":one": {"N": "1"}, ":pv": {"S": table["price_version"]},
                                       ":mid": {"S": model_id or ""}, ":ts": {"N": str(int(now or time.time()))}},
            ReturnValues="ALL_NEW")
        it = r.get("Attributes") or {}
    except Exception as exc:
        return {"tenant": tenant, "metered": False, "reason": "%s: %s" % (type(exc).__name__, exc),
                "tokens": total, "usd_micro": micro, "priced": priced}
    c = caps(tenant, now)
    used, usd = _n(it, "used"), _n(it, "usd_micro")
    out = {"tenant": tenant, "metered": True, "tokens": total, "usd_micro": micro, "priced": priced,
           "price_version": table["price_version"], "used_tokens": used, "used_usd_micro": usd,
           "cap_tokens": c["cap_tokens"], "cap_usd_micro": c["cap_usd_micro"], "behavior": c["behavior"],
           "pct_tokens": round(100.0 * used / c["cap_tokens"], 2) if c["cap_tokens"] > 0 else None,
           "pct_usd": round(100.0 * usd / c["cap_usd_micro"], 2) if c["cap_usd_micro"] > 0 else None}
    if emit_metrics:
        out["metrics"] = _emit(tenant, out)
    return out


def _emit(tenant, out):
    dims = [{"Name": "Tenant", "Value": tenant or "default"},
            {"Name": "Deployment", "Value": os.environ.get(DEPLOYMENT_ENV, "unknown")}]
    data = [{"MetricName": "TokensUsed", "Dimensions": dims, "Value": out["used_tokens"], "Unit": "Count"},
            {"MetricName": "UsdUsedMicro", "Dimensions": dims, "Value": out["used_usd_micro"], "Unit": "Count"}]
    if out.get("pct_tokens") is not None:
        data.append({"MetricName": "TokensUsedPct", "Dimensions": dims, "Value": out["pct_tokens"], "Unit": "Percent"})
    if out.get("pct_usd") is not None:
        data.append({"MetricName": "UsdUsedPct", "Dimensions": dims, "Value": out["pct_usd"], "Unit": "Percent"})
    try:
        _cloudwatch().put_metric_data(Namespace="Aegis/Budget", MetricData=data)
        return {"published": len(data)}
    except Exception as exc:
        return {"published": 0, "error": type(exc).__name__}


def check(tenant, now=None):
    """Gateway-side: refuse a tenant AT or OVER its cap (or switched off). Returns None when calls may
    proceed; raises BudgetExceeded for a HARD refusal; returns a soft-breach decision otherwise."""
    if not configured():
        return None
    try:
        c = caps(tenant, now)
        it = read_item(tenant, now)
    except Exception as exc:
        d = {"tenant": tenant, "allowed": False, "reason": "budget meter unreadable (%s) - fail-closed" % type(exc).__name__,
             "behavior": defaults()["behavior"], "guardrail_action": GUARDRAIL_ACTION}
        if d["behavior"] == "hard":
            raise BudgetExceeded(d)
        return d
    used, usd = _n(it, "used"), _n(it, "usd_micro")
    over = c["cap_tokens"] <= 0 or used >= c["cap_tokens"] or (c["cap_usd_micro"] > 0 and usd >= c["cap_usd_micro"])
    if not over:
        return None
    d = _decision(tenant, c["behavior"] != "hard", "tenant is at/over its period cap (used %d/%d tokens, %d/%d usd_micro)" % (
        used, c["cap_tokens"], usd, c["cap_usd_micro"]), c, used, usd, {"soft_breach": c["behavior"] != "hard"})
    if c["behavior"] == "hard":
        raise BudgetExceeded(d)
    return d


def status(tenant, now=None):
    c = caps(tenant, now)
    it = read_item(tenant, now)
    used, usd = _n(it, "used"), _n(it, "usd_micro")
    return {"tenant": tenant, "period": period(now), "used_tokens": used, "tokens_in": _n(it, "tokens_in"),
            "tokens_out": _n(it, "tokens_out"), "reserved": _n(it, "reserved"), "calls": _n(it, "calls"),
            "used_usd_micro": usd, "used_usd": round(usd / MICRO, 6), "price_version": it.get("price_version", {}).get("S"),
            "cap_tokens": c["cap_tokens"], "cap_usd_micro": c["cap_usd_micro"], "behavior": c["behavior"],
            "pct_tokens": round(100.0 * used / c["cap_tokens"], 2) if c["cap_tokens"] > 0 else None,
            "pct_usd": round(100.0 * usd / c["cap_usd_micro"], 2) if c["cap_usd_micro"] > 0 else None}


def refusal(decision):
    return {"refused": True, "reason": "budget_exceeded", "guardrail_action": GUARDRAIL_ACTION,
            "tenant": decision.get("tenant"), "detail": decision.get("reason"), "cap_tokens": decision.get("cap_tokens"),
            "cap_usd_micro": decision.get("cap_usd_micro"), "behavior": decision.get("behavior"),
            "message": "budget exceeded: this tenant's period cap is reached; the call is refused (hard cap)"}


def record_denial(decision, event=None, context=None, component="budget"):
    """DENIED record in the acting tenant's ledger + WORM vault via the canonical writer. Never raises."""
    try:
        import evidence
        e = event if isinstance(event, dict) else {}
        case_id = e.get("case_id")
        if not case_id:
            try:
                import telemetry
                case_id = telemetry.current().get("case_id")
            except Exception:
                case_id = None
        rec = {"case_id": case_id or "BUDGET", "action": "budget.deny", "phase": "DENIED", "actor": component,
               "deidentified": True,
               "payload": {"guardrail_action": GUARDRAIL_ACTION, "detail": decision.get("reason"),
                           "cap_tokens": decision.get("cap_tokens"), "cap_usd_micro": decision.get("cap_usd_micro"),
                           "used_tokens": decision.get("used_tokens"), "used_usd_micro": decision.get("used_usd_micro"),
                           "behavior": decision.get("behavior"), "tool": e.get("tool") or ""}}
        return evidence.record_event(rec, context, source=component)
    except Exception as exc:
        return {"stored": False, "error": "%s: %s" % (type(exc).__name__, exc)}


def log_line(decision, component, outcome="denied:budget", audit=None, emit=print):
    line = {"aegis": "budget", "ts": int(time.time() * 1000), "component": component, "outcome": outcome,
            "tenant": decision.get("tenant"), "detail": decision.get("reason"),
            "cap_tokens": decision.get("cap_tokens"), "used_tokens": decision.get("used_tokens")}
    try:
        import telemetry
        line.update({k: v for k, v in telemetry.current().items() if v})
    except Exception:
        pass
    if audit is not None:
        line["audit"] = {k: audit.get(k) for k in ("stored", "worm", "audit_id", "table", "error") if k in audit}
    emit(json.dumps(line, sort_keys=True, default=str))
    return line
