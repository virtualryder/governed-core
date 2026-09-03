"""tenant_interceptor — AgentCore Gateway REQUEST interceptor (phase 107, hybrid multi-tenant routing).

WHY THIS EXISTS: AgentCore Gateway does NOT forward the caller's JWT claims to a Lambda target (the
target gets only tool args + gateway metadata), so a tool Lambda cannot derive the tenant from the claim.
This interceptor runs AFTER inbound auth (the gateway has already validated the JWT) and BEFORE the
target: it reads the validated bearer from the passed request headers (passRequestHeaders=true),
extracts custom:tenant, and INJECTS it into the tool arguments as a reserved, HMAC-SIGNED pair
(tenancy.TENANT_FIELD / TENANT_SIG_FIELD). The target verifies the signature before trusting it, so a
caller/model-supplied tenant is refused even if this interceptor were bypassed — "tenant is DERIVED,
never REQUESTED" holds end to end. Any caller-supplied value of the reserved fields is OVERWRITTEN.

FAIL-CLOSED: in multi-tenant mode a tools/call with no tenant on the identity is DENIED (403) and the
target is never invoked. tools/list and other methods pass through unchanged. Silo mode injects nothing.

Contract: AgentCore interceptor input/output v1.0. Pure stdlib; offline unit-testable."""
import json
import os

import budget
import kill_switch
import telemetry
import tenancy

_TOOLS_CALL = "tools/call"
_CONTAINED = ("tools/call", "tools/list")       # what the kill switch short-circuits (initialize passes)


def _bearer(headers):
    for k, v in (headers or {}).items():
        if str(k).lower() == "authorization" and isinstance(v, str):
            return v[7:] if v.lower().startswith("bearer ") else v
    return ""


def _pass_through(body):
    return {"interceptorOutputVersion": "1.0",
            "mcp": {"transformedGatewayRequest": {"body": body}}}


def _deny(rid, message):
    return {"interceptorOutputVersion": "1.0",
            "mcp": {"transformedGatewayResponse": {
                "statusCode": 403,
                "body": {"jsonrpc": "2.0", "id": rid,
                         "error": {"code": -32000, "message": message}}}}}


def _audit_denial(engaged, gw, body, context):
    """Bind the VERIFIED tenant (from the validated bearer) so the denial routes to that tenant's
    ledger, write it, log it. Never raises; an unwritable ledger is reported in the log line."""
    params = body.get("params") or {}
    args = params.get("arguments") or {}
    meta = {k: v for k, v in (params.get("_meta") or {}).items() if isinstance(v, str)}
    try:
        telemetry.bind({telemetry.TRACE_FIELD: json.dumps(
            telemetry.from_headers({**(gw.get("headers") or {}), **meta}))}, context)
    except Exception:
        pass
    tenant = tenancy.tenant_from_bearer(_bearer(gw.get("headers")))
    tenancy.set_request_claims({tenancy._CLAIM: tenant} if tenant else None)
    try:
        ev = {"case_id": args.get("case_id") if isinstance(args.get("case_id"), str) else None,
              "tool": (params.get("name") or body.get("method") or "")}
        audit = kill_switch.record_denial(engaged, ev, context, component="interceptor")
        kill_switch.log_line(engaged, component="interceptor", audit=audit)
    finally:
        tenancy.clear_request_claims()
        telemetry.clear()


def _audit_budget_denial(decision, gw, body, context, tenant):
    params = body.get("params") or {}
    args = params.get("arguments") or {}
    meta = {k: v for k, v in (params.get("_meta") or {}).items() if isinstance(v, str)}
    try:
        telemetry.bind({telemetry.TRACE_FIELD: json.dumps(
            telemetry.from_headers({**(gw.get("headers") or {}), **meta}))}, context)
    except Exception:
        pass
    tenancy.set_request_claims({tenancy._CLAIM: tenant} if tenant else None)
    try:
        ev = {"case_id": args.get("case_id") if isinstance(args.get("case_id"), str) else None,
              "tool": (params.get("name") or "")}
        audit = budget.record_denial(decision, ev, context, component="interceptor")
        budget.log_line(decision, component="interceptor", audit=audit)
    finally:
        tenancy.clear_request_claims()
        telemetry.clear()


def build_output(event, secret, multitenant, context=None):
    """Pure core. Returns the interceptor output for one gateway request."""
    gw = ((event or {}).get("mcp") or {}).get("gatewayRequest") or {}
    body = gw.get("body") or {}
    rid = body.get("id", 1)
    method = body.get("method")
    # core 1.8.0: CONTAINMENT FIRST. The kill switch is checked before tenancy, before the target,
    # before anything else: engaged => 403 to the caller (the gateway never invokes the target) and a
    # DENIED record in the acting tenant's WORM ledger. Fail-closed on an unreadable switch.
    if method in _CONTAINED:
        engaged = kill_switch.check()
        if engaged:
            _audit_denial(engaged, gw, body, context)
            return _deny(rid, "containment engaged (kill switch %s): every agent action is refused"
                         % engaged.get("source", ""))
    if method != _TOOLS_CALL:
        return _pass_through(body)                 # nothing to inject
    tenant = tenancy.tenant_from_bearer(_bearer(gw.get("headers")))
    if not tenant and multitenant:
        return _deny(rid, "multi-tenant: identity carries no tenant (custom:tenant); refused")
    # core 1.9.0 (task 128): a tenant AT or OVER its period budget is refused at the gateway too (tool calls
    # that spend no tokens included) - 403 + DENIED record in that tenant's ledger. HARD caps only; a SOFT
    # breach is logged and the call proceeds. Silo deployments meter the pinned TENANT_ID.
    metered = tenant if multitenant else (tenant or tenancy.resolve_tenant())
    try:
        soft = budget.check(metered)
        if soft:
            budget.log_line(soft, component="interceptor", outcome="soft_breach:budget")
    except budget.BudgetExceeded as exc:
        _audit_budget_denial(exc.decision, gw, body, context, tenant)
        return _deny(rid, "budget exceeded (%s): the tenant's period cap is reached; refused"
                     % exc.decision.get("tenant"))
    except Exception as exc:                       # never let metering break the request path
        print(json.dumps({"aegis": "budget", "component": "interceptor", "outcome": "check_error:" + type(exc).__name__}))
    params = dict(body.get("params") or {})
    args = dict(params.get("arguments") or {})
    args.pop(tenancy.TENANT_FIELD, None)           # OVERWRITE anything the caller/model supplied
    args.pop(tenancy.TENANT_SIG_FIELD, None)
    args.pop(telemetry.TRACE_FIELD, None)
    if tenant:                                     # silo identities carry no tenant: no injection
        args[tenancy.TENANT_FIELD] = tenant
        args[tenancy.TENANT_SIG_FIELD] = tenancy.sign_tenant(tenant, secret)
    # phase 110: correlation keys from the headers ADOT/AgentCore put on the runtime's outbound call
    # (traceparent / X-Amzn-Trace-Id, baggage session.id, mcp-session-id). Observability only —
    # the tenant above stays the sole signed, trusted field.
    # The MCP client (Strands/mcp SDK) propagates the OTEL context in `params._meta` (traceparent,
    # X-Amzn-Trace-Id, baggage) - seen live 2026-09-02: the gateway forwards it verbatim - so read
    # both the HTTP headers and `_meta`; `_meta` wins (it is what the runtime's own span injected).
    meta = {k: v for k, v in (params.get("_meta") or {}).items() if isinstance(v, str)}
    trace = telemetry.from_headers({**(gw.get("headers") or {}), **meta})
    trace.pop("baggage_tenant", None)
    if trace:
        args[telemetry.TRACE_FIELD] = json.dumps(trace, sort_keys=True)
    params["arguments"] = args
    new_body = dict(body)
    new_body["params"] = params
    return _pass_through(new_body)


def handler(event, context):
    # Same trust domain + resolver as mask_pii's sanitized_ref signing (Secrets Manager ARN in
    # pilot/production; plaintext env only for disposable sandbox validation).
    try:
        import provenance
        secret = provenance._secret()
    except Exception:
        secret = (os.environ.get("PROVENANCE_SECRET") or "").encode("utf-8")
    return build_output(event, secret, tenancy.multitenant_enabled(), context)
