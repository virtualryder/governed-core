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

import telemetry
import tenancy

_TOOLS_CALL = "tools/call"


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


def build_output(event, secret, multitenant):
    """Pure core. Returns the interceptor output for one gateway request."""
    gw = ((event or {}).get("mcp") or {}).get("gatewayRequest") or {}
    body = gw.get("body") or {}
    rid = body.get("id", 1)
    if body.get("method") != _TOOLS_CALL:
        return _pass_through(body)                 # nothing to inject
    tenant = tenancy.tenant_from_bearer(_bearer(gw.get("headers")))
    if not tenant and multitenant:
        return _deny(rid, "multi-tenant: identity carries no tenant (custom:tenant); refused")
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
    trace = telemetry.from_headers(gw.get("headers"))
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
    return build_output(event, secret, tenancy.multitenant_enabled())
