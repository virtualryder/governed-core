"""governed-core 1.10.1 — the gateway interceptor makes the Cedar authorization-context fields
AUTHORITATIVE (deep-dive critical blocker #3).

The prior interceptor injected the signed tenant but forwarded consent / purpose / budget_ok /
within_service_window unchanged from the caller, so the "nine-condition" Cedar model trusted caller
assertions. Now a caller-supplied value of any reserved field is STRIPPED, and the interceptor injects
only values it can vouch for (server clock, live meter, optional pack resolver). consent/purpose without
an authoritative resolver stay UNSET so Cedar denies (fail-closed).

Offline: kill_switch, tenancy and budget are stubbed at the module seam (no AWS).
"""
import sys
import types

import governed_core  # noqa: F401  (installs the flat-import path the handlers use)
import tenant_interceptor as ti  # noqa: E402
import tenancy  # noqa: E402
import budget  # noqa: E402
import kill_switch  # noqa: E402


class _Ctx:
    invoked_function_arn = "arn:aws:lambda:us-east-1:123456789012:function:x"


def _event(args):
    return {"mcp": {"gatewayRequest": {
        "headers": {"authorization": "Bearer x"},
        "body": {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                 "params": {"name": "assess_eligibility", "arguments": args}}}}}


def _args(out):
    return out["mcp"]["transformedGatewayRequest"]["body"]["params"]["arguments"]


def _wire(monkeypatch, tenant="cw-a"):
    monkeypatch.setattr(kill_switch, "check", lambda: None)
    monkeypatch.setattr(tenancy, "tenant_from_bearer", lambda b: tenant)
    monkeypatch.setattr(tenancy, "sign_tenant", lambda t, s: "sig(%s)" % t)
    monkeypatch.setattr(budget, "check", lambda t: None)            # no soft breach
    for v in ("SERVICE_WINDOW_START", "SERVICE_WINDOW_END", "SERVICE_WINDOW_DAYS"):
        monkeypatch.delenv(v, raising=False)
    sys.modules.pop("authoritative_context", None)


def test_caller_context_fields_are_stripped_and_not_trusted(monkeypatch):
    _wire(monkeypatch)
    caller = {"case_id": "C1", "consent": True, "purpose": "marketing",
              "budget_ok": True, "within_service_window": True}
    args = _args(ti.build_output(_event(caller), b"secret", True, _Ctx()))
    assert "consent" not in args and "purpose" not in args         # no resolver -> unset -> Cedar denies
    assert args["budget_ok"] is True                               # authoritative (meter), not caller echo
    assert "within_service_window" not in args                     # unconfigured -> not asserted, caller stripped
    assert args[tenancy.TENANT_FIELD] == "cw-a"                    # tenant still injected + signed


def test_service_window_open_overrides_caller_false(monkeypatch):
    _wire(monkeypatch)
    monkeypatch.setenv("SERVICE_WINDOW_START", "0")
    monkeypatch.setenv("SERVICE_WINDOW_END", "24")                 # 00:00-24:00 UTC: always open
    args = _args(ti.build_output(_event({"case_id": "C1", "within_service_window": False}), b"s", True, _Ctx()))
    assert args["within_service_window"] is True


def test_service_window_closed_overrides_caller_true(monkeypatch):
    _wire(monkeypatch)
    monkeypatch.setenv("SERVICE_WINDOW_START", "0")
    monkeypatch.setenv("SERVICE_WINDOW_END", "0")                  # empty window: always closed
    args = _args(ti.build_output(_event({"case_id": "C1", "within_service_window": True}), b"s", True, _Ctx()))
    assert args["within_service_window"] is False


def test_pack_resolver_supplies_authoritative_consent_and_purpose(monkeypatch):
    _wire(monkeypatch)
    mod = types.ModuleType("authoritative_context")
    mod.resolve = lambda args, tenant: {"consent": True, "purpose": "eligibility"}
    monkeypatch.setitem(sys.modules, "authoritative_context", mod)
    caller = {"case_id": "C1", "consent": False, "purpose": "marketing"}
    args = _args(ti.build_output(_event(caller), b"s", True, _Ctx()))
    assert args["consent"] is True and args["purpose"] == "eligibility"   # authoritative wins over caller
