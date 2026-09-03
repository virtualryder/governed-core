"""governed-core 1.8.0 — the Kill Switch on the AgentCore agent path (task 127).

Proves, offline (SSM + ledger stubbed at the module seams, no AWS):
  (a) not configured => disengaged; configured + disengaged record => calls proceed;
  (b) engaged => the interceptor short-circuits tools/call AND tools/list with a 403 JSON-RPC error and
      writes a DENIED record into the ACTING tenant's ledger (multi-tenant routing), never the base one;
      initialize passes through;
  (c) engaged => telemetry.instrument refuses BEFORE the handler runs (KillSwitchEngaged; handler not
      called; one aegis.call line with outcome denied:kill_switch);
  (d) FAIL-CLOSED: unreadable parameter (AccessDenied / not found / throttled), empty or malformed value
      => engaged; a bare "true"/"false" value is honoured;
  (e) many-to-one: the platform-wide switch engages the deployment even when its own is disengaged;
  (f) the TTL cache bounds time-to-effect: a change is seen after the TTL, and one warm environment
      reads at most once per TTL;
  (g) controller: the actor is the IAM-verified caller (no identity => 401, never a body field);
      engage writes the record + a COMMITTED ledger entry under platform scope (BASE ledger in
      multi-tenant mode); disengage by the SAME identity (exact ARN, or same assumed role) => 403 +
      DENIED record and the switch STAYS engaged; a different identity releases it (COMMITTED);
  (h) the platform scope can never be injected through tool arguments, even correctly signed.
"""
import json
import types

import pytest

import governed_core  # noqa: F401
import evidence  # noqa: E402
import kill_switch  # noqa: E402
import kill_switch_control  # noqa: E402
import telemetry  # noqa: E402
import tenancy  # noqa: E402
import tenant_interceptor  # noqa: E402

SECRET = b"unit-test-secret"
DEPLOY = "/ben-x-eligibility/kill-switch"
GLOBAL = "/aegis/kill-switch"


class _Ctx:
    invoked_function_arn = "arn:aws:lambda:us-east-1:123456789012:function:x"
    aws_request_id = "req-1"


class _FakeSsm:
    """Parameter Store stub. `fail` maps a name to an exception to raise on read."""

    def __init__(self, values=None):
        self.values, self.fail, self.reads = dict(values or {}), {}, []

    def get_parameter(self, Name):
        self.reads.append(Name)
        if Name in self.fail:
            raise self.fail[Name]
        if Name not in self.values:
            raise RuntimeError("ParameterNotFound")
        return {"Parameter": {"Value": self.values[Name]}}

    def put_parameter(self, Name, Value, Type, Overwrite):
        assert Overwrite and Type == "String"
        self.values[Name] = Value


def _rec(engaged, actor="arn:aws:iam::123456789012:user/alice", reason="drill", at=1):
    return json.dumps({"engaged": engaged, "actor": actor, "reason": reason, "at": at})


# ---- ledger stub (same shape as test_tenant_routing) ------------------------------------------
class _FakeTable:
    def __init__(self, name, store):
        self.name, self.store = name, store

    def get_item(self, Key):
        it = self.store.get(self.name, {}).get(Key["audit_id"])
        if it is None:
            return {}
        from boto3.dynamodb.types import TypeDeserializer          # rows are stored in wire form
        d = TypeDeserializer().deserialize
        return {"Item": {k: d(v) for k, v in it.items()}}


class _FakeDdbRes:
    def __init__(self, store):
        self.store = store

    def Table(self, name):
        return _FakeTable(name, self.store)


class _FakeDdbCli:
    def __init__(self, store):
        self.store = store

    def transact_write_items(self, TransactItems):
        for it in TransactItems:
            p = it["Put"]
            self.store.setdefault(p["TableName"], {})[p["Item"]["audit_id"]["S"]] = p["Item"]


class _FakeS3:
    def __init__(self, puts):
        self.puts = puts

    def put_object(self, Bucket, Key, Body, ContentType):
        self.puts.append((Bucket, Key, json.loads(Body)))


@pytest.fixture
def env(monkeypatch):
    ssm = _FakeSsm({DEPLOY: _rec(False)})
    store, puts = {}, []
    monkeypatch.setattr(kill_switch, "_ssm", lambda: ssm)
    monkeypatch.setattr(evidence, "_clients", lambda region: (_FakeDdbRes(store), _FakeDdbCli(store), _FakeS3(puts)))
    monkeypatch.setenv(kill_switch.PARAMS_ENV, DEPLOY)
    monkeypatch.setenv(kill_switch.TTL_ENV, "15")
    monkeypatch.setenv("AUDIT_TABLE", "ben-x-audit-ledger")
    monkeypatch.setenv("AUDIT_BUCKET", "ben-x-worm-123456789012")
    monkeypatch.setenv("PROVENANCE_SECRET", SECRET.decode())
    monkeypatch.delenv("MULTITENANT", raising=False)
    monkeypatch.delenv("WORM_BUCKET_TEMPLATE", raising=False)
    kill_switch.clear_cache()
    tenancy.clear_request_claims()
    telemetry.clear()
    yield types.SimpleNamespace(ssm=ssm, store=store, puts=puts)
    kill_switch.clear_cache()
    tenancy.clear_request_claims()
    telemetry.clear()


def _bearer_for(tenant):
    """An UNSIGNED JWT whose payload carries the tenant group (tenant_from_bearer only decodes here;
    the gateway has already validated the signature before the interceptor runs)."""
    import base64
    def b64(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    return "%s.%s.sig" % (b64({"alg": "RS256"}), b64({"cognito:groups": ["benefits_caseworker", "tenant_" + tenant],
                                                      "sub": "u-1"}))


def _gw_event(method, tenant="cw-a", args=None):
    return {"mcp": {"gatewayRequest": {
        "headers": {"Authorization": "Bearer " + _bearer_for(tenant)},
        "body": {"jsonrpc": "2.0", "id": 7, "method": method,
                 "params": {"name": "assess-eligibility___assess",
                            "arguments": {"case_id": "C-9"} if args is None else args}}}}}


# ---- (a) -------------------------------------------------------------------------------------
def test_unconfigured_and_disengaged_let_calls_proceed(env, monkeypatch):
    monkeypatch.delenv(kill_switch.PARAMS_ENV)
    assert kill_switch.state() == {"engaged": False, "source": "unconfigured", "reason": ""}
    assert kill_switch.check() is None
    monkeypatch.setenv(kill_switch.PARAMS_ENV, DEPLOY)
    assert kill_switch.check() is None
    out = tenant_interceptor.build_output(_gw_event("tools/call"), SECRET, False)
    assert "transformedGatewayRequest" in out["mcp"] and "transformedGatewayResponse" not in out["mcp"]


# ---- (b) interceptor ---------------------------------------------------------------------------
def test_engaged_interceptor_denies_and_audits_in_the_tenant_ledger(env, monkeypatch):
    monkeypatch.setenv("MULTITENANT", "1")
    monkeypatch.setenv("WORM_BUCKET_TEMPLATE", "ben-x-{tenant}-worm-123456789012")
    env.ssm.values[DEPLOY] = _rec(True, reason="SEV-1 drill")
    for method in ("tools/call", "tools/list"):
        out = tenant_interceptor.build_output(_gw_event(method, tenant="cw-b"), SECRET, True, _Ctx())
        resp = out["mcp"]["transformedGatewayResponse"]
        assert resp["statusCode"] == 403
        assert resp["body"]["error"]["code"] == -32000 and "containment engaged" in resp["body"]["error"]["message"]
        assert "transformedGatewayRequest" not in out["mcp"]          # the target is never invoked
    # initialize is not contained (the session can be established; it just has no tools)
    out = tenant_interceptor.build_output(_gw_event("initialize", tenant="cw-b"), SECRET, True, _Ctx())
    assert "transformedGatewayRequest" in out["mcp"]
    # the denials landed in cw-b's OWN ledger + vault; the base ledger is untouched
    assert set(env.store) == {"ben-x-cw-b-audit-ledger"}
    rows = list(env.store["ben-x-cw-b-audit-ledger"].values())
    assert len(rows) == 2
    assert {b for b, _k, _r in env.puts} == {"ben-x-cw-b-worm-123456789012"}
    rec = env.puts[0][2]
    assert rec["phase"] == "DENIED" and rec["action"] == "kill_switch.deny" and rec["tenant_id"] == "cw-b"
    assert rec["case_id"] == "C-9"                     # the tool's case when the args carry one
    assert rec["payload"]["guardrail_action"] == "KILL_SWITCH" and rec["payload"]["engaged_reason"] == "SEV-1 drill"
    assert env.puts[1][2]["case_id"] == "C-9"


def test_engaged_silo_denial_uses_the_base_ledger_and_a_synthetic_case(env):
    env.ssm.values[DEPLOY] = _rec(True)
    out = tenant_interceptor.build_output(_gw_event("tools/list", args={}), SECRET, False, _Ctx())
    assert out["mcp"]["transformedGatewayResponse"]["statusCode"] == 403
    assert set(env.store) == {"ben-x-audit-ledger"}
    assert env.puts[0][2]["case_id"] == kill_switch.CASE_ID


# ---- (c) tool Lambdas --------------------------------------------------------------------------
def test_engaged_instrument_refuses_before_the_handler(env, capsys):
    calls = []

    @telemetry.instrument("assess")
    def handler(event, context=None):
        calls.append(event)
        return {"ok": True}

    assert handler({"case_id": "C-1"}, _Ctx()) == {"ok": True}
    env.ssm.values[DEPLOY] = _rec(True, reason="stop")
    kill_switch.clear_cache()
    with pytest.raises(kill_switch.KillSwitchEngaged) as ei:
        handler({"case_id": "C-2", "ssn": "123-45-6789"}, _Ctx())
    assert len(calls) == 1                              # the second call never reached the handler
    assert ei.value.state["reason"] == "stop"
    lines = [json.loads(l) for l in capsys.readouterr().out.splitlines() if l.startswith("{")]
    kinds = [(l.get("aegis"), l.get("outcome")) for l in lines]
    assert ("call", "denied:kill_switch") in kinds and ("kill_switch", "denied:kill_switch") in kinds
    assert not any("123-45-6789" in json.dumps(l) for l in lines)   # never argument VALUES (case_id is a key)


# ---- (d) fail-closed ---------------------------------------------------------------------------
@pytest.mark.parametrize("value", ["", "   ", "{not json", '{"engaged": "yes"}', "[]"])
def test_bad_values_fail_closed(env, value):
    env.ssm.values[DEPLOY] = value
    kill_switch.clear_cache()
    assert kill_switch.check()["engaged"] is True


def test_unreadable_parameter_fails_closed(env):
    env.ssm.fail[DEPLOY] = RuntimeError("AccessDeniedException")
    kill_switch.clear_cache()
    s = kill_switch.check()
    assert s and s["reason"].startswith("unreadable")
    with pytest.raises(kill_switch.KillSwitchEngaged):
        kill_switch.enforce()


@pytest.mark.parametrize("value,engaged", [("true", True), ("ENGAGED", True), ("false", False), ("off", False)])
def test_bare_values(env, value, engaged):
    env.ssm.values[DEPLOY] = value
    kill_switch.clear_cache()
    assert bool(kill_switch.check()) is engaged


# ---- (e) many-to-one ---------------------------------------------------------------------------
def test_platform_wide_switch_engages_the_deployment(env, monkeypatch):
    monkeypatch.setenv(kill_switch.PARAMS_ENV, "%s, %s" % (DEPLOY, GLOBAL))
    env.ssm.values[GLOBAL] = _rec(False)
    assert kill_switch.check() is None
    env.ssm.values[GLOBAL] = _rec(True, reason="platform-wide")
    kill_switch.clear_cache()
    assert kill_switch.check()["source"] == GLOBAL


# ---- (f) TTL cache -----------------------------------------------------------------------------
def test_ttl_cache_bounds_reads_and_time_to_effect(env, monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(kill_switch.time, "time", lambda: clock[0])
    for _ in range(50):
        assert kill_switch.check() is None
    assert env.ssm.reads.count(DEPLOY) == 1               # one read per TTL per environment
    env.ssm.values[DEPLOY] = _rec(True)
    assert kill_switch.check() is None                    # still cached (within TTL)
    clock[0] += 16
    assert kill_switch.check()["engaged"] is True         # seen after the TTL
    assert env.ssm.reads.count(DEPLOY) == 2


# ---- (g) controller ----------------------------------------------------------------------------
def _url_event(method, arn=None, body=None):
    e = {"requestContext": {"http": {"method": method},
                            "authorizer": {"iam": {"userArn": arn, "userId": "AIDA1", "accountId": "123456789012"}} if arn else None},
         "body": json.dumps(body) if body is not None else ""}
    return e


ALICE = "arn:aws:iam::123456789012:user/alice"
BOB = "arn:aws:iam::123456789012:user/bob"
ROLE_A1 = "arn:aws:sts::123456789012:assumed-role/IncidentResponder/alice-session"
ROLE_A2 = "arn:aws:sts::123456789012:assumed-role/IncidentResponder/other-session"
ROLE_B = "arn:aws:sts::123456789012:assumed-role/SecurityLead/bob-session"


def test_controller_requires_an_iam_identity_and_a_reason(env):
    code, body = kill_switch_control.handle(_url_event("POST", None, {"reason": "operator says so", "actor": ALICE}), _Ctx(), "engage", DEPLOY)
    assert code == 401
    code, body = kill_switch_control.handle(_url_event("POST", ALICE, {"reason": "x"}), _Ctx(), "engage", DEPLOY)
    assert code == 400
    assert json.loads(env.ssm.values[DEPLOY])["engaged"] is False   # untouched


def test_controller_engage_then_sod_then_release(env, monkeypatch):
    monkeypatch.setenv("MULTITENANT", "1")                 # platform scope must still reach the BASE ledger
    monkeypatch.setenv("WORM_BUCKET_TEMPLATE", "ben-x-{tenant}-worm-123456789012")
    code, body = kill_switch_control.handle(_url_event("POST", ALICE, {"reason": "SEV-1: runaway agent"}), _Ctx(), "engage", DEPLOY)
    assert code == 200, body
    st = json.loads(env.ssm.values[DEPLOY])
    assert st["engaged"] is True and st["actor"] == ALICE and st["reason"] == "SEV-1: runaway agent"
    assert body["audit"]["stored"] and body["audit"]["worm"]
    assert set(env.store) == {"ben-x-audit-ledger"}        # BASE ledger, even in multi-tenant mode
    assert env.puts[-1][0] == "ben-x-worm-123456789012"
    rec = env.puts[-1][2]
    assert (rec["action"], rec["phase"], rec["actor"], rec["tenant_id"]) == ("kill_switch.engage", "COMMITTED", ALICE, tenancy.PLATFORM_SCOPE)
    # every component now refuses
    kill_switch.clear_cache()
    assert kill_switch.check()["actor"] == ALICE
    # idempotent engage
    code, _ = kill_switch_control.handle(_url_event("POST", ALICE, {"reason": "again please"}), _Ctx(), "engage", DEPLOY)
    assert code == 409
    # SoD: alice cannot release what alice engaged
    code, body = kill_switch_control.handle(_url_event("POST", ALICE, {"reason": "false alarm, sorry"}), _Ctx(), "disengage", DEPLOY)
    assert code == 403 and "separation of duties" in body["error"]
    assert json.loads(env.ssm.values[DEPLOY])["engaged"] is True
    assert env.puts[-1][2]["phase"] == "DENIED" and env.puts[-1][2]["action"] == "kill_switch.disengage"
    # a second identity releases; the record names who engaged it
    code, body = kill_switch_control.handle(_url_event("POST", BOB, {"reason": "security lead sign-off"}), _Ctx(), "disengage", DEPLOY)
    assert code == 200, body
    st = json.loads(env.ssm.values[DEPLOY])
    assert st["engaged"] is False and st["actor"] == BOB and st["released"]["engaged_by"] == ALICE
    assert env.puts[-1][2]["phase"] == "COMMITTED" and env.puts[-1][2]["payload"]["engaged_by"] == ALICE
    kill_switch.clear_cache()
    assert kill_switch.check() is None
    # status works for either identity
    code, body = kill_switch_control.handle(_url_event("GET", BOB), _Ctx(), "engage", DEPLOY)
    assert code == 200 and body["state"]["engaged"] is False
    # release when not engaged
    code, _ = kill_switch_control.handle(_url_event("POST", BOB, {"reason": "nothing to release"}), _Ctx(), "disengage", DEPLOY)
    assert code == 409


def test_controller_sod_treats_the_same_assumed_role_as_the_same_identity(env):
    code, _ = kill_switch_control.handle(_url_event("POST", ROLE_A1, {"reason": "drill engage"}), _Ctx(), "engage", DEPLOY)
    assert code == 200
    code, _ = kill_switch_control.handle(_url_event("POST", ROLE_A2, {"reason": "same role, new session"}), _Ctx(), "disengage", DEPLOY)
    assert code == 403
    code, _ = kill_switch_control.handle(_url_event("POST", ROLE_B, {"reason": "different role"}), _Ctx(), "disengage", DEPLOY)
    assert code == 200


def test_controller_write_failure_leaves_state_unchanged(env):
    env.ssm.put_parameter = lambda **kw: (_ for _ in ()).throw(RuntimeError("ThrottlingException"))
    code, body = kill_switch_control.handle(_url_event("POST", ALICE, {"reason": "engage during throttle"}), _Ctx(), "engage", DEPLOY)
    assert code == 502 and "NOT changed" in body["error"]
    assert env.store == {}                                # no ledger record for a change that did not happen


# ---- (h) platform scope is not injectable ------------------------------------------------------
def test_platform_scope_cannot_arrive_through_signed_tool_args(env, monkeypatch):
    monkeypatch.setenv("MULTITENANT", "1")
    args = tenancy.signed_binding(tenancy.PLATFORM_SCOPE, SECRET)     # a correctly signed sentinel
    assert tenancy.verified_tenant_from_args(args, SECRET) is None
    assert tenancy.bind_tenant_from_args(args, SECRET) is None
    with pytest.raises(tenancy.TenantError):
        tenancy.route_store("ben-x-audit-ledger", "audit-ledger")
