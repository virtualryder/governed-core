"""governed-core 1.9.0 — the LIVE per-tenant token + USD budget meter (task 128).

Proves, offline (DynamoDB / CloudWatch / ledger stubbed at the module seams, no AWS):
  (a) not configured => everything is a no-op that allows;
  (b) reserve() is ONE conditional ADD: it allows while the estimate fits under the token cap, refuses
      (BudgetExceeded, HARD) once it would not — concurrent reservations cannot oversell; cap 0 refuses
      outright; a USD cap refuses once usd_micro has reached it; SOFT behaviour allows + flags;
  (c) commit() replaces the reservation with the real Converse usage, adds tokens_in/out + the USD
      estimate from the PINNED price table (price_version recorded), never raises, publishes metrics;
      the meter converges: after reserve(4000) + commit(actual 1500) the meter shows 1500;
  (d) per-tenant item overrides (cap_tokens / cap_usd_micro / behavior) win over deployment defaults;
  (e) check() (gateway side) refuses a tenant AT/OVER cap or switched off; unreadable meter => fail-closed
      for HARD, allowed for SOFT;
  (f) the interceptor short-circuits tools/call for an over-cap tenant with 403 + a DENIED WORM record in
      that tenant's ledger, and passes tools/list (listing costs nothing);
  (g) unknown model => unpriced (0 USD) but tokens still count; the deployment price table overrides
      the default and its version is what gets recorded.
"""
import json
import types

import pytest

import governed_core  # noqa: F401
import budget  # noqa: E402
import evidence  # noqa: E402
import kill_switch  # noqa: E402
import telemetry  # noqa: E402
import tenancy  # noqa: E402
import tenant_interceptor  # noqa: E402

SECRET = b"unit-test-secret"
TABLE = "ben-x-budgets"


class _Ctx:
    invoked_function_arn = "arn:aws:lambda:us-east-1:123456789012:function:x"
    aws_request_id = "req-1"


class _CondFail(Exception):
    def __init__(self):
        super().__init__("ConditionalCheckFailedException")
        self.response = {"Error": {"Code": "ConditionalCheckFailedException"}}


class _FakeDdb:
    """Enough of DynamoDB for the meter: ADD/SET update expressions with the meter's condition shapes."""

    def __init__(self):
        self.items, self.fail, self.updates = {}, None, 0

    def get_item(self, TableName, Key, ConsistentRead=False):
        if self.fail:
            raise self.fail
        it = self.items.get(Key["budget_key"]["S"])
        return {"Item": it} if it else {}

    def update_item(self, TableName, Key, UpdateExpression, ExpressionAttributeValues, ReturnValues, ConditionExpression=None):
        if self.fail:
            raise self.fail
        self.updates += 1
        k = Key["budget_key"]["S"]
        it = self.items.setdefault(k, {})
        v = {name: int(val["N"]) if "N" in val else val["S"] for name, val in ExpressionAttributeValues.items()}

        def num(name):
            return int(it.get(name, {"N": "0"})["N"]) if name in it else None

        if ConditionExpression:
            if "never_true_sentinel" in ConditionExpression:
                raise _CondFail()
            used = num("used")
            if not (used is None or used <= v[":room"]):
                raise _CondFail()
            if ":usd_cap" in v:
                usd = num("usd_micro")
                if not (usd is None or usd < v[":usd_cap"]):
                    raise _CondFail()
        add_part, set_part = UpdateExpression, ""
        if " SET " in UpdateExpression:
            add_part, set_part = UpdateExpression.split(" SET ")
        for pair in add_part.replace("ADD ", "").split(","):
            name, ref = pair.strip().split(" ")
            it[name] = {"N": str((num(name) or 0) + v[ref])}
        for pair in [p for p in set_part.split(",") if p.strip()]:
            name, ref = [x.strip() for x in pair.split("=")]
            it[name] = {"S": v[ref]} if isinstance(v[ref], str) else {"N": str(v[ref])}
        return {"Attributes": dict(it)}


class _FakeCw:
    def __init__(self):
        self.calls = []

    def put_metric_data(self, Namespace, MetricData):
        self.calls.append((Namespace, MetricData))


# ---- ledger stub -----------------------------------------------------------------------------
class _FakeTable:
    def __init__(self, name, store):
        self.name, self.store = name, store

    def get_item(self, Key):
        it = self.store.get(self.name, {}).get(Key["audit_id"])
        if it is None:
            return {}
        from boto3.dynamodb.types import TypeDeserializer
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
    ddb, cw = _FakeDdb(), _FakeCw()
    store, puts = {}, []
    monkeypatch.setattr(budget, "_client", lambda: ddb)
    monkeypatch.setattr(budget, "_cloudwatch", lambda: cw)
    monkeypatch.setattr(evidence, "_clients", lambda region: (_FakeDdbRes(store), _FakeDdbCli(store), _FakeS3(puts)))
    monkeypatch.setattr(kill_switch, "_ssm", lambda: types.SimpleNamespace(get_parameter=lambda Name: {"Parameter": {"Value": '{"engaged": false}'}}))
    monkeypatch.setenv(budget.TABLE_ENV, TABLE)
    monkeypatch.setenv(budget.CAP_TOKENS_ENV, "10000")
    monkeypatch.setenv(budget.BEHAVIOR_ENV, "hard")
    monkeypatch.setenv(budget.RESERVE_ENV, "4000")
    monkeypatch.setenv(budget.DEPLOYMENT_ENV, "ben-x")
    monkeypatch.delenv(budget.CAP_USD_MICRO_ENV, raising=False)
    monkeypatch.delenv(budget.PRICES_ENV, raising=False)
    monkeypatch.setenv(kill_switch.PARAMS_ENV, "/ben-x-eligibility/kill-switch")
    monkeypatch.setenv("AUDIT_TABLE", "ben-x-audit-ledger")
    monkeypatch.setenv("AUDIT_BUCKET", "ben-x-worm-123456789012")
    monkeypatch.setenv("PROVENANCE_SECRET", SECRET.decode())
    monkeypatch.delenv("MULTITENANT", raising=False)
    monkeypatch.delenv("WORM_BUCKET_TEMPLATE", raising=False)
    budget.clear_cache(); kill_switch.clear_cache(); tenancy.clear_request_claims(); telemetry.clear()
    yield types.SimpleNamespace(ddb=ddb, cw=cw, store=store, puts=puts)
    budget.clear_cache(); kill_switch.clear_cache(); tenancy.clear_request_claims(); telemetry.clear()


NOW = 1_788_000_000          # 2026-08 -> period "2026-08"
SONNET = "us.anthropic.claude-sonnet-4-5-20250929-v1:0"


def test_unconfigured_is_a_noop(env, monkeypatch):
    monkeypatch.delenv(budget.TABLE_ENV)
    assert budget.reserve("t")["allowed"] and budget.check("t") is None
    assert budget.commit("t", {"inputTokens": 5, "outputTokens": 5})["metered"] is False


# ---- (b) reserve ---------------------------------------------------------------------------------
def test_reserve_allows_until_the_cap_then_refuses_hard(env):
    d1 = budget.reserve("pha-a", now=NOW)
    d2 = budget.reserve("pha-a", now=NOW)
    assert d1["allowed"] and d2["allowed"] and d2["used_tokens"] == 8000 and d2["reserved"] == 4000
    with pytest.raises(budget.BudgetExceeded) as ei:       # 8000 + 4000 > 10000
        budget.reserve("pha-a", now=NOW)
    assert "cap reached" in ei.value.decision["reason"] and ei.value.decision["guardrail_action"] == "BUDGET"
    assert env.ddb.items[budget.key("pha-a", NOW)]["used"]["N"] == "8000"     # the refused one never landed
    assert budget.reserve("pha-b", now=NOW)["allowed"]                        # other tenant untouched


def test_cap_zero_switches_a_tenant_off(env):
    env.ddb.items[budget.key("pha-b", NOW)] = {"cap_tokens": {"N": "0"}}
    with pytest.raises(budget.BudgetExceeded):
        budget.reserve("pha-b", now=NOW)


def test_usd_cap_refuses_once_reached(env, monkeypatch):
    monkeypatch.setenv(budget.CAP_USD_MICRO_ENV, "50000")           # $0.05
    budget.clear_cache()
    env.ddb.items[budget.key("pha-a", NOW)] = {"used": {"N": "10"}, "usd_micro": {"N": "50000"}}
    with pytest.raises(budget.BudgetExceeded):
        budget.reserve("pha-a", now=NOW)


def test_soft_behaviour_flags_but_allows(env, monkeypatch):
    monkeypatch.setenv(budget.BEHAVIOR_ENV, "soft")
    env.ddb.items[budget.key("pha-a", NOW)] = {"used": {"N": "9999"}}
    d = budget.reserve("pha-a", now=NOW)
    assert d["allowed"] and d["soft_breach"] and d["reserved"] == 0
    assert budget.check("pha-a", now=NOW) is None                      # 9999 < 10000: not yet AT the cap
    env.ddb.items[budget.key("pha-a", NOW)]["used"] = {"N": "10000"}
    assert budget.check("pha-a", now=NOW)["soft_breach"]               # at the cap: flagged, still allowed


def test_unreadable_meter_fails_closed_for_hard(env):
    env.ddb.fail = RuntimeError("ProvisionedThroughputExceededException")
    with pytest.raises(budget.BudgetExceeded) as ei:
        budget.reserve("pha-a", now=NOW)
    assert "fail-closed" in ei.value.decision["reason"]
    with pytest.raises(budget.BudgetExceeded):
        budget.check("pha-a", now=NOW)


# ---- (c) commit ---------------------------------------------------------------------------------
def test_commit_replaces_the_reservation_with_real_usage_and_prices_it(env):
    r = budget.reserve("pha-a", now=NOW)
    out = budget.commit("pha-a", {"inputTokens": 1200, "outputTokens": 300, "totalTokens": 1500}, SONNET, reserved=r["reserved"], now=NOW)
    assert out["metered"] and out["tokens"] == 1500 and out["priced"]
    assert out["used_tokens"] == 1500                      # 4000 reserved -> corrected to the real 1500
    assert out["usd_micro"] == 1200 * 3 + 300 * 15         # $3 / $15 per MTok in micro-dollars
    assert out["used_usd_micro"] == out["usd_micro"] and out["pct_tokens"] == 15.0
    assert out["price_version"].startswith("anthropic-platform-2026-09-03")
    it = env.ddb.items[budget.key("pha-a", NOW)]
    assert it["reserved"]["N"] == "0" and it["tokens_in"]["N"] == "1200" and it["tokens_out"]["N"] == "300" and it["calls"]["N"] == "1"
    ns, data = env.cw.calls[-1]
    assert ns == "Aegis/Budget" and {m["MetricName"] for m in data} == {"TokensUsed", "UsdUsedMicro", "TokensUsedPct"}
    assert all({d["Name"]: d["Value"] for d in m["Dimensions"]} == {"Tenant": "pha-a", "Deployment": "ben-x"} for m in data)
    st = budget.status("pha-a", now=NOW)
    assert st["used_usd"] == round(out["usd_micro"] / 1e6, 6) and st["period"] == "2026-08"


def test_commit_never_raises_and_reports_a_metering_failure(env):
    env.ddb.fail = RuntimeError("boom")
    out = budget.commit("pha-a", {"inputTokens": 1, "outputTokens": 1}, SONNET, now=NOW)
    assert out["metered"] is False and "boom" in out["reason"]


# ---- (d) overrides -------------------------------------------------------------------------------
def test_item_overrides_win_over_deployment_defaults(env):
    env.ddb.items[budget.key("pha-b", NOW)] = {"cap_tokens": {"N": "500"}, "behavior": {"S": "soft"}, "cap_usd_micro": {"N": "7"}}
    c = budget.caps("pha-b", now=NOW)
    assert c == {"cap_tokens": 500, "cap_usd_micro": 7, "behavior": "soft"}
    assert budget.caps("pha-a", now=NOW) == {"cap_tokens": 10000, "cap_usd_micro": 0, "behavior": "hard"}


# ---- (e) check -----------------------------------------------------------------------------------
def test_check_refuses_at_or_over_cap(env):
    assert budget.check("pha-a", now=NOW) is None
    env.ddb.items[budget.key("pha-a", NOW)] = {"used": {"N": "10000"}}
    with pytest.raises(budget.BudgetExceeded):
        budget.check("pha-a", now=NOW)


# ---- (f) interceptor -----------------------------------------------------------------------------
def _bearer_for(tenant):
    import base64
    def b64(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    return "%s.%s.sig" % (b64({"alg": "RS256"}), b64({"cognito:groups": ["benefits_caseworker", "tenant_" + tenant], "sub": "u-1"}))


def _gw_event(method, tenant):
    return {"mcp": {"gatewayRequest": {"headers": {"Authorization": "Bearer " + _bearer_for(tenant)},
                                       "body": {"jsonrpc": "2.0", "id": 3, "method": method,
                                                "params": {"name": "mask-pii___mask_pii", "arguments": {"case_id": "C-1"}}}}}}


def test_interceptor_refuses_an_over_cap_tenant_and_audits_it(env, monkeypatch):
    monkeypatch.setenv("MULTITENANT", "1")
    monkeypatch.setenv("WORM_BUCKET_TEMPLATE", "ben-x-{tenant}-worm-123456789012")
    env.ddb.items[budget.key("pha-b")] = {"cap_tokens": {"N": "0"}}          # switched off (current period)
    out = tenant_interceptor.build_output(_gw_event("tools/call", "pha-b"), SECRET, True, _Ctx())
    resp = out["mcp"]["transformedGatewayResponse"]
    assert resp["statusCode"] == 403 and "budget exceeded" in resp["body"]["error"]["message"]
    assert set(env.store) == {"ben-x-pha-b-audit-ledger"}
    rec = env.puts[0][2]
    assert rec["action"] == "budget.deny" and rec["phase"] == "DENIED" and rec["tenant_id"] == "pha-b" and rec["case_id"] == "C-1"
    assert rec["payload"]["guardrail_action"] == "BUDGET"
    # listing is free and the other tenant is untouched
    assert "transformedGatewayRequest" in tenant_interceptor.build_output(_gw_event("tools/list", "pha-b"), SECRET, True, _Ctx())["mcp"]
    assert "transformedGatewayRequest" in tenant_interceptor.build_output(_gw_event("tools/call", "pha-a"), SECRET, True, _Ctx())["mcp"]


# ---- (g) prices ----------------------------------------------------------------------------------
def test_unknown_model_is_unpriced_but_counted(env):
    out = budget.commit("pha-a", {"inputTokens": 10, "outputTokens": 10}, "amazon.nova-lite-v1:0", now=NOW)
    assert out["metered"] and out["priced"] is False and out["usd_micro"] == 0 and out["used_tokens"] == 20


def test_deployment_price_table_overrides_and_is_recorded(env, monkeypatch):
    monkeypatch.setenv(budget.PRICES_ENV, json.dumps({"price_version": "bedrock-us-east-1-confirmed-2026-09-10",
                                                      "models": {"anthropic.claude-sonnet-4-5": {"input_per_m": 3.0, "output_per_m": 15.0}}}))
    out = budget.commit("pha-a", {"inputTokens": 1000000, "outputTokens": 0}, SONNET, now=NOW)
    assert out["usd_micro"] == 3 * budget.MICRO and out["price_version"] == "bedrock-us-east-1-confirmed-2026-09-10"
    assert env.ddb.items[budget.key("pha-a", NOW)]["price_version"]["S"] == "bedrock-us-east-1-confirmed-2026-09-10"
