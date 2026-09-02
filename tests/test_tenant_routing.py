"""governed-core 1.6.0 — per-tenant routing of the CANONICAL evidence writer, the exactly-once
finalize marker and the pending-approvals register (hybrid multi-tenant, promoted from the benefits
agent's phase 107).

Proves, offline (boto3 is stubbed at the module seam, no AWS):
  (a) silo mode: every store name is UNCHANGED and no binding is required (back-compat with 1.5.0);
  (b) multi-tenant: a verified signed tenant binding routes the ledger to <prefix>-<tenant>-audit-ledger
      and the WORM vault to the per-tenant bucket (WORM_BUCKET_TEMPLATE, else the '-worm-' marker);
  (c) multi-tenant FAIL-CLOSED: no binding / forged signature -> stored:false with a routing refusal,
      never a write into the shared base ledger; an unmappable bucket also refuses;
  (d) the finalize marker and the pending-approvals register route to the same tenant;
  (e) request_signoff carries the SIGNED pair into the execution input, and a downstream handler
      re-verifies it (workflow hop has no interceptor).
"""
import json
import types

import pytest

import governed_core  # noqa: F401  (installs the flat-import path the handlers use)
import evidence  # noqa: E402  — the FLAT modules, i.e. the exact objects the handlers import
import tenancy  # noqa: E402
import finalize_signoff  # noqa: E402
import signoff_register  # noqa: E402
import write_audit  # noqa: E402

SECRET = b"unit-test-provenance-secret"


class _Ctx:
    invoked_function_arn = "arn:aws:lambda:us-east-1:123456789012:function:x"


class _FakeTable:
    def __init__(self, name, store):
        self.name, self.store = name, store

    def get_item(self, Key):
        return {"Item": self.store.get(self.name, {}).get(Key["audit_id"])}

    def put_item(self, Item, ConditionExpression=None, **kw):
        key = Item.get("audit_id") or Item.get("case_id")
        rows = self.store.setdefault(self.name, {})
        if ConditionExpression and ConditionExpression.startswith("attribute_not_exists") and key in rows:
            from botocore.exceptions import ClientError
            raise ClientError({"Error": {"Code": "ConditionalCheckFailedException"}}, "PutItem")
        rows[key] = Item


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
        self.puts.append((Bucket, Key))


@pytest.fixture
def aws(monkeypatch):
    store, puts = {}, []
    monkeypatch.setattr(evidence, "_clients",
                        lambda region: (_FakeDdbRes(store), _FakeDdbCli(store), _FakeS3(puts)))
    monkeypatch.setenv("AUDIT_TABLE", "ben-mt-audit-ledger")
    monkeypatch.setenv("AUDIT_BUCKET", "ben-mt-worm-123456789012")
    monkeypatch.setenv("PROVENANCE_SECRET", SECRET.decode())
    monkeypatch.delenv("WORM_BUCKET_TEMPLATE", raising=False)
    tenancy.clear_request_claims()
    yield types.SimpleNamespace(store=store, puts=puts)
    tenancy.clear_request_claims()


def _event(**extra):
    return {"case_id": "C-1", "action": "test", "phase": "INTENT", "actor": "u", "deidentified": True,
            "payload": {"k": "v"}, **extra}


# ---- (a) silo: unchanged ----------------------------------------------------------------------
def test_silo_mode_routes_nothing(aws, monkeypatch):
    monkeypatch.delenv("MULTITENANT", raising=False)
    out = write_audit.handler(_event(), _Ctx())
    assert out["stored"] and out["worm"]
    assert out["table"] == "ben-mt-audit-ledger"
    assert out["bucket"] == "ben-mt-worm-123456789012"
    assert set(aws.store) == {"ben-mt-audit-ledger"}


# ---- (b) multi-tenant: routed by the verified binding ------------------------------------------
def test_multitenant_routes_ledger_and_worm_to_the_acting_tenant(aws, monkeypatch):
    monkeypatch.setenv("MULTITENANT", "1")
    out = write_audit.handler(_event(**tenancy.signed_binding("cw-a", SECRET)), _Ctx())
    assert out["stored"] and out["worm"], out
    assert out["table"] == "ben-mt-cw-a-audit-ledger"
    assert out["bucket"] == "ben-mt-cw-a-worm-123456789012"
    assert set(aws.store) == {"ben-mt-cw-a-audit-ledger"}          # base ledger untouched
    assert aws.puts == [("ben-mt-cw-a-worm-123456789012", "C-1/%s.json" % out["audit_id"])]


def test_multitenant_bucket_template_wins_over_marker(aws, monkeypatch):
    monkeypatch.setenv("MULTITENANT", "1")
    monkeypatch.setenv("AUDIT_BUCKET", "ben-mt-data-wormbucket-autoname")     # CDK auto-name, no marker
    monkeypatch.setenv("WORM_BUCKET_TEMPLATE", "ben-mt-{tenant}-worm-123456789012")
    out = write_audit.handler(_event(**tenancy.signed_binding("cw-b", SECRET)), _Ctx())
    assert out["stored"] and out["bucket"] == "ben-mt-cw-b-worm-123456789012"


# ---- (c) multi-tenant FAIL-CLOSED ----------------------------------------------------------------
def test_multitenant_refuses_without_binding(aws, monkeypatch):
    monkeypatch.setenv("MULTITENANT", "1")
    out = write_audit.handler(_event(), _Ctx())
    assert out["stored"] is False and "multi-tenant routing refused" in out["error"]
    assert aws.store == {} and aws.puts == []                       # nothing written anywhere


def test_multitenant_refuses_forged_binding(aws, monkeypatch):
    monkeypatch.setenv("MULTITENANT", "1")
    forged = tenancy.signed_binding("cw-a", b"wrong-key")
    out = write_audit.handler(_event(**forged), _Ctx())
    assert out["stored"] is False and aws.store == {}


def test_multitenant_refuses_unmappable_bucket(aws, monkeypatch):
    monkeypatch.setenv("MULTITENANT", "1")
    monkeypatch.setenv("AUDIT_BUCKET", "ben-mt-data-wormbucket-autoname")     # no template, no marker
    out = write_audit.handler(_event(**tenancy.signed_binding("cw-a", SECRET)), _Ctx())
    assert out["stored"] is False and "WORM_BUCKET_TEMPLATE" in out["error"]
    assert aws.store == {}                                          # ledger NOT written either


# ---- (d) finalize marker + pending register follow the tenant ----------------------------------
def test_finalize_marker_and_pending_register_route_per_tenant(aws, monkeypatch):
    monkeypatch.setenv("MULTITENANT", "1")
    monkeypatch.setattr(finalize_signoff, "PENDING_TABLE", "ben-mt-pending-approvals")
    import boto3
    monkeypatch.setattr(boto3, "resource", lambda *_a, **_k: _FakeDdbRes(aws.store))
    tenancy.bind_tenant_from_args(tenancy.signed_binding("cw-a", SECRET), SECRET)
    first, sub = finalize_signoff._exactly_once_marker("C-1", "SUB-1", "approver", "us-east-1")
    assert first and "FINAL#C-1" in aws.store["ben-mt-cw-a-audit-ledger"]
    again, sub2 = finalize_signoff._exactly_once_marker("C-1", "SUB-2", "approver", "us-east-1")
    assert not again and sub2 == "SUB-1"                            # exactly-once preserved per tenant
    assert finalize_signoff._pending_table("us-east-1").name == "ben-mt-cw-a-pending-approvals"
    # signoff_register (workflow hop, no interceptor) binds from the execution input it receives
    monkeypatch.setattr(signoff_register, "PENDING_TABLE", "ben-mt-pending-approvals")
    tenancy.clear_request_claims()
    out = signoff_register.handler({"case_id": "C-1", "requester": "r", "taskToken": "t",
                                    **tenancy.signed_binding("cw-b", SECRET)}, _Ctx())
    assert out.get("registered") is not False, out
    assert "C-1" in aws.store["ben-mt-cw-b-pending-approvals"]


def test_finalize_marker_fails_closed_without_binding(aws, monkeypatch):
    monkeypatch.setenv("MULTITENANT", "1")
    with pytest.raises(tenancy.TenantError):
        finalize_signoff._exactly_once_marker("C-1", "SUB-1", "approver", "us-east-1")


# ---- (e) the signed pair survives the workflow hop --------------------------------------------
def test_request_signoff_carries_signed_binding_into_execution_input(aws, monkeypatch):
    import request_signoff
    monkeypatch.setenv("MULTITENANT", "1")
    tenancy.bind_tenant_from_args(tenancy.signed_binding("cw-a", SECRET), SECRET)
    binding = request_signoff._tenant_binding()
    assert binding[tenancy.TENANT_FIELD] == "cw-a"
    payload = json.loads(json.dumps({"case_id": "C-1", "requester": "r", **binding}))
    tenancy.clear_request_claims()
    assert tenancy.bind_tenant_from_args(payload, SECRET) == "cw-a"
    monkeypatch.delenv("MULTITENANT")
    tenancy.clear_request_claims()
    assert request_signoff._tenant_binding() == {}                  # silo: nothing to carry
