"""governed-core 1.7.0 — phase 110 correlation: one key set (tenant · session · trace · mcp-session ·
execution · request · case) carried through the gateway interceptor, bound in the Lambda, stamped into
the hashed WORM record, and emitted as one structured log line per invocation. Offline, no AWS."""
import json

import governed_core  # noqa: F401
import evidence  # noqa: E402
import telemetry  # noqa: E402
import tenancy  # noqa: E402
import tenant_interceptor as ti  # noqa: E402
import write_audit  # noqa: E402

SECRET = b"unit-secret"
TP = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
HEADERS = {"Authorization": "Bearer x.y.z", "traceparent": TP,
           "baggage": "session.id=sess-123,tenant=pha-a", "Mcp-Session-Id": "mcp-9"}


class _Ctx:
    aws_request_id = "req-42"
    invoked_function_arn = "arn:aws:lambda:us-east-1:123456789012:function:x"


def test_header_parsing_w3c_xray_baggage():
    assert telemetry.parse_traceparent(TP) == ("4bf92f3577b34da6a3ce929d0e0e4736", "00f067aa0ba902b7")
    assert telemetry.parse_xray("Root=1-5759e988-bd862e3fe1be46a994272793;Parent=53995c3f42cd8ad8;Sampled=1") == \
        ("5759e988bd862e3fe1be46a994272793", "53995c3f42cd8ad8")
    out = telemetry.from_headers(HEADERS)
    assert out == {"trace_id": "4bf92f3577b34da6a3ce929d0e0e4736", "span_id": "00f067aa0ba902b7",
                   "session_id": "sess-123", "baggage_tenant": "pha-a", "mcp_session_id": "mcp-9"}
    # X-Ray header is the fallback when there is no traceparent; the runtime session header wins
    out = telemetry.from_headers({"X-Amzn-Trace-Id": "Root=1-5759e988-bd862e3fe1be46a994272793",
                                  "X-Amzn-Bedrock-AgentCore-Runtime-Session-Id": "rt-1", "baggage": "session.id=other"})
    assert out["trace_id"] == "5759e988bd862e3fe1be46a994272793" and out["session_id"] == "rt-1"


def _jwt(payload):
    import base64
    b = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")  # noqa: E731
    return b({"alg": "none"}) + "." + b(payload) + ".sig"


def test_interceptor_injects_trace_next_to_signed_tenant(monkeypatch):
    tok = _jwt({"cognito:groups": ["tenant_pha-a"]})
    ev = {"mcp": {"gatewayRequest": {"headers": {**HEADERS, "Authorization": "Bearer " + tok},
                                     "body": {"jsonrpc": "2.0", "id": 7, "method": "tools/call",
                                              "params": {"name": "mask-pii___mask_pii",
                                                         "arguments": {"case": "x", "__aegis_trace": "{\"trace_id\":\"forged\"}"}}}}}}
    out = ti.build_output(ev, SECRET, True)
    args = out["mcp"]["transformedGatewayRequest"]["body"]["params"]["arguments"]
    assert args[tenancy.TENANT_FIELD] == "pha-a"
    trace = json.loads(args[telemetry.TRACE_FIELD])
    assert trace == {"trace_id": "4bf92f3577b34da6a3ce929d0e0e4736", "span_id": "00f067aa0ba902b7",
                     "session_id": "sess-123", "mcp_session_id": "mcp-9"}   # caller value OVERWRITTEN, no tenant
    # silo (no tenant on the identity, not multitenant): trace still injected, no tenant pair
    ev["mcp"]["gatewayRequest"]["headers"]["Authorization"] = "Bearer " + _jwt({"sub": "u"})
    args = ti.build_output(ev, SECRET, False)["mcp"]["transformedGatewayRequest"]["body"]["params"]["arguments"]
    assert tenancy.TENANT_FIELD not in args and telemetry.TRACE_FIELD in args


def test_bind_reads_reserved_fields_context_and_env(monkeypatch):
    monkeypatch.setenv("_X_AMZN_TRACE_ID", "Root=1-5759e988-bd862e3fe1be46a994272793;Sampled=1")
    ctx = telemetry.bind({"case_id": "C-1", "__aegis_execution": "arn:aws:states:us-east-1:123456789012:execution:sm:e1"}, _Ctx())
    assert ctx == {"trace_id": "5759e988bd862e3fe1be46a994272793", "request_id": "req-42", "case_id": "C-1",
                   "execution_arn": "arn:aws:states:us-east-1:123456789012:execution:sm:e1"}
    ctx = telemetry.bind({"__aegis_trace": json.dumps({"trace_id": "abc", "session_id": "s", "span_id": "p"})}, None)
    assert ctx["trace_id"] == "abc" and ctx["session_id"] == "s" and "request_id" not in ctx
    telemetry.clear()
    assert telemetry.current() == {}


def test_evidence_record_carries_hashed_correlation_and_invocation(monkeypatch):
    monkeypatch.setenv("MULTITENANT", "1")
    monkeypatch.setenv("PROVENANCE_SECRET", SECRET.decode())
    event = {"case_id": "C-1", "action": "a", "phase": "INTENT", "actor": "u", "payload": {"k": 1},
             "__aegis_trace": json.dumps({"trace_id": "t1", "span_id": "s1", "session_id": "sess", "mcp_session_id": "m"}),
             "__aegis_execution": "arn:exec", **tenancy.signed_binding("pha-a", SECRET)}
    tenancy.bind_tenant_from_args(event, SECRET)
    telemetry.bind(event, _Ctx())
    logical = evidence.build_logical(event, "write_audit")
    assert logical["tenant_id"] == "pha-a"                       # DERIVED, not from the body/env
    assert logical["correlation"] == {"trace_id": "t1", "session_id": "sess", "mcp_session_id": "m",
                                      "execution_arn": "arn:exec", "tenant": "pha-a"}
    rec = evidence.build_record(logical, 0, None)
    assert rec["invocation"] == {"span_id": "s1", "request_id": "req-42"}
    # correlation is inside the hashed body: changing a trace id breaks entry_hash (tamper-evident)
    assert evidence.entry_hash(rec) == rec["entry_hash"]
    tampered = dict(rec); tampered["correlation"] = {**rec["correlation"], "trace_id": "t2"}
    assert evidence.entry_hash(tampered) != rec["entry_hash"]
    # the per-invocation keys are NOT in audit_id: an exact replay (new request id) is the same audit_id
    telemetry.bind({**event}, type("C", (), {"aws_request_id": "req-43"})())
    rec2 = evidence.build_record(evidence.build_logical(event, "write_audit"), 0, None)
    assert rec2["audit_id"] == rec["audit_id"] and rec2["invocation"]["request_id"] == "req-43"
    telemetry.clear(); tenancy.clear_request_claims()


def test_instrumented_handler_emits_one_call_line_without_argument_values(monkeypatch, capsys):
    monkeypatch.delenv("MULTITENANT", raising=False)
    monkeypatch.setenv("TENANT_ID", "agency-1")
    monkeypatch.setattr(evidence, "record_event", lambda e, c, source=None: {"stored": True, "audit_id": "A"})
    out = write_audit.handler({"case_id": "C-9", "action": "x", "payload": {"ssn": "900-12-3456"},
                               "__aegis_trace": json.dumps({"trace_id": "tt", "session_id": "ss"})}, _Ctx())
    assert out["stored"]
    lines = [json.loads(l) for l in capsys.readouterr().out.splitlines() if l.startswith("{")]
    calls = [l for l in lines if l.get("aegis") == "call"]
    assert len(calls) == 1
    c = calls[0]
    assert c["tool"] == "write_audit" and c["outcome"] == "stored=True" and c["tenant"] == "agency-1"
    assert c["trace_id"] == "tt" and c["session_id"] == "ss" and c["request_id"] == "req-42" and c["case_id"] == "C-9"
    assert c["arg_keys"] == ["action", "case_id", "payload"] and "900-12-3456" not in json.dumps(c)
    assert telemetry.current() == {}                                 # cleared after the call


def test_instrumented_handler_logs_and_reraises_on_exception(capsys):
    @telemetry.instrument("boom")
    def h(event, context):
        raise ValueError("x")
    try:
        h({"case_id": "C"}, _Ctx())
    except ValueError:
        pass
    line = [json.loads(l) for l in capsys.readouterr().out.splitlines() if l.startswith("{")][-1]
    assert line["outcome"] == "exception:ValueError" and line["case_id"] == "C"
