"""kill_switch_control — ENGAGE / DISENGAGE / STATUS controller for the deployment's Kill Switch (core 1.8.0).

Deployed as TWO Lambda functions from this one module (KILL_SWITCH_MODE=engage | disengage), each
behind its own Lambda FUNCTION URL with AuthType AWS_IAM. That gives real, IAM-enforced separation of
duties: an identity holds `lambda:InvokeFunctionUrl` on the engage function, or on the disengage
function — two managed policies, two roles. Nobody writes the SSM parameter directly (only these two
function roles may ssm:PutParameter it), so:

  * the ACTOR is never self-declared: it is the IAM-verified caller from the function-URL request
    context (`requestContext.authorizer.iam.userArn`, populated by Lambda for AWS_IAM auth), and it is
    written into the parameter value and into the WORM ledger;
  * separation of duties on RELEASE is enforced on that verified identity: the ARN that engaged the
    switch is refused when it tries to disengage (403, and the refusal itself is a DENIED ledger
    record) — the platform reference gateway could only enforce this in-process because IAM cannot
    inspect a parameter VALUE (docs/ops/KILL-SWITCH.md); this controller closes that gap;
  * every state change is a COMMITTED record in the deployment's BASE ledger + WORM vault (platform
    scope: tenancy.bind_platform_scope — a kill switch is deployment-wide, not a tenant's event),
    hash-chained under case KILL-SWITCH, with the correlation block (Lambda request id) so it joins
    CloudTrail's PutParameter event by time and principal.

Contract (HTTP, API Gateway v2 payload = Lambda function URL):
  POST /            body {"reason": "<why>"}   -> 200 {state, audit}   (engage or disengage per mode)
  GET  /            -> 200 {state}              (either function; read-only)
Errors: 401 (no IAM identity in the request context), 400 (no reason), 409 (already in that state),
403 (SoD: same identity), 502 (parameter write failed — the switch state is unchanged)."""
import json
import os
import time

import kill_switch

MODE_ENV = "KILL_SWITCH_MODE"          # engage | disengage
PARAM_ENV = "KILL_SWITCH_PARAM"        # this deployment's parameter (the one this controller owns)
MIN_REASON = 8


def _resp(code, body):
    return {"statusCode": code, "headers": {"content-type": "application/json"},
            "body": json.dumps(body, sort_keys=True, default=str)}


def caller_identity(event):
    """The IAM-verified caller. None unless Lambda populated the AWS_IAM authorizer context."""
    iam = (((event or {}).get("requestContext") or {}).get("authorizer") or {}).get("iam") or {}
    arn = iam.get("userArn")
    if not arn:
        return None
    return {"arn": arn, "user_id": iam.get("userId", ""), "account": iam.get("accountId", ""),
            "caller_id": iam.get("callerId", "")}


def _same_principal(a, b):
    """Same identity for SoD: exact ARN match, or the same assumed-role session role (an assumed-role
    ARN differs per session name; the ROLE is the identity the runbook assigns)."""
    if not a or not b:
        return False
    if a == b:
        return True
    return _role_of(a) is not None and _role_of(a) == _role_of(b)


def _role_of(arn):
    # arn:aws:sts::111122223333:assumed-role/<role>/<session> -> <account>/<role>
    parts = arn.split(":")
    if len(parts) >= 6 and parts[5].startswith("assumed-role/"):
        seg = parts[5].split("/")
        return parts[4] + "/" + seg[1] if len(seg) >= 2 else None
    return None


def _body(event):
    raw = (event or {}).get("body") or ""
    if (event or {}).get("isBase64Encoded"):
        import base64
        raw = base64.b64decode(raw).decode("utf-8", "replace")
    try:
        d = json.loads(raw) if raw else {}
    except ValueError:
        d = {}
    return d if isinstance(d, dict) else {}


def _read(name):
    raw = kill_switch._ssm().get_parameter(Name=name)["Parameter"]["Value"]
    rec = kill_switch.parse_value(raw)
    rec["source"] = name
    return rec


def _write(name, rec):
    kill_switch._ssm().put_parameter(Name=name, Value=json.dumps(rec, sort_keys=True), Type="String",
                                     Overwrite=True)
    kill_switch.clear_cache()


def _audit(action, phase, who, reason, payload, context):
    """COMMITTED / DENIED record in the BASE ledger (platform scope), never raises."""
    try:
        import evidence
        import tenancy
        tenancy.bind_platform_scope()
        try:
            return evidence.record_event(
                {"case_id": kill_switch.CASE_ID, "action": action, "phase": phase, "actor": who["arn"],
                 "deidentified": True,
                 "payload": {"reason": reason, "caller_user_id": who.get("user_id", ""), **payload}},
                context, source="kill_switch_control")
        finally:
            tenancy.clear_request_claims()
    except Exception as exc:
        return {"stored": False, "error": "%s: %s" % (type(exc).__name__, exc)}


def engage(name, who, reason, context):
    cur = _read(name)
    if cur.get("engaged") and not str(cur.get("reason", "")).startswith(kill_switch._UNREADABLE):
        return 409, {"error": "already engaged", "state": cur}
    now = int(time.time())
    rec = {"engaged": True, "actor": who["arn"], "actor_user_id": who.get("user_id", ""),
           "reason": reason, "at": now}
    _write(name, rec)
    audit = _audit("kill_switch.engage", "COMMITTED", who, reason,
                   {"parameter": name, "at": now, "guardrail_action": kill_switch.GUARDRAIL_ACTION}, context)
    return 200, {"state": {**rec, "source": name}, "audit": audit}


def disengage(name, who, reason, context):
    cur = _read(name)
    if not cur.get("engaged"):
        return 409, {"error": "not engaged", "state": cur}
    engaged_by = cur.get("actor", "")
    if _same_principal(engaged_by, who["arn"]):
        audit = _audit("kill_switch.disengage", "DENIED", who, reason,
                       {"parameter": name, "engaged_by": engaged_by, "sod": "same identity engaged and tried to release"},
                       context)
        return 403, {"error": "separation of duties: the identity that engaged the kill switch cannot "
                              "disengage it; a second identity must", "engaged_by": engaged_by, "audit": audit}
    now = int(time.time())
    rec = {"engaged": False, "actor": who["arn"], "actor_user_id": who.get("user_id", ""), "reason": reason,
           "at": now, "released": {"engaged_by": engaged_by, "engaged_at": cur.get("at"),
                                   "engaged_reason": cur.get("reason", "")}}
    _write(name, rec)
    audit = _audit("kill_switch.disengage", "COMMITTED", who, reason,
                   {"parameter": name, "at": now, "engaged_by": engaged_by, "engaged_at": cur.get("at"),
                    "engaged_reason": cur.get("reason", "")}, context)
    return 200, {"state": {**rec, "source": name}, "audit": audit}


def handle(event, context, mode, name):
    """Pure-ish core: (status_code, body)."""
    method = ((((event or {}).get("requestContext") or {}).get("http") or {}).get("method")
              or (event or {}).get("httpMethod") or "GET").upper()
    who = caller_identity(event)
    if not who:
        return 401, {"error": "no IAM identity on the request (function URL must use AuthType AWS_IAM)"}
    if method == "GET":
        try:
            return 200, {"state": _read(name), "mode": mode}
        except Exception as exc:
            return 502, {"error": "cannot read %s: %s" % (name, type(exc).__name__)}
    if method != "POST":
        return 405, {"error": "use GET (status) or POST (%s)" % mode}
    reason = str(_body(event).get("reason") or "").strip()
    if len(reason) < MIN_REASON:
        return 400, {"error": "a reason of at least %d characters is required" % MIN_REASON}
    try:
        if mode == "engage":
            return engage(name, who, reason, context)
        if mode == "disengage":
            return disengage(name, who, reason, context)
        return 500, {"error": "unknown KILL_SWITCH_MODE %r" % mode}
    except Exception as exc:
        return 502, {"error": "kill switch state NOT changed: %s %s" % (type(exc).__name__, exc)}


def handler(event, context):
    mode = os.environ.get(MODE_ENV, "").strip().lower()
    name = os.environ.get(PARAM_ENV, "").strip()
    if not name:
        return _resp(500, {"error": "%s not configured" % PARAM_ENV})
    code, body = handle(event, context, mode, name)
    print(json.dumps({"aegis": "kill_switch_control", "mode": mode, "status": code,
                      "caller": (caller_identity(event) or {}).get("arn", ""),
                      "audit": {k: body.get("audit", {}).get(k) for k in ("stored", "worm", "audit_id")}
                      if isinstance(body.get("audit"), dict) else None}, sort_keys=True, default=str))
    return _resp(code, body)
