import json
import time
import hashlib
import os

# evidence.py — the CANONICAL evidence service. ONE code path that every consequential event goes
# through (intake, request, approve, reject, override, finalize/commit, connector response, policy
# denial, failed action). Bundled into each control Lambda so there is a single evidence format and a
# single hash-chain implementation — no per-Lambda copies to drift.
#
# AUTHORITATIVE, ATOMIC, FORK-PROOF hash chain (fixes the caller-threaded-prev_hash defect):
#   * The chain head for a case is an item  audit_id = "HEAD#<case_id>"  holding the current tip
#     chain_hash + seq. The writer READS it server-side (never trusts a caller-supplied prev_hash).
#   * The event and the new head are written in ONE DynamoDB TransactWriteItems:
#       - Put(event)  ConditionExpression attribute_not_exists(audit_id)   -> immutable append
#       - Put(HEAD#<case>) ConditionExpression (attribute_not_exists OR chain_hash == :expected_tip)
#         -> compare-and-swap of the tip; two concurrent writers cannot both advance from the same tip,
#            so there is NO FORK. Uses PutItem only (never UpdateItem), so the append-only IAM Deny on
#            UpdateItem/DeleteItem still stands; the events themselves remain un-overwritable.
#   * On a head CAS miss (a concurrent writer advanced the tip) the writer re-reads and retries.
#   * On an event-hash collision (exact replay) it returns idempotently (append-only proof), not an error.
#
# Every record is enriched for provenance: tenant, case, actor, and the POLICY / RULE / MODEL /
# DEPLOYMENT versions in force (so "which rule version decided this" is answerable). Fail-loud: a write
# that cannot be recorded returns stored:false with the reason — it is NEVER silently swallowed.

GENESIS = "GENESIS"
_CHAIN_FIELDS = ("prev_hash", "entry_hash", "chain_hash")
_MAX_RETRIES = 6


def _env(k, d=""):
    return os.environ.get(k, d)


def _num_default(o):
    # DynamoDB returns numbers as Decimal; normalize so write-time (int/float) and read-time (Decimal)
    # canonical forms are identical — otherwise a faithfully-stored record would read as "tampered".
    from decimal import Decimal
    if isinstance(o, Decimal):
        i = int(o)
        return i if o == i else float(o)
    raise TypeError("not JSON serializable: %r" % (o,))


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=_num_default)


def entry_hash(record):
    body = {k: v for k, v in record.items() if k not in _CHAIN_FIELDS}
    return hashlib.sha256(_canonical(body).encode("utf-8")).hexdigest()


def chain_hash(prev_hash, eh):
    return hashlib.sha256(((prev_hash or GENESIS) + ":" + eh).encode("utf-8")).hexdigest()


def _coerce(event):
    e = event or {}
    if isinstance(e, str):
        try:
            e = json.loads(e)
        except Exception:
            e = {"_raw": e}
    return e


def build_logical(e, source):
    # case_id is the generic case key; icsr_id is accepted as a back-compat alias (P0-2: no domain
    # naming baked into the shared path).
    case_id = e.get("case_id") or e.get("icsr_id") or ""
    return {
        "case_id": case_id,
        "action": e.get("action", ""),
        "phase": e.get("phase", ""),          # INTENT | COMMITTED | DENIED | FAILED | ...
        "actor": e.get("actor", ""),
        "deidentified": e.get("deidentified"),
        "payload": e.get("payload", {}),
        "tenant_id": e.get("tenant_id") or _env("TENANT_ID", "default"),
        "policy_version": _env("POLICY_VERSION", "unset"),
        "rule_version": _env("RULE_VERSION", "unset"),
        "model_id": e.get("model_id") or _env("MODEL_ID", "unset"),
        "deployment_version": _env("DEPLOYMENT_VERSION", "unset"),
        "source": source or _env("SOURCE", "evidence"),
    }


def build_record(logical, seq, prev_hash):
    audit_id = hashlib.sha256(_canonical(logical).encode("utf-8")).hexdigest()
    payload_sha = hashlib.sha256(_canonical(logical.get("payload", {})).encode("utf-8")).hexdigest()
    rec = dict(logical)
    rec.update({"audit_id": audit_id, "payload_sha256": payload_sha,
                "recorded_at": int(time.time()), "seq": seq})
    eh = entry_hash(rec)
    rec["prev_hash"] = prev_hash or GENESIS
    rec["entry_hash"] = eh
    rec["chain_hash"] = chain_hash(prev_hash, eh)
    return rec


def _clients(region):
    import boto3
    return (boto3.resource("dynamodb", region_name=region),
            boto3.client("dynamodb", region_name=region),
            boto3.client("s3", region_name=region))


def _read_head(ddb_res, table, case_id):
    it = ddb_res.Table(table).get_item(Key={"audit_id": "HEAD#" + case_id}).get("Item")
    if not it:
        return GENESIS, -1
    return it.get("chain_hash", GENESIS), int(it.get("seq", -1))


def _transact(ddb_cli, table, rec, expected_tip):
    # one atomic append: immutable event + head compare-and-swap. Raises on cancellation.
    from boto3.dynamodb.types import TypeSerializer
    ser = TypeSerializer().serialize
    ev = {k: ser(v) for k, v in rec.items()}
    head = {k: ser(v) for k, v in {
        "audit_id": "HEAD#" + rec["case_id"], "case_id": rec["case_id"],
        "chain_hash": rec["chain_hash"], "seq": rec["seq"], "updated_at": rec["recorded_at"],
    }.items()}
    if expected_tip == GENESIS:
        head_cond, head_vals = "attribute_not_exists(audit_id)", None
    else:
        head_cond, head_vals = "chain_hash = :t", {":t": ser(expected_tip)}
    head_put = {"TableName": table, "Item": head, "ConditionExpression": head_cond}
    if head_vals:
        head_put["ExpressionAttributeValues"] = head_vals
    ddb_cli.transact_write_items(TransactItems=[
        {"Put": {"TableName": table, "Item": ev, "ConditionExpression": "attribute_not_exists(audit_id)"}},
        {"Put": head_put},
    ])


def record_event(event, context, source=None):
    e = _coerce(event)
    region = _env("AWS_REGION", "us-east-1")
    acct = "unknown"
    try:
        acct = context.invoked_function_arn.split(":")[4]
    except Exception:
        pass
    table = _env("AUDIT_TABLE") or "evidence-audit"
    bucket = _env("AUDIT_BUCKET") or ("evidence-worm-%s-%s" % (acct, region))
    logical = build_logical(e, source)
    if not logical["case_id"]:
        return {"stored": False, "error": "case_id (or icsr_id) is required for an evidence record"}

    ddb_res, ddb_cli, s3 = _clients(region)
    from botocore.exceptions import ClientError, BotoCoreError

    rec = None
    for attempt in range(_MAX_RETRIES):
        expected_tip, head_seq = _read_head(ddb_res, table, logical["case_id"])
        rec = build_record(logical, head_seq + 1, expected_tip)
        try:
            _transact(ddb_cli, table, rec, expected_tip)
            break
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            reasons = exc.response.get("CancellationReasons") or []
            rc = [r.get("Code") for r in reasons]
            # event already exists -> exact replay -> idempotent append-only proof
            if "ConditionalCheckFailed" in (rc[0] if rc else ""):
                return {"stored": False, "audit_id": rec["audit_id"], "chain_hash": rec["chain_hash"],
                        "reason": "append-only: this exact record is already recorded (immutable)"}
            # head CAS lost to a concurrent writer -> re-read and retry
            if code in ("TransactionCanceledException", "ConditionalCheckFailedException") and attempt < _MAX_RETRIES - 1:
                time.sleep(0.05 * (attempt + 1))
                continue
            return {"stored": False, "audit_id": rec["audit_id"],
                    "error": "evidence write failed after retries: %s %s" % (code, rc)}
        except BotoCoreError as exc:
            return {"stored": False, "error": "evidence write failed: %s" % type(exc).__name__}
    else:
        return {"stored": False, "error": "evidence write could not acquire the chain head (contention)"}

    # WORM copy (S3 Object Lock). Fail-loud: report worm:false, never swallow silently.
    worm, worm_err = False, None
    key = "%s/%s.json" % (logical["case_id"], rec["audit_id"])
    try:
        s3.put_object(Bucket=bucket, Key=key, Body=_canonical(rec).encode("utf-8"),
                      ContentType="application/json")
        worm = True
    except (ClientError, BotoCoreError) as exc:
        worm_err = type(exc).__name__

    out = {"stored": True, "worm": worm, "chain_hash": rec["chain_hash"], "prev_hash": rec["prev_hash"],
           "seq": rec["seq"], "phase": logical["phase"], "audit_id": rec["audit_id"],
           "entry_hash": rec["entry_hash"], "case_id": logical["case_id"],
           "policy_version": logical["policy_version"], "rule_version": logical["rule_version"],
           "table": table, "bucket": bucket, "key": key}
    if worm_err:
        out["worm_error"] = worm_err
    return out
