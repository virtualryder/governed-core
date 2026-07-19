import json
import hashlib
import sys

# verify_chain — replay a case's evidence records and prove the hash chain is intact (tamper-evidence).
# Checks: (1) each record's entry_hash recomputes from its content (detects any edit); (2) chain_hash =
# SHA-256(prev_hash + entry_hash) recomputes (detects chain-field tampering); (3) the links form one
# unbroken list from GENESIS with no fork/gap/duplicate; (4) the server-assigned seq is contiguous
# 0..n-1 in link order (detects a spliced or reordered record even if hashes were recomputed). Read-only,
# pure stdlib. Usage: python verify_chain.py records.json

GENESIS = "GENESIS"
_CHAIN_FIELDS = ("prev_hash", "entry_hash", "chain_hash")


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


def _entry_hash(record):
    body = {k: v for k, v in record.items() if k not in _CHAIN_FIELDS}
    return hashlib.sha256(_canonical(body).encode("utf-8")).hexdigest()


def _chain_hash(prev_hash, eh):
    return hashlib.sha256(((prev_hash or GENESIS) + ":" + eh).encode("utf-8")).hexdigest()


def verify(records):
    recs = [r for r in (records or []) if not str(r.get("audit_id", "")).startswith("HEAD#")]
    n = len(recs)
    if n == 0:
        return {"intact": True, "length": 0, "broken_at": None, "reason": "empty chain (vacuously intact)"}

    for r in recs:
        for f in _CHAIN_FIELDS:
            if f not in r:
                return {"intact": False, "length": n, "broken_at": r.get("chain_hash"),
                        "reason": "record missing chain field '%s' (audit_id=%s)" % (f, r.get("audit_id"))}
        eh = _entry_hash(r)
        if eh != r["entry_hash"]:
            return {"intact": False, "length": n, "broken_at": r.get("chain_hash"),
                    "reason": "content was altered (entry_hash mismatch) for audit_id=%s" % r.get("audit_id")}
        if _chain_hash(r["prev_hash"], eh) != r["chain_hash"]:
            return {"intact": False, "length": n, "broken_at": r.get("chain_hash"),
                    "reason": "chain_hash does not match prev_hash+entry_hash for audit_id=%s" % r.get("audit_id")}

    by_prev = {}
    for r in recs:
        by_prev.setdefault(r["prev_hash"], []).append(r)
    if len(by_prev.get(GENESIS, [])) != 1:
        return {"intact": False, "length": n, "broken_at": None,
                "reason": "expected exactly one GENESIS record, found %d" % len(by_prev.get(GENESIS, []))}

    idx, tip = 0, GENESIS
    while True:
        nxt = by_prev.get(tip, [])
        if not nxt:
            break
        if len(nxt) > 1:
            return {"intact": False, "length": n, "broken_at": tip,
                    "reason": "fork: %d records share prev_hash %s" % (len(nxt), tip[:12])}
        cur = nxt[0]
        if cur.get("seq") is not None and cur.get("seq") != idx:
            return {"intact": False, "length": n, "broken_at": cur.get("chain_hash"),
                    "reason": "seq out of order: expected %d, got %s (audit_id=%s)" % (idx, cur.get("seq"), cur.get("audit_id"))}
        idx += 1
        tip = cur["chain_hash"]
    if idx != n:
        return {"intact": False, "length": n, "broken_at": None,
                "reason": "chain covers %d of %d records (orphaned / gap / reordered)" % (idx, n)}

    return {"intact": True, "length": n, "broken_at": None, "reason": "chain intact: %d linked records" % n}


def handler(event, context):
    e = event or {}
    if isinstance(e, str):
        try:
            e = json.loads(e)
        except Exception:
            e = {}
    return verify(e.get("records", []))


if __name__ == "__main__":
    data = json.load(open(sys.argv[1])) if len(sys.argv) > 1 else json.load(sys.stdin)
    if isinstance(data, dict):
        data = data.get("records", [])
    result = verify(data)
    print(json.dumps(result, indent=2))
    sys.exit(0 if result["intact"] else 1)
