import hashlib
import hmac
import json
import os

# provenance.py — the SHARED authoritative-source provenance signer/verifier (P0-3).
#
# THE DEFECT THIS FIXES: a determination tool (assess_housing_eligibility, and the analogous
# EDU / benefits / PV assessors) used to trust income limits + an `il_source` label that arrived in
# the tool CALL BODY. Any caller could hand it fabricated numbers plus a string that says
# "US Dept of Housing and Urban Development — authoritative" and the determination would be issued —
# and written to the WORM audit — as if it came from the real federal source. Provenance you can type
# is not provenance.
#
# THE FIX: the ONLY component that actually reached the authoritative source (lookup_income_limit,
# which alone made the HUD USER API call) SIGNS the exact values it fetched with a per-deploy secret
# (env PROVENANCE_SECRET, injected into the lookup + assess Lambdas at deploy time, never in the repo).
# The downstream assessor VERIFIES that signature against the values it was handed before it will treat
# them as authoritative. A caller without the secret cannot forge the signature, and cannot alter a
# single limit number without breaking it. No valid signature -> the values are UNVERIFIED -> the
# determination is NEEDS_REVIEW with authoritative:false. Fail-closed: secret absent, token missing,
# or any mismatch all resolve to "not authoritative", never to a fabricated authoritative determination.
#
# HMAC (symmetric) is deliberate: signer and verifier are two Lambdas in the SAME deployment/account
# that already share a trust boundary; a per-deploy shared secret is the least machinery that binds the
# values to the genuine lookup. (The connector system-of-record, a cross-trust-boundary case, uses
# asymmetric RS256/JWKS instead — see lib/connector/sor_api.py.)

_SECRET_ENV = "PROVENANCE_SECRET"
_ALG = "HMAC-SHA256"


def _secret():
    return (os.environ.get(_SECRET_ENV) or "").encode("utf-8")


def _norm(o):
    # Numbers cross the gateway as JSON and come back as int OR float (the assessor coerces limits with
    # float()). Normalize integral floats/Decimals to int so a value SIGNED as 50000 still VERIFIES when
    # it arrives as 50000.0 — otherwise a faithfully-passed limit would read as tampered.
    from decimal import Decimal
    if isinstance(o, bool):
        return o
    if isinstance(o, Decimal):
        i = int(o)
        return i if o == i else float(o)
    if isinstance(o, float):
        return int(o) if o.is_integer() else o
    if isinstance(o, dict):
        return {k: _norm(v) for k, v in o.items()}
    if isinstance(o, (list, tuple)):
        return [_norm(v) for v in o]
    return o


def _canon(source, fields):
    return json.dumps({"source": source, "fields": _norm(fields)},
                      sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def sign(source, fields):
    """Mint a provenance token for `fields` (the authoritative values fetched from `source`).
    authoritative is True ONLY when a secret is configured AND a signature was produced — so a lookup
    running without the secret self-reports non-authoritative rather than pretending."""
    s = _secret()
    if not s:
        return {"source": source, "authoritative": False, "sig": None, "alg": _ALG,
                "reason": "PROVENANCE_SECRET not configured; source values cannot be signed as authoritative"}
    sig = hmac.new(s, _canon(source, fields).encode("utf-8"), hashlib.sha256).hexdigest()
    return {"source": source, "authoritative": True, "sig": sig, "alg": _ALG}


def verify(source, fields, token):
    """True ONLY if `token` carries a signature that matches HMAC over (token source, `fields`) with the
    shared secret. Missing secret, missing/short token, authoritative!=True, or ANY value mismatch ->
    False (fail-closed). `fields` MUST be rebuilt by the verifier from the values IT will actually use,
    so tampering with any limit after the lookup breaks verification."""
    s = _secret()
    if not s or not isinstance(token, dict):
        return False
    sig = token.get("sig")
    if not sig or token.get("authoritative") is not True:
        return False
    tok_source = token.get("source", source)
    expected = hmac.new(s, _canon(tok_source, fields).encode("utf-8"), hashlib.sha256).hexdigest()
    try:
        return hmac.compare_digest(str(sig), expected)
    except Exception:
        return False
