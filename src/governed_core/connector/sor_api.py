import json
import os
import base64
import time
import hashlib
import urllib.request
import urllib.error

# sor_api.py — MOCK external "system of record" (stands in for a real verification service such as EIV,
# a student information system, or a safety database). It is OAuth2-PROTECTED: every request must carry a
# valid Cognito machine-to-machine (client_credentials) access token with the required scope. Exposed via
# an API Gateway HTTP API. It is NOT a stub: a call without a valid, correctly-scoped, unexpired,
# CRYPTOGRAPHICALLY-VERIFIED token from the expected client is rejected (401/403). Reusable across agents —
# the domain label is env-driven.
#
# Token validation now performs FULL RS256 / JWKS signature verification against the Cognito issuer's
# published JSON Web Key Set, in addition to the standard access-token claims (issuer, token_use,
# client_id, scope, exp). The signature check is implemented in PURE PYTHON (PKCS#1 v1.5, SHA-256) so the
# Lambda needs no crypto library on its path — the deploy bundle stays boto3-only. This retires the
# "claims-only" caveat: a token whose signature does not verify against the issuer's live public key is
# rejected, so a forged or tampered token cannot pass even if its claims look correct.
#
# Env:
#   EXPECTED_ISS        the trusted Cognito issuer (https://cognito-idp.<region>.amazonaws.com/<pool>)
#   EXPECTED_CLIENT_ID  the expected M2M app client id
#   REQUIRED_SCOPE      the scope the token must carry (e.g. "<prefix>-sor/read")
#   SOR_LABEL           human label for the mock system of record
#   JWKS_URL            (optional) override; defaults to EXPECTED_ISS + /.well-known/jwks.json
#   VERIFY_SIGNATURE    (optional) "false" disables the RS256 check (claims-only); default enabled

EXPECTED_ISS = os.environ.get("EXPECTED_ISS", "")
EXPECTED_CLIENT_ID = os.environ.get("EXPECTED_CLIENT_ID", "")
REQUIRED_SCOPE = os.environ.get("REQUIRED_SCOPE", "")
SOR_LABEL = os.environ.get("SOR_LABEL", "MOCK-SOR")
JWKS_URL = os.environ.get("JWKS_URL", "")
VERIFY_SIGNATURE = os.environ.get("VERIFY_SIGNATURE", "true").lower() != "false"

# ASN.1 DigestInfo prefix for SHA-256 (RFC 8017 §9.2).
_SHA256_DIGESTINFO = bytes.fromhex("3031300d060960864801650304020105000420")

# module-level JWKS cache: {"url":..., "keys": {kid: jwk}, "exp": epoch}
_JWKS_CACHE = {"url": None, "keys": {}, "exp": 0}


def _b64url(s):
    if isinstance(s, str):
        s = s.encode("ascii")
    s += b"=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def _seg(tok, i):
    parts = tok.split(".")
    if len(parts) != 3:
        return None
    try:
        return json.loads(_b64url(parts[i]))
    except Exception:
        return None


def _jwks_url():
    if JWKS_URL:
        return JWKS_URL
    if EXPECTED_ISS:
        return EXPECTED_ISS.rstrip("/") + "/.well-known/jwks.json"
    return ""


def _fetch_jwks(url):
    req = urllib.request.Request(url, headers={"User-Agent": "sor-api/1.0"})
    with urllib.request.urlopen(req, timeout=5) as r:
        doc = json.loads(r.read().decode("utf-8"))
    return {k.get("kid"): k for k in doc.get("keys", []) if k.get("kty") == "RSA" and k.get("kid")}


def _jwk_for(kid, force=False):
    now = int(time.time())
    url = _jwks_url()
    if not url:
        return None
    fresh = _JWKS_CACHE["url"] == url and _JWKS_CACHE["exp"] > now and _JWKS_CACHE["keys"]
    if force or not fresh:
        keys = _fetch_jwks(url)
        _JWKS_CACHE.update({"url": url, "keys": keys, "exp": now + 3600})
    return _JWKS_CACHE["keys"].get(kid)


def _pkcs1v15_rs256_ok(n, e, sig, signing_input):
    # Verify an RSASSA-PKCS1-v1_5 / SHA-256 signature with pure integer math.
    k = (n.bit_length() + 7) // 8
    if len(sig) != k:
        return False
    s = int.from_bytes(sig, "big")
    if s <= 0 or s >= n:
        return False
    m = pow(s, e, n)
    em = m.to_bytes(k, "big")
    t = _SHA256_DIGESTINFO + hashlib.sha256(signing_input).digest()
    ps_len = k - 3 - len(t)
    if ps_len < 8:
        return False
    expected = b"\x00\x01" + (b"\xff" * ps_len) + b"\x00" + t
    # length-fixed compare
    return hashlib.sha256(em).digest() == hashlib.sha256(expected).digest()


def _verify_signature(tok):
    # returns (ok, reason)
    parts = tok.split(".")
    if len(parts) != 3:
        return False, "malformed token"
    hdr = _seg(tok, 0)
    if not hdr:
        return False, "malformed header"
    if hdr.get("alg") != "RS256":
        return False, "unexpected alg %s (require RS256)" % hdr.get("alg")
    kid = hdr.get("kid")
    if not kid:
        return False, "no kid in token header"
    signing_input = (parts[0] + "." + parts[1]).encode("ascii")
    try:
        sig = _b64url(parts[2])
    except Exception:
        return False, "bad signature encoding"
    try:
        jwk = _jwk_for(kid)
        if jwk is None:
            jwk = _jwk_for(kid, force=True)  # key rotation: refresh once on a kid miss
        if jwk is None:
            return False, "signing key (kid) not found in issuer JWKS"
        n = int.from_bytes(_b64url(jwk["n"]), "big")
        e = int.from_bytes(_b64url(jwk["e"]), "big")
    except urllib.error.URLError:
        return False, "issuer JWKS unreachable"
    except Exception as ex:
        return False, "JWKS/key error: %s" % type(ex).__name__
    if not _pkcs1v15_rs256_ok(n, e, sig, signing_input):
        return False, "RS256 signature verification failed"
    return True, "ok"


def _resp(code, body):
    return {"statusCode": code, "headers": {"Content-Type": "application/json"}, "body": json.dumps(body)}


def handler(event, context):
    headers = event.get("headers") or {}
    auth = headers.get("authorization") or headers.get("Authorization") or ""
    if not auth.lower().startswith("bearer "):
        return _resp(401, {"error": "missing OAuth2 Bearer token", "www_authenticate": "Bearer"})
    tok = auth.split(" ", 1)[1].strip()

    if VERIFY_SIGNATURE:
        ok, reason = _verify_signature(tok)
        if not ok:
            # unreachable JWKS is an availability failure (503); anything else is a rejected token (401).
            code = 503 if "unreachable" in reason else 401
            return _resp(code, {"error": "token signature not verified", "detail": reason})

    c = _seg(tok, 1)
    if not c:
        return _resp(401, {"error": "malformed token"})
    now = int(time.time())
    if EXPECTED_ISS and c.get("iss") != EXPECTED_ISS:
        return _resp(403, {"error": "wrong issuer"})
    if c.get("token_use") != "access":
        return _resp(403, {"error": "not an access token"})
    if EXPECTED_CLIENT_ID and c.get("client_id") != EXPECTED_CLIENT_ID:
        return _resp(403, {"error": "unrecognized client"})
    if REQUIRED_SCOPE and REQUIRED_SCOPE not in str(c.get("scope", "")).split():
        return _resp(403, {"error": "insufficient scope", "need": REQUIRED_SCOPE, "got": c.get("scope")})
    if int(c.get("exp", 0)) < now:
        return _resp(401, {"error": "token expired"})

    qs = event.get("queryStringParameters") or {}
    case = qs.get("case_id") or "_default"
    return _resp(200, {"system_of_record": SOR_LABEL, "case_id": case, "verified": True,
                       "record": {"status": "on file", "as_of": "2026-06"},
                       "authorized_via": "OAuth2 client_credentials (Cognito M2M)",
                       "token_signature": "RS256/JWKS verified" if VERIFY_SIGNATURE else "claims-only",
                       "client_id": c.get("client_id")})
