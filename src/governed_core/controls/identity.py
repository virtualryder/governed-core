import base64
import hashlib
import json
import os
import time
import urllib.request
import urllib.error

# identity.py — verify a Cognito ACCESS token and return the caller's cryptographically-verified identity
# and group membership. Pure stdlib RS256 / JWKS (PKCS#1 v1.5, SHA-256) — no crypto library on the Lambda
# path, same primitive proven in lib/connector/sor_api.py.
#
# P0-5: the human sign-off gate derives the REQUESTER (request_signoff) and the APPROVER (approve_signoff)
# from THIS verifier — never from an "approver"/"requester" string in the event body. A spoofed
# `{"approver":"someone"}` with no valid token cannot pass, and separation-of-duties is enforced on the
# verified usernames. Fail-closed: missing / malformed / forged / expired / wrong-issuer / wrong-client /
# not-in-required-group all resolve to "not verified".
#
# Env:
#   COGNITO_ISS       trusted issuer https://cognito-idp.<region>.amazonaws.com/<pool_id>
#                     (or set POOL_ID [+ AWS_REGION] and it is derived)
#   CLIENT_ID         expected app client id (the access token's `client_id` claim)
#   REVIEWER_GROUP    group the identity must belong to (from verified cognito:groups)
#   VERIFY_SIGNATURE  optional "false" -> claims-only (unit tests / offline); default: verify

_SHA256_DIGESTINFO = bytes.fromhex("3031300d060960864801650304020105000420")
_JWKS_CACHE = {"url": None, "keys": {}, "exp": 0}


def _iss():
    iss = os.environ.get("COGNITO_ISS", "")
    if iss:
        return iss.rstrip("/")
    pool = os.environ.get("POOL_ID", "")
    region = os.environ.get("AWS_REGION", "us-east-1")
    return "https://cognito-idp.%s.amazonaws.com/%s" % (region, pool) if pool else ""


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
    override = os.environ.get("JWKS_URL", "")
    if override:
        return override
    iss = _iss()
    return iss.rstrip("/") + "/.well-known/jwks.json" if iss else ""


def _fetch_jwks(url):
    req = urllib.request.Request(url, headers={"User-Agent": "identity/1.0"})
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
        _JWKS_CACHE.update({"url": url, "keys": _fetch_jwks(url), "exp": now + 3600})
    return _JWKS_CACHE["keys"].get(kid)


def _pkcs1v15_rs256_ok(n, e, sig, signing_input):
    k = (n.bit_length() + 7) // 8
    if len(sig) != k:
        return False
    s = int.from_bytes(sig, "big")
    if s <= 0 or s >= n:
        return False
    em = pow(s, e, n).to_bytes(k, "big")
    t = _SHA256_DIGESTINFO + hashlib.sha256(signing_input).digest()
    ps_len = k - 3 - len(t)
    if ps_len < 8:
        return False
    expected = b"\x00\x01" + (b"\xff" * ps_len) + b"\x00" + t
    return hashlib.sha256(em).digest() == hashlib.sha256(expected).digest()


def _verify_signature(tok):
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
        jwk = _jwk_for(kid) or _jwk_for(kid, force=True)  # refresh once on a kid miss (key rotation)
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


def verify_access_token(tok, require_group=True):
    """Return (claims, None) if the token is a valid Cognito access token for this pool/client (and, when
    require_group, the identity is in REVIEWER_GROUP); otherwise (None, reason). Fail-closed."""
    if not tok or not isinstance(tok, str):
        return None, "no access token presented"
    if os.environ.get("VERIFY_SIGNATURE", "true").lower() != "false":
        ok, reason = _verify_signature(tok)
        if not ok:
            return None, reason
    c = _seg(tok, 1)
    if not c:
        return None, "malformed token"
    now = int(time.time())
    iss = _iss()
    if iss and c.get("iss") != iss:
        return None, "wrong issuer"
    if c.get("token_use") != "access":
        return None, "not an access token"
    cid = os.environ.get("CLIENT_ID", "")
    if cid and c.get("client_id") != cid:
        return None, "unrecognized client"
    if int(c.get("exp", 0)) < now:
        return None, "token expired"
    grp = os.environ.get("REVIEWER_GROUP", "")
    if require_group and grp and grp not in (c.get("cognito:groups") or []):
        return None, "identity not in required group '%s'" % grp
    return c, None


def identity_of(claims):
    """The stable username for a verified access token."""
    return (claims or {}).get("username") or (claims or {}).get("cognito:username") or (claims or {}).get("sub") or ""
