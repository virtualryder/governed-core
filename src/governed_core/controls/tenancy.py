"""tenancy.py — Gate-B B5: tenant identity is DERIVED, never REQUESTED.

THE DEFECT THIS FIXES: mask_pii once stamped `tenant` into the signed sanitized_ref straight from the
tool-call BODY (`e.get("tenant", "default")`) — i.e. the caller/model chose its own tenant. That lets
one tenant mint artifacts that verify as another's, and mis-attributes audit records. A tenant you can
type is not a tenant.

TWO MODES (both derive tenant from a TRUSTED source, never the request body):

  * SINGLE-TENANT / SILO (default) — one PHA per isolated deployment. The tenant id is pinned at deploy
    time (CDK context `tenant` -> env TENANT_ID on every governed Lambda) and is the only source.
    resolve_tenant() ignores request input by design.

  * MULTI-TENANT / HYBRID (env MULTITENANT=1 — phase 107) — one shared control plane serves many
    tenants. The tenant is derived from the VERIFIED JWT `custom:tenant` claim (the human's access token
    is the bearer the gateway already validated; Cedar evaluates that same principal). It is NEVER read
    from the tool-call body. Missing/blank claim => FAIL-CLOSED (refuse), so an un-tenanted or spoofed
    call cannot silently fall back to a default tenant.

In BOTH modes `check_ref_tenant` refuses an artifact whose tenant != the acting tenant, so an artifact
minted for another tenant (even under a shared signing key) is rejected — fail-closed cross-tenant
rejection. The multi-tenant claim path is the documented Gate-B extension, now implemented.

PROMOTED INTO THE CORE (governed-core 1.6.0, 2026-09-02). This module was implemented in the benefits
agent (phase 107) and existed in NEITHER this package nor the other verticals — the same failure shape
as the exactly-once FINAL# gap. Upstreamed so the CANONICAL evidence writer (evidence.py), the
exactly-once finalize marker and the pending-approvals register route to the acting tenant's PHYSICAL
ledger / WORM vault / approvals table, instead of the shared base stores, in multi-tenant mode.
"""
import base64
import binascii
import contextvars
import hashlib
import hmac
import json
import os

_ENV = "TENANT_ID"
_MT_ENV = "MULTITENANT"          # "1"/"true"/"yes" => multi-tenant (claim-derived); else silo
_CLAIM = "custom:tenant"         # the VERIFIED JWT claim carrying the tenant id (if the IdP emits it)
_GROUPS_CLAIM = "cognito:groups"  # ALWAYS in a Cognito ACCESS token (custom attrs are not) - Cedar reads it
TENANT_GROUP_PREFIX = "tenant_"   # tenant membership as a Cognito group: tenant_<id>
DEFAULT_TENANT = "default"
# core 1.8.0: a deployment-wide CONTROL-PLANE scope (kill-switch state changes, and nothing else so far).
# A trusted control component binds it explicitly (bind_platform_scope); route_* then return the BASE
# (deployment) ledger / vault even in multi-tenant mode. It can never arrive through tool arguments:
# verified_tenant_from_args refuses it even with a valid signature.
PLATFORM_SCOPE = "__platform__"

# Request-scoped VERIFIED claims. The Lambda entrypoint binds these once per invocation at the trusted
# boundary (set_request_claims), so the data-access layer can route to the acting tenant's store WITHOUT
# threading claims through every function signature. Never bind the request BODY here.
_REQUEST_CLAIMS = contextvars.ContextVar("aegis_request_claims", default=None)


def set_request_claims(claims):
    """Bind the current request's VERIFIED JWT claims (trusted-boundary call). Non-dict clears."""
    _REQUEST_CLAIMS.set(claims if isinstance(claims, dict) else None)


def clear_request_claims():
    _REQUEST_CLAIMS.set(None)


def bind_platform_scope():
    """Trusted control-plane entry (kill_switch_control): route evidence to the deployment's BASE
    ledger + vault. Never call this from a tool handler — tools act for a tenant, not for the platform."""
    _REQUEST_CLAIMS.set({_CLAIM: PLATFORM_SCOPE})


def platform_scoped(claims=None):
    c = _effective_claims(claims)
    return bool(c) and c.get(_CLAIM) == PLATFORM_SCOPE


def _effective_claims(claims):
    return claims if claims is not None else _REQUEST_CLAIMS.get()


class TenantError(Exception):
    """Raised in multi-tenant mode when no verified tenant claim is present (fail-closed)."""


def multitenant_enabled():
    return os.environ.get(_MT_ENV, "").strip().lower() in ("1", "true", "yes", "on")


def tenant_from_claims(claims):
    """Extract the tenant id from VERIFIED JWT claims (custom:tenant). Never from a request body.
    Returns the trimmed tenant id, or None if absent/blank/not-a-dict."""
    if not isinstance(claims, dict):
        return None
    t = claims.get(_CLAIM)
    if isinstance(t, str) and t.strip():
        return t.strip()
    # Fallback: tenant membership as a group. Cognito ACCESS tokens carry cognito:groups (not custom
    # attributes), so this is the tier-free path the gateway/Cedar already evaluate. Accepts a list
    # or a string (space/comma separated). The FIRST tenant_<id> group wins; an identity should hold one.
    g = claims.get(_GROUPS_CLAIM)
    groups = g if isinstance(g, (list, tuple)) else (str(g).replace(",", " ").split() if g else [])
    for grp in groups:
        if isinstance(grp, str) and grp.startswith(TENANT_GROUP_PREFIX) and grp[len(TENANT_GROUP_PREFIX):].strip():
            return grp[len(TENANT_GROUP_PREFIX):].strip()
    return None


def tenant_from_bearer(token):
    """Read custom:tenant from a JWT bearer WITHOUT verifying it — the gateway (CUSTOM_JWT) is the
    verifier; the runtime only reads the already-trusted claim to bind the session tenant / log it.
    Returns None on any decode problem. Never use this for an AUTHORIZATION decision (that is Cedar's
    job at the gateway); use it only for session binding / observability tagging."""
    if not isinstance(token, str) or token.count(".") < 2:
        return None
    payload_b64 = token.split(".")[1]
    payload_b64 += "=" * (-len(payload_b64) % 4)          # pad to a multiple of 4
    try:
        claims = json.loads(base64.urlsafe_b64decode(payload_b64).decode("utf-8"))
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None
    return tenant_from_claims(claims)


def resolve_tenant(_event=None, *, claims=None):
    """Resolve the acting tenant.

    SILO (default): the deployment's pinned TENANT_ID (request input IGNORED).
    MULTI-TENANT (MULTITENANT=1): the VERIFIED custom:tenant claim; FAIL-CLOSED if absent.

    In BOTH modes, request-body tenant values are ignored — identity is derived, never requested.
    Pass `claims` (the gateway-verified JWT claims) in multi-tenant mode.
    """
    if multitenant_enabled():
        t = tenant_from_claims(_effective_claims(claims))
        if not t:
            raise TenantError(
                "multi-tenant: no verified custom:tenant claim; refusing "
                "(tenant is derived from the authenticated identity, never requested)")
        return t
    return os.environ.get(_ENV) or DEFAULT_TENANT


def check_ref_tenant(ref, *, claims=None):
    """True iff the (already signature-verified) ref belongs to the ACTING tenant.
    Fail-closed: not-a-dict, missing tenant field, a mismatch, or (multi-tenant) a missing claim -> False."""
    if not isinstance(ref, dict):
        return False
    try:
        return ref.get("tenant") == resolve_tenant(claims=claims)
    except TenantError:
        return False


def tenant_scoped_name(base, tenant):
    """Per-tenant PHYSICAL resource name (hybrid model: each tenant gets its OWN data store, not a
    shared table with a tenant partition key). Blank tenant -> the base name (single-tenant silo).
    Used by the CDK (per-tenant table/bucket naming) and by the compute layer (routing a claim-derived
    tenant to its store), so naming cannot drift between infra and runtime."""
    t = (tenant or "").strip()
    return f"{t}-{base}" if t else base


def route_store(silo_name, logical, claims=None):
    """Route a logical store to the ACTING tenant's PHYSICAL store name.

    silo (default): the name unchanged ('<prefix>-<logical>').
    multi-tenant: '<prefix>-<tenant>-<logical>' from the VERIFIED claim (request context or explicit),
    FAIL-CLOSED if no tenant. `logical` is the store's stable suffix (e.g. 'case-store'), used to locate
    the insertion point so the derived name matches the CDK's per-tenant DataStack naming exactly."""
    if not multitenant_enabled() or platform_scoped(claims):
        return silo_name
    tenant = resolve_tenant(claims=claims)          # raises TenantError if no verified tenant
    suffix = "-" + logical
    prefix = silo_name[:-len(suffix)] if silo_name.endswith(suffix) else silo_name
    return f"{prefix}-{tenant}-{logical}"


_BUCKET_TEMPLATE_ENV = "WORM_BUCKET_TEMPLATE"   # e.g. "<prefix>-{tenant}-worm-<account>" (CDK-supplied)


def route_bucket(silo_bucket, claims=None):
    """Route the WORM evidence vault to the ACTING tenant's PHYSICAL bucket (hybrid model: one Object
    Lock vault per tenant, `<prefix>-<tenant>-worm-<account>`).

    silo (default): the name unchanged. multi-tenant: WORM_BUCKET_TEMPLATE.format(tenant=...) when the
    deployment supplies it (the CDK does, so naming cannot drift from the per-tenant DataStack);
    otherwise the tenant is inserted before the '-worm-' marker. FAIL-CLOSED: no verified tenant, or a
    silo bucket name the router cannot map, raises TenantError — an evidence record is NEVER written
    to the shared base vault in multi-tenant mode."""
    if not multitenant_enabled() or platform_scoped(claims):
        return silo_bucket
    tenant = resolve_tenant(claims=claims)
    tmpl = os.environ.get(_BUCKET_TEMPLATE_ENV, "").strip()
    if tmpl:
        return tmpl.format(tenant=tenant)
    head, marker, tail = (silo_bucket or "").partition("-worm-")
    if not marker:
        raise TenantError("multi-tenant: cannot route WORM bucket %r to tenant %r (set %s)"
                          % (silo_bucket, tenant, _BUCKET_TEMPLATE_ENV))
    return f"{head}-{tenant}-worm-{tail}"


# ---- interceptor-injected tenant (phase 107 routing correction) --------------------------------
# AgentCore Gateway does NOT forward JWT claims to a Lambda target, so the gateway REQUEST interceptor
# (tenant_interceptor.py) derives the tenant from the validated JWT and injects it into the tool
# arguments as a reserved, HMAC-SIGNED pair. The target trusts it ONLY if the signature verifies, so a
# caller/model-supplied tenant (unsigned or wrong key) is refused even if the interceptor were bypassed.
TENANT_FIELD = "__aegis_tenant"
TENANT_SIG_FIELD = "__aegis_tenant_sig"


def sign_tenant(tenant, secret):
    """HMAC-SHA256 over the tenant with the per-deploy provenance secret (same trust domain as
    mask_pii's sanitized_ref signature)."""
    key = bytes(secret) if isinstance(secret, (bytes, bytearray)) else str(secret).encode("utf-8")
    return hmac.new(key, ("tenant|" + str(tenant)).encode("utf-8"), hashlib.sha256).hexdigest()


def verified_tenant_from_args(args, secret):
    """The interceptor-injected tenant, accepted ONLY if its HMAC verifies. None otherwise (fail-closed)."""
    if not isinstance(args, dict) or not secret:
        return None
    t, sig = args.get(TENANT_FIELD), args.get(TENANT_SIG_FIELD)
    if not isinstance(t, str) or not t.strip() or not isinstance(sig, str):
        return None
    t = t.strip()
    if t == PLATFORM_SCOPE:                       # control-plane scope is never a request tenant
        return None
    if not hmac.compare_digest(sign_tenant(t, secret), sig):
        return None
    return t


def _default_secret():
    try:
        import provenance
        return provenance._secret()   # same resolver/trust domain as the interceptor
    except Exception:
        return os.environ.get("PROVENANCE_SECRET", "")


def signed_binding(tenant=None, secret=None):
    """The signed tenant pair to CARRY the acting tenant across a trust hop that has no interceptor
    (a Step Functions execution input, a start_execution payload). {} when there is no bound tenant
    (silo) so callers can splat it unconditionally. Every downstream Lambda re-verifies the HMAC via
    bind_tenant_from_args, so the pair cannot be forged or altered in execution state."""
    if tenant is None:
        try:
            tenant = resolve_tenant() if multitenant_enabled() else None
        except TenantError:
            tenant = None
    if not tenant:
        return {}
    return {TENANT_FIELD: tenant, TENANT_SIG_FIELD: sign_tenant(tenant, secret if secret is not None else _default_secret())}


def bind_tenant_from_args(args, secret=None):
    """Tool-Lambda entrypoint helper: verify the injected tenant and bind it for routing
    (set_request_claims). Returns the tenant or None; multi-tenant callers treat None as fail-closed."""
    if secret is None:
        secret = _default_secret()
    t = verified_tenant_from_args(args, secret)
    set_request_claims({_CLAIM: t} if t else None)
    return t
