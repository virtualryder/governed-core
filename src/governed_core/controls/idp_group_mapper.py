import json
import os

# idp_group_mapper — a Cognito **Pre Token Generation (V2_0)** trigger that makes EXTERNAL IdP users
# hit the same Cedar deny-by-default policy as native users, WITHOUT changing a single policy.
#
# The problem: the Cedar permit authorizes on `cognito:groups` (e.g. `... like "*aid_officer*"`). A user
# who federates in from Okta / Entra / any OIDC or SAML IdP does NOT get `cognito:groups` populated from
# their IdP group membership automatically — Cognito only fills `cognito:groups` from *native* Cognito
# groups. So a real employee, correctly in the "FinancialAidOfficers" IdP group, would be denied.
#
# The fix (this Lambda): the IdP's group/role claim is mapped (in the Cognito IdP attribute mapping) to a
# user attribute (default `custom:idp_roles`). On every token issuance this trigger reads that attribute,
# maps each external group to the agent's Cedar role via GROUP_MAP, and OVERRIDES `cognito:groups` with
# the union of the user's native groups + the mapped roles. The existing permit then fires unchanged.
# An external user whose groups map to nothing gets no role -> deny-by-default still holds.
#
# Config (env):
#   GROUP_MAP     JSON object, external-group -> Cedar role, e.g. {"FinancialAidOfficers":"aid_officer"}
#   SOURCE_ATTR   user attribute holding the IdP groups (default "custom:idp_roles")
#   ROLE_GROUP    the agent's Cedar role group (fallback/allow-list); mapped roles are intersected with
#                 the app's known groups only if STRICT=1
#   STRICT        "1" to only ever emit known app roles (recommended); default off (emit whatever maps)
#
# Pure logic (no boto3); the deterministic mapping is unit-tested offline and in CI.

_SEP = [",", ";", " ", "\n", "\t"]


def _split(v):
    if not v:
        return []
    for s in _SEP[1:]:
        v = v.replace(s, ",")
    return [p.strip() for p in v.split(",") if p.strip()]


def _config():
    try:
        gmap = json.loads(os.environ.get("GROUP_MAP", "{}"))
        if not isinstance(gmap, dict):
            gmap = {}
    except Exception:
        gmap = {}
    return {
        "map": gmap,
        "source_attr": os.environ.get("SOURCE_ATTR", "custom:idp_roles"),
        "role_group": os.environ.get("ROLE_GROUP", ""),
        "strict": os.environ.get("STRICT", "") == "1",
    }


def map_groups(user_attributes, native_groups, cfg):
    """Return the sorted `cognito:groups` override: native groups + IdP groups mapped via cfg['map']."""
    src = user_attributes.get(cfg["source_attr"], "") if user_attributes else ""
    external = _split(src)
    mapped = [cfg["map"][g] for g in external if g in cfg["map"]]
    allowed = {cfg["role_group"]} if cfg["strict"] and cfg["role_group"] else None
    if allowed is not None:
        mapped = [m for m in mapped if m in allowed]
    return sorted(set(list(native_groups or []) + mapped))


def handler(event, context):
    cfg = _config()
    req = event.get("request", {}) or {}
    user_attrs = req.get("userAttributes", {}) or {}
    native = ((req.get("groupConfiguration") or {}).get("groupsToOverride")) or []
    groups = map_groups(user_attrs, native, cfg)

    event.setdefault("response", {})
    event["response"]["claimsAndScopeOverrideDetails"] = {
        "groupOverrideDetails": {
            "groupsToOverride": groups,
            "iamRolesToOverride": [],
            "preferredRole": None,
        }
    }
    return event
