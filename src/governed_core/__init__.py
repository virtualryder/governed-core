"""governed-core — the versioned governance operating layer shared by every regulated vertical.

This is the single source of truth for the Cedar-authorized controls, the canonical hash-chained
WORM evidence service, the separation-of-duties human sign-off gate, the provenance and identity
verifiers, the deploy/render engine, and the AgentCore runtime. Each vertical agent PINS a released
version of this package (`governed-core==<x.y.z>`) instead of copying it, so a hardening fix is
released once and adopted by a version bump — drift across verticals becomes impossible to merge.

Layout note: the control/connector modules import each other by bare name (`import evidence`) because
at AgentCore/Lambda runtime the deploy engine bundles them flat next to each tool handler. Importing
this package puts the `controls/` and `connector/` directories on `sys.path` so that same flat-import
contract holds for local tooling and tests, without changing a line of the runtime code.
"""
import pathlib
import sys

CORE_ROOT = pathlib.Path(__file__).resolve().parent

try:
    __version__ = (CORE_ROOT / "CORE_VERSION").read_text(encoding="utf-8").strip()
except OSError:  # pragma: no cover
    __version__ = "0.0.0"

# Preserve the flat-import contract (`import evidence`, `import identity`, `import sor_api`).
for _sub in ("controls", "connector"):
    _p = str(CORE_ROOT / _sub)
    if _p not in sys.path:
        sys.path.insert(0, _p)


def controls_dir() -> pathlib.Path:
    """Absolute path to the bundled control modules (used by the deploy engine and tests)."""
    return CORE_ROOT / "controls"


def connector_dir() -> pathlib.Path:
    return CORE_ROOT / "connector"


def engine_dir() -> pathlib.Path:
    return CORE_ROOT / "engine"
