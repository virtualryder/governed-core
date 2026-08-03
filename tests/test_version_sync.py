"""The two places the version lives must agree.

`pyproject.toml` carries `version` (what pip installs as) and `governed_core/CORE_VERSION` carries the
version the integrity lock is stamped with (what `verify_core.py` checks). They are supposed to be the
same number. On 2026-08-03 they were not: CORE_VERSION said 1.3.1 while pyproject still said 1.3.0,
because a re-lock bumped one and a hand-edit set the other.

That is not cosmetic. Consumers pin `governed-core==<pyproject version>`; the agents assert their core
matches `<CORE_VERSION>`. If those drift, a repo can pin 1.3.0, receive a core stamped 1.3.1, and both
checks still pass individually while the pin means nothing.
"""
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _pyproject_version():
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    # Only the [project] version, not a dependency pin.
    m = re.search(r"^version\s*=\s*[\"']([^\"']+)[\"']", text, re.MULTILINE)
    assert m, "no version found in pyproject.toml"
    return m.group(1)


def _core_version():
    return (ROOT / "src" / "governed_core" / "CORE_VERSION").read_text(encoding="utf-8").strip()


def test_pyproject_and_core_version_agree():
    py, core = _pyproject_version(), _core_version()
    assert py == core, (
        "version drift: pyproject.toml=%s but governed_core/CORE_VERSION=%s. "
        "Re-run regen_core_lock.py --set <ver> and update pyproject to the same value." % (py, core)
    )


def test_lock_records_the_same_version():
    lock = (ROOT / "src" / "governed_core" / "core.lock").read_text(encoding="utf-8")
    locked = None
    for line in lock.splitlines():
        if line.startswith("version:"):
            locked = line.split(":", 1)[1].strip()
            break
    assert locked == _core_version(), (
        "core.lock records version %s but CORE_VERSION is %s" % (locked, _core_version())
    )
