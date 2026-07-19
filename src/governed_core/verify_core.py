#!/usr/bin/env python3
"""Governance-core integrity check (P0-9). Verifies that this vertical's lib/ (the shared, versioned
governance core) exactly matches the pinned version recorded in lib/core.lock — no silent drift.

The governance core (Cedar controls, evidence service, sign-off gate, provenance/identity verifiers,
deploy engine, runtime) is IDENTICAL across all four agents and is versioned as a unit. CI runs this
script; a mismatch fails the build. To change the core, edit it, run regen_core_lock.py to bump the
version + re-lock, and sync the identical core to every vertical. Stdlib only. Exit 0 = OK, 1 = drift."""
import hashlib
import os
import sys

LIB = os.path.dirname(os.path.abspath(__file__))          # the lib/ directory (this file lives in lib/)
ROOT = os.path.dirname(LIB)
LOCK = os.path.join(LIB, "core.lock")
EXCL_DIRS = {".venv", "__pycache__", ".bedrock_agentcore", ".work", ".build"}
NAMES = {"Dockerfile", "requirements.txt", "CORE_VERSION", ".dockerignore"}
EXTS = {".py", ".sh", ".tmpl"}


def _sha256(path):
    # Normalize line endings before hashing so the lock is identical whether the repo is checked out on
    # Windows (CRLF) or a Linux CI runner (LF) — otherwise CI would report false drift. Core files are
    # all small text files.
    with open(path, "rb") as fh:
        data = fh.read()
    data = data.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    return hashlib.sha256(data).hexdigest()


def discover():
    """Return {repo-relative-path: abspath} for every governance-core file under lib/ (excluding the
    lock file and runtime state)."""
    out = {}
    for base, dirs, files in os.walk(LIB):
        dirs[:] = [d for d in dirs if d not in EXCL_DIRS]
        for f in files:
            p = os.path.join(base, f)
            if os.path.abspath(p) == LOCK:
                continue
            _, ext = os.path.splitext(f)
            if f in NAMES or ext in EXTS:
                rel = os.path.relpath(p, ROOT).replace("\\", "/")
                out[rel] = p
    return out


def parse_lock():
    ver = None
    locked = {}
    with open(LOCK, encoding="utf-8") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if line.startswith("version:"):
                ver = line.split(":", 1)[1].strip()
            elif line and not line.startswith("#") and not line.startswith(("files:", "tree_sha256:")):
                parts = line.split("  ", 1)
                if len(parts) == 2:
                    locked[parts[1].strip()] = parts[0].strip()
    return ver, locked


def main():
    if not os.path.exists(LOCK):
        print("DRIFT: lib/core.lock is missing", file=sys.stderr)
        return 1
    ver, locked = parse_lock()
    on_disk = discover()
    problems = []
    for rel, want in sorted(locked.items()):
        p = on_disk.get(rel)
        if p is None:
            problems.append("MISSING core file: %s" % rel)
            continue
        got = _sha256(p)
        if got != want:
            problems.append("MODIFIED core file: %s" % rel)
    for rel in sorted(on_disk):
        if rel not in locked:
            problems.append("UNLOCKED core file (added without re-locking): %s" % rel)
    if problems:
        print("governance core DRIFT vs pinned version %s:" % ver, file=sys.stderr)
        for pr in problems:
            print("  - " + pr, file=sys.stderr)
        print("If this change is intentional, run: python lib/regen_core_lock.py --bump <patch|minor|major>", file=sys.stderr)
        return 1
    print("governance core v%s OK (%d files, no drift)" % (ver, len(locked)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
