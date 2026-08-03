# governed-core

The versioned governance layer that the regulated-agent verticals are built on. It is a **library of
controls**, not an application: hash-chained WORM evidence, a separation-of-duties sign-off gate,
exactly-once finalization, identity and provenance verification, and the deploy/runtime engine that
carries them into AWS.

Built on AWS. This is a reference implementation, not an official AWS solution, and it does not confer
compliance on anything — see [What this does and does not claim](#what-this-does-and-does-not-claim).

## Why this package exists

Four vertical agents — pharmacovigilance, benefits eligibility, financial aid, housing eligibility —
each need the same security-critical control plane. They used to carry *copies* of it. On 2026-08-03 a
cross-repo check found the consequence: an exactly-once finalization control existed in two of the four
and was missing from the other two, while all four integrity locks recorded the same tree hash, so
every repo's CI was green. In a pharmacovigilance workflow the missing control is a duplicate-ICSR
risk — the same case reported to a regulator twice.

Worse, when the package was finally compared against the agents, **all four agents agreed with each
other and all four differed from this package**, which had no exactly-once control at all. The
verticals were ahead; the nominal source of truth was stale.

This package is the fix: one artifact, one version, consumed by pinned hash instead of copied.

## Install

Pin the released wheel by URL and hash. Nothing here is on PyPI.

```
governed-core @ https://github.com/virtualryder/governed-core/releases/download/v1.3.1/governed_core-1.3.1-py3-none-any.whl \
  --hash=sha256:<see RELEASE-HASHES.txt on the release>
```

`pip install --require-hashes` will refuse the install if the artifact ever changes, which is the
property that makes this a dependency rather than a copy with extra steps.

## What is in here

| Path | What it is |
|---|---|
| `src/governed_core/controls/` | The control plane. `evidence.py` (hash-chained append-only ledger), `verify_chain.py`, `write_audit.py`, `identity.py`, `request_signoff.py` / `approve_signoff.py` (separation of duties), `finalize_signoff.py` (exactly-once commit gate), `mcp_client.py`, `idp_group_mapper.py`. |
| `src/governed_core/engine/` | Deploy engine — manifest rendering, Cedar policy and Step Functions ASL templates. |
| `src/governed_core/runtime/` | The AgentCore runtime image and its bootstrap scripts. |
| `src/governed_core/connector/` | System-of-record connector scaffolding and source verification. |
| `src/governed_core/core.lock` | Integrity lock. `verify_core.py` re-hashes every core file and fails on drift. |

### The two integrity questions, which are not the same question

- **`verify_core.py`** — does *this checkout* match *its own* lock? Intra-repo. Run it anywhere,
  including in a consumer that vendors a copy.
- **`tools/check_core_parity.py`** (in `governed-agent-platform`) — do the consumers match *this
  package*, and do their version pins agree? Cross-repo.

The lock header used to claim "every vertical carries this identical core." It did not, and asserting
it is precisely what stopped anyone from checking. The lock now states its real scope, and the
`version` field means **"derived from governed-core \<version\>"** — not "byte-identical to every
sibling," which was never true and cannot be, because the domain-shaped modules legitimately differ.

## What this does and does not claim

- It does **not** make a system GxP-compliant, Part 11-compliant, HIPAA-compliant, or FedRAMP
  authorized. It implements **controls that support** those validation activities. Validation is owned
  by the deploying organization.
- It is **not** an official AWS solution or an AWS-supported product.
- The agents built on it are **assistants**. They do not award, adjudicate, deny, or auto-submit
  anything. Every consequential action terminates at a human sign-off gate.

## Releasing

```bash
python -m pytest tests -q
python src/governed_core/verify_core.py          # must exit 0
python src/governed_core/regen_core_lock.py --bump minor   # if the core changed
python -m build --wheel
```

Then attach the wheel and its sha256 to a GitHub Release tagged `v<version>`, and bump the pin in each
consumer. `verify_core.py`, the version-sync test, and the wheel build all run in CI on every push.

## License

Apache-2.0.
