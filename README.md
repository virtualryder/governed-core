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
governed-core @ https://github.com/virtualryder/governed-core/releases/download/v1.9.0/governed_core-1.9.0-py3-none-any.whl \
  --hash=sha256:<see RELEASE-HASHES.txt on the release>
```

`pip install --require-hashes` will refuse the install if the artifact ever changes, which is the
property that makes this a dependency rather than a copy with extra steps.

## What is in here

| Path | What it is |
|---|---|
| `src/governed_core/controls/` | The control plane. `evidence.py` (hash-chained append-only ledger), `verify_chain.py`, `write_audit.py`, `identity.py`, `request_signoff.py` / `approve_signoff.py` (separation of duties), `finalize_signoff.py` (exactly-once commit gate), `tenancy.py` + `tenant_interceptor.py` (hybrid multi-tenant: tenant DERIVED from the verified identity by the AgentCore Gateway request interceptor, carried as an HMAC-signed pair, and the ledger / WORM vault / approvals register routed to the acting tenant's physically separate stores — 1.6.0), `telemetry.py` (1.7.0: one correlation set — tenant · session · trace · mcp-session · execution · request · case — carried by the interceptor and the workflow, hashed into every WORM record, and emitted as one structured `aegis.call` log line per tool invocation), `kill_switch.py` + `kill_switch_control.py` (1.8.0: the one-command CONTAINMENT control on the AgentCore path — every component reads the deployment's SSM kill-switch FIRST, fail-closed, 15 s TTL; the interceptor short-circuits with 403 and a DENIED WORM record, tool Lambdas refuse at `telemetry.instrument`; engage / disengage are two IAM-authenticated function URLs with IAM-verified actors, separation of duties on release, every state change a COMMITTED ledger record), `budget.py` (1.9.0: the LIVE per-tenant token + USD meter — one conditional DynamoDB reservation before every model call, real Converse usage committed after, pinned price table with recorded version, gateway-side check, CloudWatch metrics for 60/85/100 % alarms; fail-closed on a hard cap), `mcp_client.py`, `idp_group_mapper.py`. |
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

## Version history (what each release added, and which consumer proved it live)

| Version | Added | Live proof |
|---|---|---|
| 1.3.1 | package split out of the verticals; integrity lock | — |
| 1.4.0 | GA-5 duplicate-submission protection promoted into `signoff_register` | benefits |
| 1.5.0 | `finalize_signoff` verifies the APPROVAL PATH (SoD + consumed-by-`approve_signoff`), fail-closed | benefits (raw `send-task-success` refused live) |
| 1.6.0 | **hybrid multi-tenant**: `tenancy` + `tenant_interceptor` promoted into the core; the canonical evidence writer, exactly-once `FINAL#` marker and pending-approvals register route to the acting tenant's own ledger / WORM vault / approvals table, fail-closed; the signed tenant pair rides the Step Functions execution input | benefits `evidence/AGENTCORE-MULTITENANT-AUDIT-2026-09-02.md` (2 tenants, 12/12) |
| 1.7.0 | **correlation** (`telemetry.py`): tenant · session · trace · mcp-session · execution · request · case carried by the interceptor and the workflow, hashed into every WORM record, one structured `aegis.call` log line per tool invocation; `evidence.tenant_id` is the DERIVED tenant | — |
| 1.7.1 | interceptor reads the MCP `params._meta` trace context (what the Strands MCP client actually propagates) | benefits `evidence/AGENTCORE-OBSERVABILITY-2026-09-02.md` (real AgentCore Runtime, 2 tenants, 13/13 each) |
| 1.8.0 | **kill switch** (`kill_switch.py`, `kill_switch_control.py`): containment precedes evaluation on the AgentCore path — interceptor (403 + DENIED WORM record in the acting tenant's ledger), every tool Lambda (`telemetry.instrument` raises `KillSwitchEngaged`), runtime hook; fail-closed on an unreadable switch; many-to-one (deployment + platform-wide parameters); engage-only / disengage-only controller functions with IAM-verified actors and SoD on release; `tenancy.PLATFORM_SCOPE` for deployment-wide control-plane records (never injectable via tool args) | benefits `evidence/AGENTCORE-KILL-SWITCH-2026-09-03.md` (real Runtime, 2 tenants, 29/29, time-to-effect 13.9 s) |
| 1.9.0 | **per-tenant budget** (`budget.py`): reserve-before / commit-after on every model call (atomic conditional ADD, cannot oversell), USD estimate from a pinned price table (version recorded on every commit), per-tenant cap overrides by PutItem, gateway interceptor refuses a tenant at/over cap (403 + DENIED WORM record), metrics for 60/85/100 % alarms; hard = fail-closed, soft = flag | benefits `evidence/AGENTCORE-BUDGET-2026-09-03.md` (pending) |

Consumers pin one of these by URL + sha256 (`requirements-core.txt`, `--require-hashes`); the wheel and
`RELEASE-HASHES.txt` on each release are attached by CI (from 1.7.0; earlier releases were hand-uploaded).
CI on this repo was red from 1.3.1 to 1.5.0 (tests ran without `PYTHONPATH=src`) — fixed in 1.6.0.

## Releasing

```bash
python -m pytest tests -q
python src/governed_core/verify_core.py          # must exit 0
python src/governed_core/regen_core_lock.py --bump minor   # if the core changed
SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)" python -m build --wheel
```

Then tag `v<version>`, create the GitHub Release, and let CI attach the wheel and `RELEASE-HASHES.txt`
(the tag run has `contents: write`); bump the pin in each consumer to the hash **on the release**.
A local build is NOT byte-identical to CI's across platforms even with `SOURCE_DATE_EPOCH` (checked
2026-09-02: Windows vs ubuntu builds of the same commit differ — zip entry attributes), so the asset
CI attaches is the one consumers pin; a hand-uploaded asset must be the one the pin was taken from. `verify_core.py`, the version-sync test, and the wheel build all run in CI on every push.

## License

Apache-2.0.
