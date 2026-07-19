import evidence

# write_audit — the gateway-exposed evidence tool. Thin wrapper over the CANONICAL evidence service
# (evidence.py), so the tool and every internal writer share one hash-chain + WORM implementation.
# Re-exports the chain primitives for tests / back-compat.

GENESIS = evidence.GENESIS
entry_hash = evidence.entry_hash
chain_hash = evidence.chain_hash
build_record = evidence.build_record


def handler(event, context):
    return evidence.record_event(event, context)
