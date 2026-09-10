"""Canonical serialisation and hashing, shared by every component.

The verifier on the ledger host recomputes digests over records it pulls back
from the primary. That only works if both hosts serialise a record to exactly
the same bytes, so the serialisation is defined once, here, and imported by the
agent and the verifier rather than restated in each program. A divergence
between two copies of these three lines would surface as a phantom TAMPER alert
and would be very hard to diagnose.

Build spec section 3.2:
    json.dumps(obj, sort_keys=True, separators=(",", ":"))
"""

import hashlib
import json

# Chain head before any entry exists. Spec section 3.3: genesis is 64 zeros.
GENESIS = "0" * 64

# Reserved event string for liveness beats. Under full root the cheapest attack
# is not tampering but `kill`: stop the agent, append unwitnessed records,
# restart it. A beat on a fixed interval turns that silence into a gap the
# ledger can see, using its own receipt times rather than the primary's.
HEARTBEAT_EVENT = "__heartbeat__"


def canonical_bytes(record):
    """Return the exact bytes a record's digest is taken over.

    `record` is the record object only -- {"seq", "ts", "event"} -- never the
    envelope that carries the digest alongside it. Hashing the digest field
    into its own digest would make the record unverifiable.
    """
    return json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")


def compute_digest(record):
    """SHA-256 of the canonical record, as lowercase hex."""
    return hashlib.sha256(canonical_bytes(record)).hexdigest()


def next_chain_hash(digest, prev_chain):
    """Bind a digest to the chain head before it.

    Spec section 3.3:
        chain_hash[n] = SHA256(digest[n] || chain_hash[n-1])

    Altering or removing entry n invalidates n and every entry after it, so
    concealing one edit means rewriting the whole subsequent chain -- on a host
    the primary cannot write to.
    """
    return hashlib.sha256((digest + prev_chain).encode("utf-8")).hexdigest()
