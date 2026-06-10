# ADR 004: External Deletion Continuity Receipts

## Context

Destroying a wrapped subject key in the live database does not guarantee that
the key stays destroyed. Restoring an older database snapshot can resurrect
both ciphertext and wrapped key material.

Keeping the deletion marker only inside the restored database creates a circular
dependency: the system forgets the deletion at the same moment it restores the
old state.

## Decision

Finalized deletions produce an HMAC-signed receipt in an append-only journal
outside SQLite.

Each receipt contains:

- tenant and dataset scope;
- a keyed reference derived from the subject identifier;
- deletion request and request hash;
- finalization time;
- audit-chain event hash;
- receipt version and signature.

The raw subject identifier is not written to the external journal.

Before accepting a subject write, EraseKey checks both database deletion state
and valid external receipts. A reconciliation operation scans restored subject
keys, compares keyed references, and destroys matching resurrected key material.

## Consequences

- A stale SQLite restore cannot silently make finalized data usable again while
  the external journal and signing key remain trustworthy.
- Receipt verification fails closed for writes and reconciliation.
- Reconciliation is intentionally linear in the number of candidate subject
  keys and receipts for this small lab.
- Production deployments must put the journal and signing key in a different
  backup and administrative trust domain from the application database.
- HMAC is a demo choice. A production evidence format should use asymmetric
  signatures and an immutable external store.
