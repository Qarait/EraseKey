# Project brief

## Purpose

Explore a narrow failure mode in cryptographic deletion: a backup restore can
bring back both ciphertext and the wrapped key needed to read it.

## The problem
Teams promise deletion, but modern cloud systems replicate data into snapshots, versioned object stores, analytics pipelines, and long-lived backups. A row delete in the primary database does not reliably erase those copies.

## Approach
When a deletion is finalized, EraseKey destroys wrapped subject keys and writes
a signed receipt outside the application database. If stale state later
resurrects those keys, the receipt blocks new writes and drives re-erasure.

## Included
- Subject-scoped envelope encryption
- Dataset registration
- Record ingestion under active subject keys
- Legal holds
- Deletion request workflow
- Cryptographic erasure execution
- Audit events and evidence export
- External signed deletion receipts
- Stale-restore reconciliation

## Not included
- Full privacy request intake portal or compliance dashboard
- Cross-cloud support
- Connector marketplaces or automatic discovery across every system
- Machine unlearning
- Immutable compliance archive design

The useful part of the project is the continuity protocol: deletion intent is
recorded outside the database that may later be rolled back.
