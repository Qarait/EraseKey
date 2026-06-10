# Product brief

## Working title
EraseKey

## Positioning
Restore-safe deletion continuity for security engineers.

## The problem
Teams promise deletion, but modern cloud systems replicate data into snapshots, versioned object stores, analytics pipelines, and long-lived backups. A row delete in the primary database does not reliably erase those copies.

## The project wedge

Most privacy products orchestrate requests and connectors. EraseKey explores a
different failure mode: old snapshots can restore data and key material after a
deletion appeared complete.

## Core promise
When a deletion is finalized, EraseKey destroys wrapped subject keys and writes
a signed receipt outside the application database. If stale state later
resurrects those keys, the receipt blocks new writes and drives re-erasure.

## Intended audience

Security and backend engineers learning about envelope encryption, irreversible
state machines, stale restores, evidence, and recovery controls.

## MVP scope
- Subject-scoped envelope encryption
- Dataset registration
- Record ingestion under active subject keys
- Legal holds
- Deletion request workflow
- Cryptographic erasure execution
- Audit events and evidence export
- External signed deletion receipts
- Stale-restore reconciliation

## Non-goals for MVP
- Full privacy request intake portal or compliance dashboard
- Cross-cloud support
- Connector marketplaces or automatic discovery across every system
- Machine unlearning
- Immutable compliance archive design

## Why this direction is distinct

The interesting artifact is not the deletion endpoint. It is the continuity
protocol that remembers an erasure outside the database being restored.
