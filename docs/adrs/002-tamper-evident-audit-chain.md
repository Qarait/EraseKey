# ADR 002: Tamper-Evident Audit Chaining

## Context
A major premise of EraseKey's deletion assurance is an honest, verifiable audit trail. Simple database logs are subject to retroactive local modifications. Auditors require a mathematical mechanism to detect if an event was tampered with, deleted, or back-dated.

## Decision
We will employ a robust cryptographic hash-chain across the `audit_events` ledger, utilizing a precise domain-separated hashing mechanism.

1.  **Hash Algorithm Contract**:
    The chain is computed iteratively using stable row-insert order (using auto-incremented primary keys or stable sequence IDs rather than vulnerable timestamps alone).
    `event_hash = sha256("erasekey.audit.v1\n" + prev_hash + "\n" + canonical_json(event_core))`
2.  **State Object (`event_core`)**:
    Contains structured properties isolated from DB vagaries: `event_type`, `timestamp`, `actor`, `tenant`, `target_id` (request/hold id), and `payload`.
3.  **Migration & Backfill Strategy**:
    *   Transforming the state must be strictly additive. We will run an `ALTER TABLE` to append `prev_hash`, `event_hash`, and a sequence indicator.
    *   Legacy, unchained records will be systematically backfilled on startup: iterating in insertion-order to compute hashes sequentially, joining the new strict chain naturally without destroying log history.
4.  **Verification API Boundaries**:
    *   `GET /admin/audit/verify` explicitly checks chain mathematical integrity, returning: `ok (bool)`, `verified_count`, `first_bad_event_id`, `expected_hash`, and `actual_hash`.
    *   `GET /admin/audit/head` efficiently returns the latest contiguous valid hash, to serve as an anchoring point for external monitoring.
5.  **Evidence Honesty**:
    *   The `EvidenceOut` representation for scheduled or finalized requests will explicitly embed: `audit_event_id`, `event_hash`, `prev_hash`, and `chain_version`. We discard the vague "chain_proof" nomenclature for raw clarity.

## Consequences
- Requires a one-time automatic backfill algorithm loaded on app start for existing SQLite databases.
- Dramatically increases the reliability characteristics of `.evidence_json` by securely anchoring it to a verifiable ledger context.
