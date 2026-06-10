# ADR 002: Hash-chained audit events

## Status

Accepted.

## Context

Deletion evidence should reveal edits to existing audit rows. A conventional
SQLite table does not provide that property.

## Decision

Each audit event stores the hash of the previous event and its own event hash:

```text
sha256("erasekey.audit.v1\n" + prev_hash + "\n" + canonical_json(event))
```

Events are ordered by SQLite `rowid`. The hashed event includes the action,
timestamp, actor, tenant, entity, and payload.

`GET /admin/audit/verify` walks the chain and reports the first mismatch.
`GET /admin/audit/head` returns the latest stored hash.

## Consequences

- Editing or reordering an existing event breaks verification.
- The chain is tamper-evident, not immutable. An attacker with full database
  access could rewrite the table and recompute every hash.
- External anchoring would be required for stronger evidence.
