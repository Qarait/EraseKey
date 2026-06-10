# Architecture

```text
Client / Privacy Operations
            |
            v
       FastAPI API
            |
     Service layer
       /         \
      v           v
 SQLite state   Signed receipt journal
      |
      v
 Key provider (local AES-GCM or AWS KMS)
```

## Key hierarchy

1. A configured key provider generates or unwraps data-encryption keys.
2. Each subject has a wrapped key scoped to its tenant and dataset.
3. Record payloads are encrypted with their subject key.

Subject-scoped keys make deletion granular. A dataset-wide key would make a
single person's erasure too coarse because destroying it would affect every
record in the dataset.

## Record flow

When a record is created, the service resolves the tenant, dataset, and subject
key, encrypts the JSON payload with AES-GCM, and stores the ciphertext and
authenticated metadata in SQLite.

## Erasure flow

An approved deletion request enters a configurable execution window. Once it
is finalized, EraseKey removes the wrapped subject key, marks the subject as
erased, appends a signed deletion receipt, and records the action in the audit
chain. The ciphertext remains but can no longer be decrypted through the
application.

## Restore flow

A stale database backup may still contain a wrapped key that existed before
deletion. The append-only receipt journal is stored separately from the
database backup. After a restore, reconciliation verifies the journal and
reapplies any missing erasures before records are served.

## Limitations

- The local API is unauthenticated unless authentication is explicitly enabled.
- The local key and receipt-signing secret are development conveniences.
- SQLite updates and receipt appends are separate writes. A process failure
  between them can leave the two stores inconsistent; a production design
  should use an outbox or another transactional handoff.
- The audit hash chain detects edits only while its head is independently
  trusted. A database administrator could otherwise rewrite the chain.
