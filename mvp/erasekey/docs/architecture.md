# Architecture

## MVP architecture

```text
Client / Privacy Ops
        |
        v
   FastAPI Service
        |
        +--> SQLite metadata store
        |      - tenants
        |      - datasets
        |      - subject_keys
        |      - records
        |      - legal_holds
        |      - deletion_requests
        |      - audit_events
        |
        +--> Envelope crypto
               - demo root key provider
               - wrapped per-subject data keys

        +--> External receipt journal
               - keyed subject references
               - signed deletion receipts
               - stale-restore reconciliation
```

## Key hierarchy

1. Root key (demo-only in a local file for this repo)
2. Subject-scoped data key per tenant + dataset + subject
3. Individual records encrypted under the active subject data key

## Why subject-scoped keys
Deletion is often requested per person, not per entire dataset. If you encrypt everything with one dataset key, deleting one person’s data becomes too coarse. Subject-scoped keys make deletion granular.

## Record flow

1. Client submits a record with `tenant_id`, `dataset_id`, `subject_id`, and `payload`.
2. EraseKey looks up an active subject key.
3. If none exists, EraseKey generates one and stores only the wrapped form.
4. The payload is encrypted with AES-256-GCM.
5. The encrypted record and authenticated metadata are stored.

## Erasure flow

1. Privacy team creates a deletion request.
2. EraseKey checks for active legal holds.
3. If blocked, the request stays blocked.
4. If allowed, EraseKey destroys the wrapped subject keys.
5. Records encrypted under those keys become unreadable.
6. An evidence object is written back to the request and the audit log.

## Why ciphertext remains in the MVP
That is deliberate. The product is modeling backup and cold-storage reality: data copies may continue to exist physically, but once key material is gone, those copies are no longer usable.

## Deletion continuity after restore

SQLite is not the source of truth for completed erasures. Finalization also
writes a signed receipt to a separate append-only journal. The receipt contains
a keyed subject reference rather than the raw subject identifier.

After restoring stale application state, the restore guard:

1. verifies the journal signatures;
2. scans local subject keys in the receipted tenant and dataset;
3. derives keyed references for local subjects;
4. destroys any resurrected wrapped key that matches a receipt;
5. adds a `restore.re_erased` event to the audit chain.

The receipt journal and its signing key must live outside the database backup
domain for this property to hold.

## Production evolution

Replace the demo key wrapper with a real control plane:

- AWS KMS for key wrapping and deletion orchestration
- S3 object connectors
- Postgres / RDS connector for live-system deletes
- Warehouse tombstones for analytics pipelines
- Signed evidence bundles for auditors

## Important limitation
The MVP demonstrates deletion continuity mechanics. The local API is
unauthenticated, and the local receipt signing key is a teaching substitute for
a separate managed signing service.
