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

## Production evolution

Replace the demo key wrapper with a real control plane:

- AWS KMS for key wrapping and deletion orchestration
- S3 object connectors
- Postgres / RDS connector for live-system deletes
- Warehouse tombstones for analytics pipelines
- Restore detection to re-apply deletion after backup restore
- Signed evidence bundles for auditors

## Important limitation
The MVP demonstrates cryptographic erasure mechanics. It does not claim to solve every real-world deletion problem by itself.
