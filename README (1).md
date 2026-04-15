# EraseKey

EraseKey is a Deletion Assurance MVP inspired by the cryptographic-erasure thesis in Article 3.

Instead of pretending every copy of user data can be physically deleted immediately, this service encrypts subject-scoped records with envelope encryption and then makes them unreadable by destroying the wrapped subject keys. The ciphertext can remain in place, which mirrors the reality of backups and cold storage.

## What this MVP does

- Creates tenants and datasets
- Encrypts records under subject-scoped data keys
- Reuses active subject keys for new records until deletion
- Supports legal holds that block erasure
- Executes cryptographic erasure by destroying wrapped subject keys
- Produces deletion evidence and an audit trail
- Returns `cryptographically_erased` for records whose keys were destroyed

## What this MVP does not do yet

- Real AWS KMS integration
- Key deletion waiting periods and cancellation windows
- Data lineage discovery across warehouses, queues, and feature stores
- Restore-safe re-deletion after snapshot recovery
- Policy-driven retention across multiple cloud accounts
- Search tokenization for encrypted fields
- Production auth, RBAC, rate limiting, or SIEM integration

## Tech stack

- FastAPI
- SQLite for the MVP metadata store
- AES-256-GCM envelope encryption via `cryptography`

## Run locally

```bash
cd erasekey
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open the API docs at `http://127.0.0.1:8000/docs`.

## Demo flow

1. Create a tenant.
2. Create a dataset.
3. Ingest one or more records for the same subject.
4. Read the record back and confirm it is decryptable.
5. Create and execute a deletion request.
6. Read the same record again and confirm `erase_status=cryptographically_erased`.
7. Fetch deletion evidence.

## Sample curl commands

Create a tenant:

```bash
curl -s -X POST http://127.0.0.1:8000/tenants \
  -H 'Content-Type: application/json' \
  -d '{"name":"Acme Health"}'
```

Create a dataset:

```bash
curl -s -X POST http://127.0.0.1:8000/datasets \
  -H 'Content-Type: application/json' \
  -d '{"tenant_id":"tenant_xxx","name":"support_tickets","description":"Customer support transcripts"}'
```

Ingest a record:

```bash
curl -s -X POST http://127.0.0.1:8000/records \
  -H 'Content-Type: application/json' \
  -d '{
    "tenant_id":"tenant_xxx",
    "dataset_id":"dataset_xxx",
    "subject_id":"user_123",
    "record_type":"ticket",
    "payload":{"email":"user@example.com","message":"Please delete my account."}
  }'
```

Create a deletion request:

```bash
curl -s -X POST http://127.0.0.1:8000/deletion-requests \
  -H 'Content-Type: application/json' \
  -d '{
    "tenant_id":"tenant_xxx",
    "dataset_id":"dataset_xxx",
    "subject_id":"user_123",
    "requested_by":"privacy-team",
    "reason":"GDPR erasure request"
  }'
```

Execute the deletion request:

```bash
curl -s -X POST http://127.0.0.1:8000/deletion-requests/delreq_xxx/execute
```

Fetch evidence:

```bash
curl -s http://127.0.0.1:8000/deletion-requests/delreq_xxx/evidence
```

## Repository layout

```text
app/
  config.py
  crypto.py
  db.py
  main.py
  schemas.py
  services.py
docs/
  antigravity-playbook.md
  architecture.md
  product-brief.md
tests/
  test_flow.py
```

## Next production steps

- Swap the demo root key provider for AWS KMS or Vault
- Split metadata, key orchestration, and evidence services
- Add auth and per-tenant access control
- Add object-storage connectors and warehouse tombstoning
- Build restore detection and re-delete automation
- Add signed evidence exports and policy packs
