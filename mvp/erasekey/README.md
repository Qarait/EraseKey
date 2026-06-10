# EraseKey Restore Lab

EraseKey is a restore-safe cryptographic-erasure experiment. It is deliberately
not a privacy request portal, compliance dashboard, or connector marketplace.

Instead of pretending every copy of user data can be physically deleted immediately, this service encrypts subject-scoped records with envelope encryption and then makes them unreadable by destroying the wrapped subject keys. The ciphertext remains in place (mirroring backups/cold storage), but is rendered cryptographically unrecoverable.

## Core Features

- **Multi-Tenant & Dataset Scoped**: Organize keys and records by tenant and dataset.
- **Subject-Scoped Keys**: Automatically manages cryptographic keys on a per-subject basis (e.g., per user).
- **AWS KMS Integration**: Support for real AWS KMS as the Root Key Provider.
- **Deletion Lifecycle**:
    - **Pending**: Request created but not yet executed.
    - **Scheduled**: Request executed; keys are in a "Pending Erasure" state for a mandatory waiting period. Access is blocked.
    - **Finalized**: Wrapped keys are destroyed; erasure is complete.
- **Legal Holds**: Holds block both the transition to "Scheduled" and the final "Finalized" step.
- **Audit Trail**: Every action (ingestion, hold, schedule, destroy) produces a signed-hash audit event.
- **Deletion Receipts**: Finalization writes a signed receipt to an append-only journal outside SQLite.
- **Restore Guard**: A stale SQLite restore can be scanned against the receipt journal and re-erased.
- **Resurrection Prevention**: Scheduled or receipted subjects cannot receive new records.

## Tech Stack

- **FastAPI**: Core API framework.
- **SQLite**: Local metadata and key-state store.
- **AES-256-GCM**: Envelope encryption via `cryptography`.
- **boto3**: AWS KMS integration.

## Repository Layout

```text
app/
  config.py         # Environment-driven configuration
  crypto.py         # AES-256-GCM logic
  db.py             # SQLite schema and connections
  key_providers.py  # Mock/AWS Root Key Providers
  main.py           # API routes and entry point
  schemas.py        # Pydantic models
  services.py       # Core business logic
  utils.py          # ID generation and hashing
scripts/
  aws_smoke_test.py # Verification for AWS KMS connectivity
  finalize_worker.py # Background worker for due deletions
tests/
  test_flow.py      # E2E lifecycle and safety tests
```

## Running Locally

1. Install dependencies:
   ```bash
   cd mvp/erasekey
   python -m venv .venv
   source .venv/bin/activate  # or .venv\Scripts\activate on Windows
   pip install -r requirements.txt
   ```

2. Run the server:
   ```bash
   uvicorn app.main:app --reload
   ```

3. Open the API docs at `http://127.0.0.1:8000/docs`.

## Production Configuration

EraseKey behavior is controlled by environment variables:

| Variable | Default | Description |
| :--- | :--- | :--- |
| `ERASEKEY_KMS_MODE` | `mock` | `mock` for local development, `aws` for production. |
| `ERASEKEY_AWS_KMS_KEY_ID` | None | The ARN or ID of the CMK in AWS KMS. |
| `ERASEKEY_DELETION_WINDOW_DAYS` | `7` | Mandatory waiting period before keys can be destroyed. |
| `ERASEKEY_RECEIPT_LOG_PATH` | `data/deletion_receipts.jsonl` | Receipt journal stored separately from application state. |
| `ERASEKEY_RECEIPT_SIGNING_KEY_PATH` | `data/.receipt_signing_key` | Local HMAC key used to sign and identify receipts in demo mode. |

## Deletion Semantics

1. **`POST /deletion-requests/{id}/execute`**:
   Moves a request from `pending` to `scheduled`. Associated subject keys enter `pending_erasure` state. Data becomes unreadable via the API.
2. **`POST /deletion-requests/{id}/cancel`**:
   Reverts a `scheduled` request to `canceled`. Keys return to `active` state and data is readable again. Only possible before finalization.
3. **`POST /deletion-requests/{id}/finalize`**:
   Destroys the wrapped subject keys. This is irreversible.
4. **Automatic Finalization**:
   Run `python scripts/finalize_worker.py` to automatically finalize all requests whose waiting period has expired.

## Restore-Safety Demo

1. Create a tenant, dataset, record, and deletion request.
2. Finalize the deletion. EraseKey destroys the wrapped subject key and appends a signed receipt.
3. Simulate a stale restore by putting the old wrapped key back into SQLite.
4. Call `POST /admin/restore/reconcile`.
5. EraseKey verifies the external receipt journal, matches the keyed subject reference, and destroys the restored key again.

`GET /admin/deletion-receipts/verify` verifies every receipt signature.

The automated test `test_restore_reconciliation_re_erases_resurrected_key`
executes this scenario end to end.

## Security Boundary

This repository is a local lab. Its API has no production authentication and
must not be exposed to an untrusted network. The local HMAC journal demonstrates
the protocol, but a real deployment should place receipts and signing keys in a
separate trust domain such as an immutable object store and managed signing
service.
