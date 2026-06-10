# EraseKey

EraseKey demonstrates subject-scoped encryption and deletion that survives a
stale database restore. It is a local engineering project, not a general privacy
operations platform.

Instead of pretending every copy of user data can be physically deleted immediately, this service encrypts subject-scoped records with envelope encryption and then makes them unreadable by destroying the wrapped subject keys. The ciphertext remains in place (mirroring backups/cold storage), but is rendered cryptographically unrecoverable.

## What it demonstrates

- Tenant and dataset scoped records.
- One envelope-encryption key per subject.
- Mock and AWS KMS key providers.
- A deletion lifecycle:
    - **Pending**: Request created but not yet executed.
    - **Scheduled**: Request executed; keys are in a "Pending Erasure" state for a mandatory waiting period. Access is blocked.
    - **Finalized**: Wrapped keys are destroyed; erasure is complete.
- Legal holds that block scheduling and finalization.
- A hash-chained audit log.
- Signed deletion receipts stored outside SQLite.
- Reconciliation that removes keys resurrected by a stale restore.
- Write blocking for subjects with pending or completed deletion.

## Tech Stack

- **FastAPI**: Core API framework.
- **SQLite**: Local metadata and key-state store.
- **AES-256-GCM**: Envelope encryption via `cryptography`.
- **boto3**: AWS KMS integration.

## Repository Layout

```text
app/
  auth.py           # Local step-up challenge boundary
  config.py         # Environment-driven configuration
  crypto.py         # AES-256-GCM logic
  db.py             # SQLite schema and connections
  key_providers.py  # Mock/AWS Root Key Providers
  main.py           # API routes and entry point
  policy_engine.py  # Local and external policy adapters
  receipts.py       # Signed deletion receipt journal
  schemas.py        # Pydantic models
  services.py       # Core business logic
  utils.py          # ID generation and hashing
scripts/
  aws_smoke_test.py # Verification for AWS KMS connectivity
  finalize_worker.py # Background worker for due deletions
tests/
  test_flow.py      # E2E lifecycle and safety tests
  test_security.py  # Step-up, policy, and audit tests
```

## Running Locally

1. Install dependencies:
   ```bash
   cd mvp/erasekey
   python -m venv .venv
   source .venv/bin/activate  # or .venv\Scripts\activate on Windows
   pip install -r requirements.txt -r requirements-dev.txt
   ```

2. Run the server:
   ```bash
   uvicorn app.main:app --reload
   ```

3. Open the API docs at `http://127.0.0.1:8000/docs`.

## Configuration

EraseKey behavior is controlled by environment variables:

| Variable | Default | Description |
| :--- | :--- | :--- |
| `ERASEKEY_KMS_MODE` | `mock` | `mock` for local development, `aws` for the AWS adapter. |
| `ERASEKEY_AWS_KMS_KEY_ID` | None | The ARN or ID of the CMK in AWS KMS. |
| `ERASEKEY_DELETION_WINDOW_DAYS` | `7` | Mandatory waiting period before keys can be destroyed. |
| `ERASEKEY_RECEIPT_LOG_PATH` | `data/deletion_receipts.jsonl` | Receipt journal stored separately from application state. |
| `ERASEKEY_RECEIPT_SIGNING_KEY_PATH` | `data/.receipt_signing_key` | Local HMAC key used to sign and identify receipts in demo mode. |
| `ERASEKEY_STEP_UP_MODE` | `mock` | `webauthn` is reserved but not implemented. |
| `ERASEKEY_POLICY_ENGINE_MODE` | `local` | Set to `gate1` to exercise the fail-closed external adapter. |

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
4. Restart EraseKey, or call `POST /admin/restore/reconcile` explicitly.
5. EraseKey verifies the external receipt journal, matches the keyed subject reference, and destroys the restored key again before serving startup traffic.

`GET /admin/deletion-receipts/verify` verifies every receipt signature.

The automated test `test_restore_reconciliation_re_erases_resurrected_key`
executes this scenario end to end.

## Scope and security

The API has no production authentication and should not be exposed to an
untrusted network. The local HMAC journal is enough to demonstrate the restore
protocol. A production design would keep receipts in immutable storage and use a
managed signing key outside the database backup domain.

Finalization updates SQLite and appends to the receipt file as two separate
writes. The receipt is flushed first and is authoritative if the SQLite commit
fails; receipt creation is idempotent and startup reconciliation completes the
erasure before requests are served. This is still not a distributed
transaction, and concurrent application processes require external
serialization.

The receipt journal and signing key must be stored outside the database
backup's storage and administrative domain. Merely choosing another path on the
same disk does not provide restore independence.
