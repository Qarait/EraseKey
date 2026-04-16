# EraseKey

EraseKey is a Deletion Assurance MVP inspired by the cryptographic-erasure thesis in Article 3.

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

## Deletion Semantics

1. **`POST /deletion-requests/{id}/execute`**:
   Moves a request from `pending` to `scheduled`. Associated subject keys enter `pending_erasure` state. Data becomes unreadable via the API.
2. **`POST /deletion-requests/{id}/cancel`**:
   Reverts a `scheduled` request to `canceled`. Keys return to `active` state and data is readable again. Only possible before finalization.
3. **`POST /deletion-requests/{id}/finalize`**:
   Destroys the wrapped subject keys. This is irreversible.
4. **Automatic Finalization**:
   Run `python scripts/finalize_worker.py` to automatically finalize all requests whose waiting period has expired.
