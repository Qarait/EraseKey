# API Summary

FastAPI publishes the complete OpenAPI document at `/docs`. This page is a
short map of the available routes.

## Service and diagnostics

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/healthz` | Basic service health |
| `GET` | `/admin/provider-status` | Active key-provider details |
| `GET` | `/admin/security-status` | Authentication and policy-engine status |
| `GET` | `/admin/audit/head` | Current audit-chain head |
| `GET` | `/admin/audit/verify` | Verify the audit-event chain |
| `GET` | `/admin/deletion-receipts/verify` | Verify the signed receipt journal |
| `POST` | `/admin/restore/reconcile` | Reapply deletion receipts after a stale restore |

## Step-up challenges

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/auth/step-up/challenge` | Issue a short-lived challenge for sensitive operations |

The bundled challenge mechanism is a local demonstration. It is not a
replacement for an identity provider or production MFA.

## Tenants, datasets, and records

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/tenants` | Create a tenant |
| `GET` | `/tenants` | List tenants |
| `POST` | `/datasets` | Create a dataset for a tenant |
| `GET` | `/datasets` | List datasets, optionally filtered by tenant |
| `POST` | `/records` | Encrypt and store a record |
| `GET` | `/records/{record_id}` | Decrypt a live record |

## Holds and deletion requests

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/legal-holds` | Place a legal hold |
| `POST` | `/legal-holds/{hold_id}/release` | Release a legal hold |
| `POST` | `/deletion-requests` | Create a deletion request |
| `GET` | `/deletion-requests/{request_id}` | Read request state |
| `POST` | `/deletion-requests/{request_id}/execute` | Schedule erasure, or finalize immediately when the window is zero |
| `POST` | `/deletion-requests/{request_id}/cancel` | Cancel a scheduled request |
| `POST` | `/deletion-requests/{request_id}/finalize` | Finalize a due request |
| `GET` | `/deletion-requests/{request_id}/evidence` | Return deletion evidence |
| `GET` | `/audit-events` | List audit events with optional entity filters |
