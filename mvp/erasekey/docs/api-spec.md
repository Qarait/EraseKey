# API overview

## POST /tenants
Create a tenant.

## GET /tenants
List tenants.

## POST /datasets
Create a dataset under a tenant.

## GET /datasets?tenant_id=
List datasets, optionally filtered by tenant.

## POST /records
Ingest an encrypted record.

Request body:

```json
{
  "tenant_id": "tenant_xxx",
  "dataset_id": "dataset_xxx",
  "subject_id": "user_123",
  "record_type": "ticket",
  "payload": {"email": "user@example.com", "message": "Delete me"}
}
```

## GET /records/{record_id}
Read a record. Returns `erase_status=cryptographically_erased` when the key is gone.

## POST /legal-holds
Create a legal hold.

## POST /legal-holds/{hold_id}/release
Release a legal hold.

## POST /deletion-requests
Create a deletion request.

## GET /deletion-requests/{request_id}
Read deletion-request status.

## POST /deletion-requests/{request_id}/execute
Execute cryptographic erasure for active subject keys.

## GET /deletion-requests/{request_id}/evidence
Return machine-readable evidence after execution.

## GET /audit-events
List recent audit events. Supports `entity_type` and `entity_id` filters.
