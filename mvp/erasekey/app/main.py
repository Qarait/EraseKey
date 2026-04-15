from __future__ import annotations

from typing import Optional

from fastapi import FastAPI

from .config import settings
from .db import init_db
from .schemas import (
    DatasetCreate,
    DatasetOut,
    DeletionRequestCreate,
    DeletionRequestOut,
    EvidenceOut,
    HealthOut,
    LegalHoldCreate,
    LegalHoldOut,
    RecordCreate,
    RecordOut,
    TenantCreate,
    TenantOut,
)
from .services import (
    create_dataset,
    create_deletion_request,
    create_legal_hold,
    create_record,
    create_tenant,
    execute_deletion_request,
    get_deletion_request,
    get_evidence,
    list_audit_events,
    list_datasets,
    list_tenants,
    read_record,
    release_legal_hold,
    cancel_deletion_request,
    finalize_deletion_request,
)

app = FastAPI(
    title='EraseKey API',
    version='0.1.0',
    description=(
        'Deletion Assurance MVP: encrypts subject-scoped records with envelope encryption, '
        'supports legal holds, and performs cryptographic erasure by destroying wrapped subject keys.'
    ),
)


@app.on_event('startup')
def startup() -> None:
    init_db()


@app.get('/healthz', response_model=HealthOut)
def healthz() -> HealthOut:
    return HealthOut(status='ok', app=settings.app_name)


@app.post('/tenants', response_model=TenantOut, status_code=201)
def api_create_tenant(payload: TenantCreate) -> TenantOut:
    return TenantOut(**create_tenant(payload))


@app.get('/tenants', response_model=list[TenantOut])
def api_list_tenants() -> list[TenantOut]:
    return [TenantOut(**item) for item in list_tenants()]


@app.post('/datasets', response_model=DatasetOut, status_code=201)
def api_create_dataset(payload: DatasetCreate) -> DatasetOut:
    return DatasetOut(**create_dataset(payload))


@app.get('/datasets', response_model=list[DatasetOut])
def api_list_datasets(tenant_id: Optional[str] = None) -> list[DatasetOut]:
    return [DatasetOut(**item) for item in list_datasets(tenant_id)]


@app.post('/records', response_model=RecordOut, status_code=201)
def api_create_record(payload: RecordCreate) -> RecordOut:
    return RecordOut(**create_record(payload))


@app.get('/records/{record_id}', response_model=RecordOut)
def api_read_record(record_id: str) -> RecordOut:
    return RecordOut(**read_record(record_id))


@app.post('/legal-holds', response_model=LegalHoldOut, status_code=201)
def api_create_legal_hold(payload: LegalHoldCreate) -> LegalHoldOut:
    return LegalHoldOut(**create_legal_hold(payload))


@app.post('/legal-holds/{hold_id}/release', response_model=LegalHoldOut)
def api_release_legal_hold(hold_id: str) -> LegalHoldOut:
    return LegalHoldOut(**release_legal_hold(hold_id))


@app.post('/deletion-requests', response_model=DeletionRequestOut, status_code=201)
def api_create_deletion_request(payload: DeletionRequestCreate) -> DeletionRequestOut:
    return DeletionRequestOut(**create_deletion_request(payload))


@app.get('/deletion-requests/{request_id}', response_model=DeletionRequestOut)
def api_get_deletion_request(request_id: str) -> DeletionRequestOut:
    return DeletionRequestOut(**get_deletion_request(request_id))


@app.post('/deletion-requests/{request_id}/execute', response_model=DeletionRequestOut)
def api_execute_deletion_request(request_id: str) -> DeletionRequestOut:
    return DeletionRequestOut(**execute_deletion_request(request_id))


@app.get('/deletion-requests/{request_id}/evidence', response_model=EvidenceOut)
def api_get_evidence(request_id: str) -> EvidenceOut:
    return EvidenceOut(**get_evidence(request_id))

@app.post('/deletion-requests/{request_id}/cancel', response_model=DeletionRequestOut)
def api_cancel_deletion_request(request_id: str) -> DeletionRequestOut:
    return DeletionRequestOut(**cancel_deletion_request(request_id))

@app.post('/deletion-requests/{request_id}/finalize', response_model=DeletionRequestOut)
def api_finalize_deletion_request(request_id: str) -> DeletionRequestOut:
    return DeletionRequestOut(**finalize_deletion_request(request_id))

@app.get('/audit-events')
def api_list_audit_events(entity_type: Optional[str] = None, entity_id: Optional[str] = None):
    return list_audit_events(entity_type=entity_type, entity_id=entity_id)
