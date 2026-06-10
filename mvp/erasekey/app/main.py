from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Optional, Any, Union

from fastapi import FastAPI, Body, HTTPException

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
    ProviderStatusOut,
    StepUpChallenge,
    StepUpAssertion,
    AuditVerificationResult,
    SecurityStatusOut,
    ReceiptVerificationOut,
    RestoreReconciliationOut,
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
    get_audit_head,
    verify_audit_chain,
    list_audit_events,
    list_datasets,
    list_tenants,
    read_record,
    release_legal_hold,
    cancel_deletion_request,
    finalize_deletion_request,
    finalize_due_deletions,
    reconcile_deletion_receipts,
    ActorType,
)
from .auth import verifier
from . import utils
from .receipts import verify_receipt_log


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    yield

app = FastAPI(
    title='EraseKey API',
    version='0.1.0',
    description=(
        'Restore-safe deletion continuity lab: encrypts subject-scoped records, '
        'destroys wrapped keys, and re-applies erasure after stale restores.'
    ),
    lifespan=lifespan,
)


@app.get('/healthz', response_model=HealthOut)
def healthz() -> HealthOut:
    return HealthOut(status='ok', app=settings.app_name)


@app.get('/admin/provider-status', response_model=ProviderStatusOut)
def api_provider_status() -> ProviderStatusOut:
    raw_key_id = settings.aws_kms_key_id or "none"
    # Redact key ID: show suffix only (last 4 chars)
    redacted_id = f"...{raw_key_id[-4:]}" if len(raw_key_id) > 4 else raw_key_id
    
    return ProviderStatusOut(
        kms_mode=settings.kms_mode,
        kms_key_id=redacted_id,
        deletion_window_days=settings.deletion_window_days,
        auto_finalization_enabled=True,
        step_up_mode=settings.step_up_mode
    )


@app.get('/admin/security-status', response_model=SecurityStatusOut)
def api_security_status() -> SecurityStatusOut:
    return SecurityStatusOut(
        step_up_mode=settings.step_up_mode,
        policy_engine_mode=settings.policy_engine_mode,
        is_mock_mode=(settings.step_up_mode == "mock"),
        operator_public_key_id=settings.mock_stepup_pubkey_id
    )


@app.post('/auth/step-up/challenge', response_model=StepUpChallenge)
def api_generate_challenge(action: str, target_resource_id: str, operator_id: str) -> StepUpChallenge:
    token = verifier.generate_challenge(action, target_resource_id, operator_id)
    # 5 minute expiry is hardcoded in auth.py
    expires_at = (utils.utc_now_dt() + utils.timedelta(minutes=5)).isoformat()
    return StepUpChallenge(
        challenge=token,
        action=action,
        target_resource_id=target_resource_id,
        operator_id=operator_id,
        expires_at=expires_at
    )


def verify_step_up(
    action: str,
    target_resource_id: str,
    auth: Optional[Union[StepUpAssertion, dict[str, Any]]] = None
) -> bool:
    """Validate and verify a step-up assertion."""
    if not auth:
        return False
    
    try:
        if isinstance(auth, dict):
            validated_auth = StepUpAssertion.model_validate(auth)
        else:
            validated_auth = auth
    except Exception:
        return False

    return verifier.verify_assertion(
        challenge_token=validated_auth.challenge,
        assertion_payload=validated_auth.assertion_payload.model_dump(),
        action=action,
        target_resource_id=target_resource_id,
        operator_id=validated_auth.operator_id
    )


@app.get('/admin/audit/verify', response_model=AuditVerificationResult)
def api_verify_audit_chain() -> AuditVerificationResult:
    return AuditVerificationResult(**verify_audit_chain())


@app.get('/admin/audit/head')
def api_get_audit_head():
    return {"head_hash": get_audit_head()}


@app.get('/admin/deletion-receipts/verify', response_model=ReceiptVerificationOut)
def api_verify_deletion_receipts() -> ReceiptVerificationOut:
    return ReceiptVerificationOut(**verify_receipt_log())


@app.post('/admin/restore/reconcile', response_model=RestoreReconciliationOut)
def api_reconcile_restored_data() -> RestoreReconciliationOut:
    return RestoreReconciliationOut(**reconcile_deletion_receipts())


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
def api_release_legal_hold(
    hold_id: str, 
    auth: Optional[StepUpAssertion] = Body(None)
) -> LegalHoldOut:
    if auth is None:
        raise HTTPException(status_code=403, detail="Policy Denied: STEP_UP_REQUIRED")
    is_verified = verify_step_up("release_legal_hold", hold_id, auth)
    return LegalHoldOut(**release_legal_hold(hold_id, step_up_verified=is_verified, actor_type=ActorType.HUMAN))


@app.post('/deletion-requests', response_model=DeletionRequestOut, status_code=201)
def api_create_deletion_request(payload: DeletionRequestCreate) -> DeletionRequestOut:
    return DeletionRequestOut(**create_deletion_request(payload))


@app.get('/deletion-requests/{request_id}', response_model=DeletionRequestOut)
def api_get_deletion_request(request_id: str) -> DeletionRequestOut:
    return DeletionRequestOut(**get_deletion_request(request_id))


@app.post('/deletion-requests/{request_id}/execute', response_model=DeletionRequestOut)
def api_execute_deletion_request(
    request_id: str,
    auth: Optional[StepUpAssertion] = Body(None)
) -> DeletionRequestOut:
    if auth is None:
        raise HTTPException(status_code=403, detail="Policy Denied: STEP_UP_REQUIRED")
    is_verified = verify_step_up("execute", request_id, auth)
    return DeletionRequestOut(**execute_deletion_request(request_id, step_up_verified=is_verified, actor_type=ActorType.HUMAN))


@app.get('/deletion-requests/{request_id}/evidence', response_model=EvidenceOut)
def api_get_evidence(request_id: str) -> EvidenceOut:
    return EvidenceOut(**get_evidence(request_id))

@app.post('/deletion-requests/{request_id}/cancel', response_model=DeletionRequestOut)
def api_cancel_deletion_request(
    request_id: str,
    auth: Optional[StepUpAssertion] = Body(None)
) -> DeletionRequestOut:
    if auth is None:
        raise HTTPException(status_code=403, detail="Policy Denied: STEP_UP_REQUIRED")
    is_verified = verify_step_up("cancel", request_id, auth)
    return DeletionRequestOut(**cancel_deletion_request(request_id, step_up_verified=is_verified, actor_type=ActorType.HUMAN))

@app.post('/deletion-requests/{request_id}/finalize', response_model=DeletionRequestOut)
def api_finalize_deletion_request(
    request_id: str,
    auth: Optional[StepUpAssertion] = Body(None)
) -> DeletionRequestOut:
    if auth is None:
        raise HTTPException(status_code=403, detail="Policy Denied: STEP_UP_REQUIRED")
    is_verified = verify_step_up("finalize", request_id, auth)
    return DeletionRequestOut(**finalize_deletion_request(request_id, step_up_verified=is_verified, actor_type=ActorType.HUMAN))

@app.get('/audit-events')
def api_list_audit_events(entity_type: Optional[str] = None, entity_id: Optional[str] = None):
    return list_audit_events(entity_type=entity_type, entity_id=entity_id)
