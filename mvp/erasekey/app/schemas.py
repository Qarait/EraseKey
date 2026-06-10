from __future__ import annotations

from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class KeyState(str, Enum):
    active = "active"
    pending_erasure = "pending_erasure"
    destroyed = "destroyed"


class RequestStatus(str, Enum):
    pending = "pending"
    blocked = "blocked"
    scheduled = "scheduled"
    canceled = "canceled"
    finalized = "finalized"


class EraseStatus(str, Enum):
    readable = "readable"
    scheduled_for_erasure = "scheduled_for_erasure"
    cryptographically_erased = "cryptographically_erased"


class TenantCreate(BaseModel):
    name: str = Field(min_length=2, max_length=120)


class TenantOut(BaseModel):
    id: str
    name: str
    created_at: str


class DatasetCreate(BaseModel):
    tenant_id: str
    name: str = Field(min_length=2, max_length=120)
    description: Optional[str] = None
    retention_days: Optional[int] = Field(default=None, ge=1)


class DatasetOut(BaseModel):
    id: str
    tenant_id: str
    name: str
    description: Optional[str]
    retention_days: Optional[int]
    created_at: str


class RecordCreate(BaseModel):
    tenant_id: str
    dataset_id: str
    subject_id: str = Field(min_length=1, max_length=120)
    record_type: str = Field(min_length=1, max_length=80)
    payload: dict[str, Any]


class RecordOut(BaseModel):
    id: str
    tenant_id: str
    dataset_id: str
    subject_id: str
    record_type: str
    created_at: str
    payload: Optional[dict[str, Any]] = None
    key_state: KeyState
    erase_status: EraseStatus


class LegalHoldCreate(BaseModel):
    tenant_id: str
    dataset_id: Optional[str] = None
    subject_id: Optional[str] = None
    reason: str = Field(min_length=3, max_length=500)


class LegalHoldOut(BaseModel):
    id: str
    tenant_id: str
    dataset_id: Optional[str]
    subject_id: Optional[str]
    reason: str
    active: bool
    created_at: str
    released_at: Optional[str]


class DeletionRequestCreate(BaseModel):
    tenant_id: str
    dataset_id: str
    subject_id: str
    requested_by: str = Field(min_length=2, max_length=120)
    reason: str = Field(min_length=3, max_length=500)


class DeletionRequestOut(BaseModel):
    id: str
    tenant_id: str
    dataset_id: str
    subject_id: str
    requested_by: str
    reason: str
    status: RequestStatus
    blocked_reason: Optional[str]
    created_at: str
    executed_at: Optional[str]  # When transitioning from pending to scheduled (or immediate)
    canceled_at: Optional[str] 
    finalized_at: Optional[str]
    request_hash: str


class EvidenceOut(BaseModel):
    request_id: str
    status: RequestStatus
    evidence: dict[str, Any]
    audit_event_id: Optional[str] = None
    event_hash: Optional[str] = None
    prev_hash: Optional[str] = None
    chain_version: int = 1


class StepUpChallenge(BaseModel):
    challenge: str
    action: str
    target_resource_id: str
    expires_at: str
    operator_id: str


class WebAuthnAssertion(BaseModel):
    clientDataJSON: str
    authenticatorData: str
    signature: str


class StepUpAssertion(BaseModel):
    challenge: str
    assertion_payload: WebAuthnAssertion
    operator_id: str


class AuditVerificationResult(BaseModel):
    ok: bool
    verified_count: int
    first_bad_event_id: Optional[str] = None
    expected_hash: Optional[str] = None
    actual_hash: Optional[str] = None
    head_hash: Optional[str] = None


class HealthOut(BaseModel):
    status: str
    app: str


class ProviderStatusOut(BaseModel):
    kms_mode: str
    kms_key_id: Optional[str]
    deletion_window_days: int
    auto_finalization_enabled: bool
    step_up_mode: str


class SecurityStatusOut(BaseModel):
    step_up_mode: str
    policy_engine_mode: str
    is_mock_mode: bool
    operator_public_key_id: str


class ReceiptVerificationOut(BaseModel):
    ok: bool
    receipt_count: int
    invalid_receipt_ids: list[str]


class RestoreReconciliationOut(BaseModel):
    ok: bool
    verified_receipts: int
    matched_receipt_ids: list[str]
    re_erased_key_ids: list[str]

