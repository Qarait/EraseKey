from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi import HTTPException, status

from .config import settings
from .db import get_conn
from .schemas import DatasetCreate, DeletionRequestCreate, RecordCreate, TenantCreate
from .services import (
    create_dataset,
    create_deletion_request,
    create_record,
    create_tenant,
    execute_deletion_request,
    get_evidence,
    read_record,
    reconcile_deletion_receipts,
    verify_audit_chain,
)
from .receipts import verify_receipt_log
from .utils import canonical_json, new_id


def _rewrite_receipt_log_without_request(request_id: str) -> None:
    log_path = Path(settings.receipt_log_path)
    if not log_path.exists():
        return

    retained_lines: list[str] = []
    for line in log_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            receipt = json.loads(line)
        except json.JSONDecodeError:
            retained_lines.append(line)
            continue
        if receipt.get("request_id") != request_id:
            retained_lines.append(canonical_json(receipt))

    with log_path.open("w", encoding="utf-8") as handle:
        for line in retained_lines:
            handle.write(line + "\n")
        handle.flush()


def _cleanup_public_demo_rows(
    *,
    tenant_id: str,
    dataset_id: str,
    subject_id: str,
    record_id: str,
    request_id: str,
) -> None:
    with get_conn() as conn:
        conn.execute("DELETE FROM records WHERE id = ?", (record_id,))
        conn.execute(
            """
            DELETE FROM subject_keys
            WHERE tenant_id = ? AND dataset_id = ? AND subject_id = ?
            """,
            (tenant_id, dataset_id, subject_id),
        )
        conn.execute("DELETE FROM deletion_requests WHERE id = ?", (request_id,))
        conn.execute("DELETE FROM datasets WHERE id = ?", (dataset_id,))
        conn.execute("DELETE FROM tenants WHERE id = ?", (tenant_id,))
        conn.execute(
            """
            DELETE FROM audit_events
            WHERE entity_id IN (?, ?, ?, ?)
               OR payload_json LIKE ?
            """,
            (
                tenant_id,
                dataset_id,
                record_id,
                request_id,
                f"%{subject_id}%",
            ),
        )
    _rewrite_receipt_log_without_request(request_id)


def run_restore_scenario() -> dict[str, Any]:
    if settings.kms_mode != "mock":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The restore scenario is available only with the local mock KMS.",
        )

    scenario_id = new_id("demo")
    subject_id = f"subject-{scenario_id[-8:]}"
    tenant = create_tenant(TenantCreate(name=f"Restore Lab {scenario_id[-6:]}"))
    dataset = create_dataset(
        DatasetCreate(
            tenant_id=tenant["id"],
            name=f"support-records-{scenario_id[-6:]}",
            description="Local restore-safety demonstration",
        )
    )
    record = create_record(
        RecordCreate(
            tenant_id=tenant["id"],
            dataset_id=dataset["id"],
            subject_id=subject_id,
            record_type="support_profile",
            payload={
                "email": "demo@example.test",
                "note": "Encrypted sample data for the local restore lab",
            },
        )
    )

    with get_conn() as conn:
        key_row = conn.execute(
            """
            SELECT id, wrapped_key, wrapped_key_nonce
            FROM subject_keys
            WHERE tenant_id = ? AND dataset_id = ? AND subject_id = ?
              AND key_state = 'active'
            ORDER BY key_version DESC
            LIMIT 1
            """,
            (tenant["id"], dataset["id"], subject_id),
        ).fetchone()
        if key_row is None:
            raise HTTPException(status_code=500, detail="Demo subject key was not created.")
        stale_key = {
            "id": key_row["id"],
            "wrapped_key": key_row["wrapped_key"],
            "wrapped_key_nonce": key_row["wrapped_key_nonce"],
        }

    deletion_request = create_deletion_request(
        DeletionRequestCreate(
            tenant_id=tenant["id"],
            dataset_id=dataset["id"],
            subject_id=subject_id,
            requested_by="restore-lab",
            reason="Demonstrate deletion continuity after a stale restore",
        )
    )
    finalized_request = execute_deletion_request(
        deletion_request["id"],
        step_up_verified=True,
        deletion_window_days=0,
    )
    after_deletion = read_record(record["id"])

    with get_conn() as conn:
        conn.execute(
            """
            UPDATE subject_keys
            SET wrapped_key = ?,
                wrapped_key_nonce = ?,
                key_state = 'active',
                pending_deletion_until = NULL,
                destroyed_at = NULL
            WHERE id = ?
            """,
            (
                stale_key["wrapped_key"],
                stale_key["wrapped_key_nonce"],
                stale_key["id"],
            ),
        )
        conn.execute(
            """
            UPDATE deletion_requests
            SET status = 'pending',
                finalized_at = NULL
            WHERE id = ?
            """,
            (deletion_request["id"],),
        )

    after_stale_restore = read_record(record["id"], enforce_receipts=False)
    reconciliation = reconcile_deletion_receipts()
    after_reconciliation = read_record(record["id"])

    result = {
        "scenario_id": scenario_id,
        "tenant": tenant,
        "dataset": dataset,
        "record_id": record["id"],
        "subject_id": subject_id,
        "deletion_request_id": deletion_request["id"],
        "timeline": [
            {
                "phase": "encrypted",
                "label": "Record created",
                "erase_status": record["erase_status"],
                "key_state": record["key_state"],
                "payload_visible": record["payload"] is not None,
            },
            {
                "phase": "deleted",
                "label": "Deletion finalized",
                "erase_status": after_deletion["erase_status"],
                "key_state": after_deletion["key_state"],
                "payload_visible": after_deletion["payload"] is not None,
            },
            {
                "phase": "restored",
                "label": "Stale key restored",
                "erase_status": after_stale_restore["erase_status"],
                "key_state": after_stale_restore["key_state"],
                "payload_visible": after_stale_restore["payload"] is not None,
            },
            {
                "phase": "reconciled",
                "label": "Receipt reapplied",
                "erase_status": after_reconciliation["erase_status"],
                "key_state": after_reconciliation["key_state"],
                "payload_visible": after_reconciliation["payload"] is not None,
            },
        ],
        "receipt_verification": verify_receipt_log(),
        "audit_verification": verify_audit_chain(),
        "reconciliation": reconciliation,
        "evidence": get_evidence(finalized_request["id"]),
    }
    if settings.public_demo_mode:
        _cleanup_public_demo_rows(
            tenant_id=tenant["id"],
            dataset_id=dataset["id"],
            subject_id=subject_id,
            record_id=record["id"],
            request_id=deletion_request["id"],
        )
    return result
