from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
from typing import Any, Iterable

from .config import settings
from .utils import canonical_json, new_id, utc_now


RECEIPT_VERSION = 1


class ReceiptJournalError(RuntimeError):
    """Raised when the external receipt journal cannot be trusted."""


def _signing_key() -> bytes:
    key_path = Path(settings.receipt_signing_key_path)
    key_path.parent.mkdir(parents=True, exist_ok=True)
    if key_path.exists():
        return key_path.read_bytes()

    key = os.urandom(32)
    key_path.write_bytes(key)
    return key


def _signature(payload: dict[str, Any]) -> str:
    return hmac.new(
        _signing_key(),
        canonical_json(payload).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def subject_ref(
    subject_id: str,
    tenant_id: str | None = None,
    dataset_id: str | None = None,
) -> str:
    if tenant_id is not None and dataset_id is not None:
        payload = f"{tenant_id}\x1f{dataset_id}\x1f{subject_id}"
    else:
        payload = subject_id
    return hmac.new(
        _signing_key(),
        payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def receipt_matches_subject(receipt: dict[str, Any], subject_id: str) -> bool:
    scoped_ref = subject_ref(
        subject_id,
        receipt.get("tenant_id"),
        receipt.get("dataset_id"),
    )
    legacy_ref = subject_ref(subject_id)
    return receipt.get("subject_ref") in {scoped_ref, legacy_ref}


def append_deletion_receipt(
    *,
    tenant_id: str,
    dataset_id: str,
    subject_id: str,
    request_id: str,
    request_hash: str,
    finalized_at: str,
    audit_event_hash: str,
) -> dict[str, Any]:
    existing_receipts = list(iter_receipts())
    verification = verify_receipt_log(existing_receipts)
    if not verification["ok"]:
        raise ReceiptJournalError(
            "Deletion receipt journal failed signature verification."
        )

    expected_subject_ref = subject_ref(subject_id, tenant_id, dataset_id)
    for receipt in existing_receipts:
        if receipt["request_id"] != request_id:
            continue
        if (
            receipt["tenant_id"] != tenant_id
            or receipt["dataset_id"] != dataset_id
            or receipt["subject_ref"] != expected_subject_ref
            or receipt["request_hash"] != request_hash
        ):
            raise ReceiptJournalError(
                f"Deletion request {request_id} conflicts with an existing receipt."
            )
        return receipt

    payload = {
        "version": RECEIPT_VERSION,
        "receipt_id": new_id("receipt"),
        "issued_at": utc_now(),
        "finalized_at": finalized_at,
        "tenant_id": tenant_id,
        "dataset_id": dataset_id,
        "subject_ref": expected_subject_ref,
        "request_id": request_id,
        "request_hash": request_hash,
        "audit_event_hash": audit_event_hash,
    }
    receipt = {**payload, "signature": _signature(payload)}

    log_path = Path(settings.receipt_log_path)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as handle:
        handle.write(canonical_json(receipt) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    return receipt


def iter_receipts() -> Iterable[dict[str, Any]]:
    log_path = Path(settings.receipt_log_path)
    if not log_path.exists():
        return []

    receipts: list[dict[str, Any]] = []
    for line in log_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            receipts.append(json.loads(line))
        except json.JSONDecodeError:
            receipts.append({"malformed": True, "raw": line})
    return receipts


def verify_receipt(receipt: dict[str, Any]) -> bool:
    if receipt.get("version") != RECEIPT_VERSION:
        return False
    signature = receipt.get("signature")
    if not isinstance(signature, str):
        return False
    payload = {key: value for key, value in receipt.items() if key != "signature"}
    return hmac.compare_digest(signature, _signature(payload))


def verify_receipt_log(
    receipts: Iterable[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    loaded_receipts = list(iter_receipts() if receipts is None else receipts)
    invalid_ids = [
        receipt.get("receipt_id", "malformed")
        for receipt in loaded_receipts
        if not verify_receipt(receipt)
    ]
    return {
        "ok": not invalid_ids,
        "receipt_count": len(loaded_receipts),
        "invalid_receipt_ids": invalid_ids,
    }


def valid_receipts(
    receipts: Iterable[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    loaded_receipts = iter_receipts() if receipts is None else receipts
    return [receipt for receipt in loaded_receipts if verify_receipt(receipt)]


def has_deletion_receipt(
    tenant_id: str,
    dataset_id: str,
    subject_id: str,
    receipts: Iterable[dict[str, Any]] | None = None,
) -> bool:
    expected_refs = {
        subject_ref(subject_id, tenant_id, dataset_id),
        subject_ref(subject_id),
    }
    return any(
        receipt["tenant_id"] == tenant_id
        and receipt["dataset_id"] == dataset_id
        and receipt["subject_ref"] in expected_refs
        for receipt in valid_receipts(receipts)
    )
