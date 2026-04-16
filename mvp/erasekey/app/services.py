from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import HTTPException, status

from . import crypto
from .config import settings
from .db import get_conn
from .key_providers import KeyResolver, KeyProviderError, InvalidKmsState
from .schemas import (
    DatasetCreate,
    DeletionRequestCreate,
    LegalHoldCreate,
    RecordCreate,
    TenantCreate,
    KeyState,
    RequestStatus,
    EraseStatus,
)
from . import utils
from .policy_engine import ActorType, PolicyContext, PolicyDecision, PolicyResponse, engine


def _row_to_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
    if row is None:
        return None
    return {key: row[key] for key in row.keys()}


def _audit(conn: sqlite3.Connection, entity_type: str, entity_id: str, action: str, payload: dict[str, Any], actor: str = "system") -> str:
    # 1. Fetch previous hash
    # Use rowid to ensure stable ordering for the chain
    last_event = conn.execute(
        "SELECT event_hash FROM audit_events ORDER BY rowid DESC LIMIT 1"
    ).fetchone()
    prev_hash = last_event['event_hash'] if last_event and last_event['event_hash'] else "none"

    # 2. Build event core for hashing (precise and honest)
    now = utils.utc_now()
    event_core = {
        "event_type": action,
        "timestamp": now,
        "actor": actor,
        "tenant_id": payload.get("tenant_id", "none"),
        "entity_type": entity_type,
        "entity_id": entity_id,
        "payload": payload
    }
    
    # 3. Compute hash: sha256("erasekey.audit.v1\n" + prev_hash + "\n" + canonical_json(event_core))
    core_json = utils.canonical_json(event_core)
    hash_input = f"erasekey.audit.v1\n{prev_hash}\n{core_json}"
    event_hash = utils.sha256_hex(hash_input)

    conn.execute(
        """
        INSERT INTO audit_events (id, entity_type, entity_id, action, payload_json, created_at, prev_hash, event_hash, chain_version)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            utils.new_id('audit'),
            entity_type,
            entity_id,
            action,
            utils.canonical_json(payload),
            now,
            prev_hash,
            event_hash,
            1, # chain_version
        ),
    )
    return event_hash


def _handle_policy_deny(conn: sqlite3.Connection, entity_id: str, decision: PolicyResponse, entity_type: str, actor_type: ActorType = ActorType.HUMAN):
    """
    Centralized policy denial handler.
    Ensures that for deletion requests, legal holds are persisted as 'blocked' status
    before raising the final 403.
    """
    blocked_reason = f"Policy Denied: {decision.reason_code}"
    actor_name = "system_worker" if actor_type == ActorType.SYSTEM_WORKER else "operator"
    
    # Audit the denial
    _audit(conn, entity_type, entity_id, f'{entity_type}.denied', {
        'reason_code': decision.reason_code,
        'blocked_reason': blocked_reason,
        'actor_type': actor_type
    }, actor=actor_name)

    if decision.reason_code == "ACTIVE_LEGAL_HOLD" and entity_type == "deletion_request":
        conn.execute(
            'UPDATE deletion_requests SET status = ?, blocked_reason = ? WHERE id = ?',
            (RequestStatus.blocked.value, blocked_reason, entity_id),
        )
        _audit(conn, 'deletion_request', entity_id, 'deletion_request.blocked', {
            'reason_code': decision.reason_code,
            'blocked_reason': blocked_reason,
            'actor_type': actor_type
        }, actor=actor_name)
        # Crucial: commit the state transition before raising exception
        conn.commit()
    
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail=blocked_reason
    )


def _fetch_tenant(conn: sqlite3.Connection, tenant_id: str) -> dict[str, Any]:
    row = conn.execute('SELECT * FROM tenants WHERE id = ?', (tenant_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail='Tenant not found.')
    return _row_to_dict(row) or {}


def _fetch_dataset(conn: sqlite3.Connection, dataset_id: str) -> dict[str, Any]:
    row = conn.execute('SELECT * FROM datasets WHERE id = ?', (dataset_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail='Dataset not found.')
    return _row_to_dict(row) or {}


def create_tenant(payload: TenantCreate) -> dict[str, Any]:
    record = {
        'id': utils.new_id('tenant'),
        'name': payload.name.strip(),
        'kms_key_id': None,
        'created_at': utils.utc_now(),
    }
    with get_conn() as conn:
        conn.execute(
            'INSERT INTO tenants (id, name, kms_key_id, created_at) VALUES (?, ?, ?, ?)',
            (record['id'], record['name'], record['kms_key_id'], record['created_at']),
        )
        _audit(conn, 'tenant', record['id'], 'tenant.created', record)
    return record


def list_tenants() -> list[dict[str, Any]]:
    with get_conn() as conn:
        rows = conn.execute('SELECT * FROM tenants ORDER BY created_at DESC').fetchall()
        return [_row_to_dict(row) or {} for row in rows]


def create_dataset(payload: DatasetCreate) -> dict[str, Any]:
    with get_conn() as conn:
        _fetch_tenant(conn, payload.tenant_id)
        record = {
            'id': utils.new_id('dataset'),
            'tenant_id': payload.tenant_id,
            'name': payload.name.strip(),
            'description': payload.description,
            'retention_days': payload.retention_days,
            'created_at': utils.utc_now(),
        }
        try:
            conn.execute(
                'INSERT INTO datasets (id, tenant_id, name, description, retention_days, created_at) VALUES (?, ?, ?, ?, ?, ?)',
                (
                    record['id'],
                    record['tenant_id'],
                    record['name'],
                    record['description'],
                    record['retention_days'],
                    record['created_at'],
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise HTTPException(status_code=409, detail='Dataset name already exists for this tenant.') from exc
        _audit(conn, 'dataset', record['id'], 'dataset.created', record)
    return record


def list_datasets(tenant_id: str | None = None) -> list[dict[str, Any]]:
    with get_conn() as conn:
        if tenant_id:
            rows = conn.execute(
                'SELECT * FROM datasets WHERE tenant_id = ? ORDER BY created_at DESC',
                (tenant_id,),
            ).fetchall()
        else:
            rows = conn.execute('SELECT * FROM datasets ORDER BY created_at DESC').fetchall()
        return [_row_to_dict(row) or {} for row in rows]


def _find_active_holds(
    conn: sqlite3.Connection,
    tenant_id: str,
    dataset_id: str,
    subject_id: str,
) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT *
        FROM legal_holds
        WHERE tenant_id = ?
          AND active = 1
          AND (dataset_id IS NULL OR dataset_id = ?)
          AND (subject_id IS NULL OR subject_id = ?)
        ORDER BY created_at DESC
        """,
        (tenant_id, dataset_id, subject_id),
    ).fetchall()
    results: list[dict[str, Any]] = []
    for row in rows:
        item = _row_to_dict(row) or {}
        item['active'] = bool(item['active'])
        results.append(item)
    return results


def create_legal_hold(payload: LegalHoldCreate) -> dict[str, Any]:
    with get_conn() as conn:
        _fetch_tenant(conn, payload.tenant_id)
        if payload.dataset_id:
            dataset = _fetch_dataset(conn, payload.dataset_id)
            if dataset['tenant_id'] != payload.tenant_id:
                raise HTTPException(status_code=400, detail='Dataset does not belong to tenant.')
        record = {
            'id': utils.new_id('hold'),
            'tenant_id': payload.tenant_id,
            'dataset_id': payload.dataset_id,
            'subject_id': payload.subject_id,
            'reason': payload.reason.strip(),
            'active': True,
            'created_at': utils.utc_now(),
            'released_at': None,
        }
        conn.execute(
            """
            INSERT INTO legal_holds (id, tenant_id, dataset_id, subject_id, reason, active, created_at, released_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record['id'],
                record['tenant_id'],
                record['dataset_id'],
                record['subject_id'],
                record['reason'],
                1,
                record['created_at'],
                None,
            ),
        )
        _audit(conn, 'legal_hold', record['id'], 'legal_hold.created', record)
    return record


def release_legal_hold(hold_id: str, step_up_verified: bool = False, actor_type: ActorType = ActorType.HUMAN) -> dict[str, Any]:
    with get_conn() as conn:
        row = conn.execute('SELECT * FROM legal_holds WHERE id = ?', (hold_id,)).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail='Legal hold not found.')
        hold_item = _row_to_dict(row) or {}

        # Policy Check
        context = PolicyContext(
            action="release_legal_hold",
            tenant_id=hold_item['tenant_id'],
            dataset_id=hold_item['dataset_id'],
            subject_id=hold_item['subject_id'],
            step_up_verified=step_up_verified,
            actor_type=actor_type
        )
        decision = engine.evaluate(context)
        if decision.decision == PolicyDecision.DENY:
            _handle_policy_deny(conn, hold_id, decision, "legal_hold", actor_type)

        released_at = utils.utc_now()
        conn.execute(
            'UPDATE legal_holds SET active = 0, released_at = ? WHERE id = ?',
            (released_at, hold_id),
        )
        hold_item['active'] = False
        hold_item['released_at'] = released_at
        _audit(conn, 'legal_hold', hold_id, 'legal_hold.released', {'released_at': released_at}, actor="system_worker" if actor_type == ActorType.SYSTEM_WORKER else "operator")
        return hold_item


def _next_subject_key_version(conn: sqlite3.Connection, tenant_id: str, dataset_id: str, subject_id: str) -> int:
    row = conn.execute(
        'SELECT COALESCE(MAX(key_version), 0) AS max_version FROM subject_keys WHERE tenant_id = ? AND dataset_id = ? AND subject_id = ?',
        (tenant_id, dataset_id, subject_id),
    ).fetchone()
    return int(row['max_version']) + 1 if row else 1


def _build_encryption_context(tenant_id: str, dataset_id: str, subject_id: str, subject_key_id: str, key_version: int) -> dict[str, str]:
    return {
        "app": "erasekey",
        "tenant_id": tenant_id,
        "dataset_id": dataset_id,
        "subject_ref": utils.sha256_hex({"subject_id": subject_id}),
        "subject_key_id": subject_key_id,
        "key_version": str(key_version),
        "schema": "erasekey.subject_key.v2",
    }


def _get_active_subject_key(conn: sqlite3.Connection, tenant_id: str, dataset_id: str, subject_id: str) -> dict[str, Any] | None:
    row = conn.execute(
        """
        SELECT * FROM subject_keys
        WHERE tenant_id = ? AND dataset_id = ? AND subject_id = ? AND key_state = 'active'
        ORDER BY key_version DESC
        LIMIT 1
        """,
        (tenant_id, dataset_id, subject_id),
    ).fetchone()
    return _row_to_dict(row)


def _ensure_subject_key(conn: sqlite3.Connection, tenant_dict: dict[str, Any], dataset_id: str, subject_id: str) -> tuple[dict[str, Any], bytes]:
    tenant_id = tenant_dict['id']
    existing = _get_active_subject_key(conn, tenant_id, dataset_id, subject_id)
    if existing is not None:
        try:
            provider = KeyResolver.resolve_provider(tenant_kms_key_id=existing['kms_key_id'])
            context = json.loads(existing['encryption_context_json'])
            data_key = provider.unwrap_data_key(existing['wrapped_key'], context)
        except KeyProviderError as exc:
            raise HTTPException(status_code=500, detail=f"KMS Provider failure: {exc}") from exc
        return existing, data_key

    version = _next_subject_key_version(conn, tenant_id, dataset_id, subject_id)
    skey_id = utils.new_id('skey')
    context = _build_encryption_context(tenant_id, dataset_id, subject_id, skey_id, version)

    provider = KeyResolver.resolve_provider(tenant_kms_key_id=tenant_dict.get('kms_key_id'))
    provider_info = provider.describe_provider()
    
    try:
        data_key, wrapped_key = provider.generate_data_key(context)
    except KeyProviderError as exc:
        raise HTTPException(status_code=500, detail=f"Failed to generate KMS key: {exc}") from exc

    record = {
        'id': skey_id,
        'tenant_id': tenant_id,
        'dataset_id': dataset_id,
        'subject_id': subject_id,
        'key_version': version,
        'kms_key_id': provider_info.get("key_id"),
        'encryption_context_json': json.dumps(context, sort_keys=True),
        'wrapped_key': wrapped_key,
        'wrapped_key_nonce': None,
        'key_state': KeyState.active.value,
        'created_at': utils.utc_now(),
        'pending_deletion_until': None,
        'destroyed_at': None,
    }
    conn.execute(
        """
        INSERT INTO subject_keys (id, tenant_id, dataset_id, subject_id, key_version, kms_key_id, encryption_context_json, wrapped_key, wrapped_key_nonce, key_state, created_at, pending_deletion_until, destroyed_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            record['id'], record['tenant_id'], record['dataset_id'], record['subject_id'],
            record['key_version'], record['kms_key_id'], record['encryption_context_json'],
            record['wrapped_key'], record['wrapped_key_nonce'], record['key_state'],
            record['created_at'], record['pending_deletion_until'], record['destroyed_at']
        ),
    )
    _audit(conn, 'subject_key', record['id'], 'subject_key.created', {
        'tenant_id': tenant_id,
        'dataset_id': dataset_id,
        'subject_id': subject_id,
        'key_version': version,
    })
    return record, data_key


def create_record(payload: RecordCreate) -> dict[str, Any]:
    with get_conn() as conn:
        tenant_dict = _fetch_tenant(conn, payload.tenant_id)
        dataset = _fetch_dataset(conn, payload.dataset_id)
        if dataset['tenant_id'] != payload.tenant_id:
            raise HTTPException(status_code=400, detail='Dataset does not belong to tenant.')

        subject_key, data_key = _ensure_subject_key(conn, tenant_dict, payload.dataset_id, payload.subject_id)
        record_id = utils.new_id('rec')
        aad = {
            'tenant_id': payload.tenant_id,
            'dataset_id': payload.dataset_id,
            'subject_id': payload.subject_id,
            'record_type': payload.record_type,
            'subject_key_id': subject_key['id'],
            'record_id': record_id,
            'schema': 'erasekey.record.v1',
        }
        ciphertext, nonce = crypto.encrypt_payload(data_key, payload.payload, aad)
        record = {
            'id': record_id,
            'tenant_id': payload.tenant_id,
            'dataset_id': payload.dataset_id,
            'subject_id': payload.subject_id,
            'subject_key_id': subject_key['id'],
            'record_type': payload.record_type,
            'ciphertext': ciphertext,
            'nonce': nonce,
            'aad': utils.canonical_json(aad),
            'created_at': utils.utc_now(),
        }
        conn.execute(
            """
            INSERT INTO records (id, tenant_id, dataset_id, subject_id, subject_key_id, record_type, ciphertext, nonce, aad, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record['id'], record['tenant_id'], record['dataset_id'], record['subject_id'],
                record['subject_key_id'], record['record_type'], record['ciphertext'],
                record['nonce'], record['aad'], record['created_at']
            ),
        )
        _audit(conn, 'record', record['id'], 'record.ingested', {
            'tenant_id': record['tenant_id'], 'dataset_id': record['dataset_id'],
            'subject_id': record['subject_id'], 'subject_key_id': record['subject_key_id'],
            'record_type': record['record_type'],
        })
        return {
            'id': record['id'],
            'tenant_id': record['tenant_id'],
            'dataset_id': record['dataset_id'],
            'subject_id': record['subject_id'],
            'record_type': record['record_type'],
            'created_at': record['created_at'],
            'payload': payload.payload,
            'key_state': KeyState.active.value,
            'erase_status': EraseStatus.readable.value,
        }


def read_record(record_id: str) -> dict[str, Any]:
    with get_conn() as conn:
        row = conn.execute('SELECT * FROM records WHERE id = ?', (record_id,)).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail='Record not found.')
        record = _row_to_dict(row) or {}
        key_row = conn.execute('SELECT * FROM subject_keys WHERE id = ?', (record['subject_key_id'],)).fetchone()
        if key_row is None:
            return {
                'id': record['id'], 'tenant_id': record['tenant_id'], 'dataset_id': record['dataset_id'],
                'subject_id': record['subject_id'], 'record_type': record['record_type'],
                'created_at': record['created_at'], 'payload': None,
                'key_state': 'missing', 'erase_status': EraseStatus.cryptographically_erased.value,
            }
        
        key_item = _row_to_dict(key_row) or {}
        
        # Determine status
        if key_item['key_state'] == KeyState.destroyed.value or not key_item['wrapped_key']:
            return {
                'id': record['id'], 'tenant_id': record['tenant_id'], 'dataset_id': record['dataset_id'],
                'subject_id': record['subject_id'], 'record_type': record['record_type'],
                'created_at': record['created_at'], 'payload': None,
                'key_state': key_item['key_state'], 'erase_status': EraseStatus.cryptographically_erased.value,
            }

        # Subject key is pending erasure, block it
        if key_item['key_state'] == KeyState.pending_erasure.value:
            # Note: We do not check if pending_deletion_until > now here to finalize automatically. 
            # Finalization is an explicit sweep. We just block access.
            return {
                'id': record['id'], 'tenant_id': record['tenant_id'], 'dataset_id': record['dataset_id'],
                'subject_id': record['subject_id'], 'record_type': record['record_type'],
                'created_at': record['created_at'], 'payload': None,
                'key_state': key_item['key_state'], 'erase_status': EraseStatus.scheduled_for_erasure.value,
            }

        try:
            provider = KeyResolver.resolve_provider(tenant_kms_key_id=key_item.get('kms_key_id'))
            context = json.loads(key_item['encryption_context_json'])
            data_key = provider.unwrap_data_key(key_item['wrapped_key'], context)
            
            payload = crypto.decrypt_payload(
                data_key=data_key,
                ciphertext=record['ciphertext'],
                nonce=record['nonce'],
                aad=json.loads(record['aad']),
            )
        except InvalidKmsState:
            # Fallback for when the KMS key itself is deleted
            return {
                'id': record['id'], 'tenant_id': record['tenant_id'], 'dataset_id': record['dataset_id'],
                'subject_id': record['subject_id'], 'record_type': record['record_type'],
                'created_at': record['created_at'], 'payload': None,
                'key_state': key_item['key_state'], 'erase_status': EraseStatus.cryptographically_erased.value,
            }
        except (crypto.CryptoError, KeyProviderError) as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc
            
        return {
            'id': record['id'], 'tenant_id': record['tenant_id'], 'dataset_id': record['dataset_id'],
            'subject_id': record['subject_id'], 'record_type': record['record_type'],
            'created_at': record['created_at'], 'payload': payload,
            'key_state': key_item['key_state'], 'erase_status': EraseStatus.readable.value,
        }


def create_deletion_request(payload: DeletionRequestCreate) -> dict[str, Any]:
    with get_conn() as conn:
        _fetch_tenant(conn, payload.tenant_id)
        dataset = _fetch_dataset(conn, payload.dataset_id)
        if dataset['tenant_id'] != payload.tenant_id:
            raise HTTPException(status_code=400, detail='Dataset does not belong to tenant.')

        holds = _find_active_holds(conn, payload.tenant_id, payload.dataset_id, payload.subject_id)
        blocked_reason = None
        status_value = RequestStatus.pending.value
        if holds:
            status_value = RequestStatus.blocked.value
            blocked_reason = f'Active legal hold count: {len(holds)}'

        base_request = {
            'tenant_id': payload.tenant_id, 'dataset_id': payload.dataset_id,
            'subject_id': payload.subject_id, 'requested_by': payload.requested_by.strip(),
            'reason': payload.reason.strip(),
        }
        request_hash = utils.sha256_hex(base_request)
        record = {
            'id': utils.new_id('delreq'), **base_request,
            'status': status_value, 'blocked_reason': blocked_reason,
            'created_at': utils.utc_now(), 'executed_at': None, 'canceled_at': None, 'finalized_at': None,
            'request_hash': request_hash,
        }
        conn.execute(
            """
            INSERT INTO deletion_requests (id, tenant_id, dataset_id, subject_id, requested_by, reason, status, blocked_reason, created_at, executed_at, canceled_at, finalized_at, evidence_json, request_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record['id'], record['tenant_id'], record['dataset_id'], record['subject_id'],
                record['requested_by'], record['reason'], record['status'], record['blocked_reason'],
                record['created_at'], None, None, None, None, record['request_hash']
            ),
        )
        _audit(conn, 'deletion_request', record['id'], 'deletion_request.created', record)
        return record


def get_deletion_request(request_id: str) -> dict[str, Any]:
    with get_conn() as conn:
        row = conn.execute('SELECT * FROM deletion_requests WHERE id = ?', (request_id,)).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail='Deletion request not found.')
        return _row_to_dict(row) or {}


def execute_deletion_request(request_id: str, step_up_verified: bool = False, actor_type: ActorType = ActorType.HUMAN) -> dict[str, Any]:
    with get_conn() as conn:
        row = conn.execute('SELECT * FROM deletion_requests WHERE id = ?', (request_id,)).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail='Deletion request not found.')
        request_item = _row_to_dict(row) or {}

        if request_item['status'] != RequestStatus.pending.value:
            # We allow re-executing if blocked or scheduled? For now just block.
            if request_item['status'] == RequestStatus.scheduled.value:
                return request_item
            if request_item['status'] != RequestStatus.blocked.value:
                raise HTTPException(status_code=400, detail='Request is not in a states that can be executed.')

        # Policy Check
        holds = _find_active_holds(
            conn, request_item['tenant_id'], request_item['dataset_id'], request_item['subject_id']
        )
        context = PolicyContext(
            action="execute",
            tenant_id=request_item['tenant_id'],
            dataset_id=request_item['dataset_id'],
            subject_id=request_item['subject_id'],
            active_hold_present=len(holds) > 0,
            step_up_verified=step_up_verified,
            actor_type=actor_type
        )
        decision = engine.evaluate(context)
        
        if decision.decision == PolicyDecision.DENY:
            _handle_policy_deny(conn, request_id, decision, "deletion_request", actor_type)

        window = settings.deletion_window_days
        now = utils.utc_now()

        if window == 0:
            return _finalize_deletion_internal(conn, request_item, now)
        
        # Schedule it
        active_keys = conn.execute(
            """
            SELECT id FROM subject_keys
            WHERE tenant_id = ? AND dataset_id = ? AND subject_id = ? AND key_state = 'active'
            """,
            (request_item['tenant_id'], request_item['dataset_id'], request_item['subject_id']),
        ).fetchall()

        pending_until_obj = utils.utc_now_dt() + timedelta(days=window)
        pending_until_str = pending_until_obj.isoformat()
        
        affected_keys = []
        for key_row in active_keys:
            skey_id = key_row['id']
            conn.execute(
                """
                UPDATE subject_keys
                SET key_state = ?, pending_deletion_until = ?
                WHERE id = ?
                """,
                (KeyState.pending_erasure.value, pending_until_str, skey_id),
            )
            affected_keys.append(skey_id)

        evidence = {
            'tenant_id': request_item['tenant_id'],
            'dataset_id': request_item['dataset_id'],
            'subject_id': request_item['subject_id'],
            'affected_key_ids': affected_keys,
            'pending_deletion_until': pending_until_str,
            'message': 'Access to records is blocked by policy. Final cryptographic erasure is pending timeline expiration.',
            'request_hash': request_item['request_hash'],
        }

        conn.execute(
            'UPDATE deletion_requests SET status = ?, blocked_reason = NULL, executed_at = ?, evidence_json = ?, step_up_authorized = ? WHERE id = ?',
            (RequestStatus.scheduled.value, now, utils.canonical_json(evidence), 1 if step_up_verified else 0, request_id),
        )
        request_item['status'] = RequestStatus.scheduled.value
        request_item['blocked_reason'] = None
        request_item['executed_at'] = now
        request_item['evidence_json'] = utils.canonical_json(evidence) # to keep memory object fresh
        
        _audit(conn, 'deletion_request', request_id, 'deletion_request.scheduled', evidence)
        return request_item

def _finalize_deletion_internal(conn: sqlite3.Connection, request_item: dict[str, Any], now: str, evidence_payload: dict[str, Any] = None, actor_type: ActorType = ActorType.HUMAN) -> dict[str, Any]:
    actor_name = "system_worker" if actor_type == ActorType.SYSTEM_WORKER else "operator"
    
    # 1. Subject Keys -> destroyed
    rows = conn.execute(
        'SELECT * FROM subject_keys WHERE tenant_id = ? AND dataset_id = ? AND subject_id = ? AND key_state != ?',
        (request_item['tenant_id'], request_item['dataset_id'], request_item['subject_id'], KeyState.destroyed.value),
    ).fetchall()
    
    destroyed_key_ids = []
    for row in rows:
        key_item = _row_to_dict(row) or {}
        conn.execute(
            """
            UPDATE subject_keys
            SET wrapped_key = NULL,
                wrapped_key_nonce = NULL,
                key_state = ?,
                destroyed_at = ?
            WHERE id = ?
            """,
            (KeyState.destroyed.value, now, key_item['id']),
        )
        destroyed_key_ids.append(key_item['id'])
        _audit(conn, 'subject_key', key_item['id'], 'subject_key.destroyed', {
            'destroyed_at': now,
            'reason': f'Cryptographic erasure via deletion request {request_item["id"]}',
        }, actor=actor_name)

    record_count_row = conn.execute(
        'SELECT COUNT(*) AS count FROM records WHERE tenant_id = ? AND dataset_id = ? AND subject_id = ?',
        (request_item['tenant_id'], request_item['dataset_id'], request_item['subject_id']),
    ).fetchone()
    record_count = int(record_count_row['count']) if record_count_row else 0

    evidence = {
        'finalized_at': now,
        'tenant_id': request_item['tenant_id'],
        'dataset_id': request_item['dataset_id'],
        'subject_id': request_item['subject_id'],
        'record_count': record_count,
        'destroyed_key_ids': destroyed_key_ids,
        'message': 'Wrapped subject data keys were destroyed. Ciphertext remains but is no longer decryptable.',
        'controls': {
            'live_data_action': 'application keeps ciphertext to model backup/cold-storage reality',
            'crypto_action': 'wrapped subject keys destroyed',
            'legal_hold_checked': True,
        },
        'request_hash': request_item['request_hash'],
    }

    # Add extra payload if provided (Worker observations)
    if evidence_payload:
        evidence.update(evidence_payload)

    status_field = RequestStatus.finalized.value
    conn.execute(
        'UPDATE deletion_requests SET status = ?, blocked_reason = NULL, executed_at = COALESCE(executed_at, ?), finalized_at = ?, evidence_json = ? WHERE id = ?',
        (status_field, now, now, utils.canonical_json(evidence), request_item['id']),
    )
    request_item['status'] = status_field
    request_item['blocked_reason'] = None
    if not request_item.get('executed_at'):
        request_item['executed_at'] = now
    request_item['finalized_at'] = now
    request_item['evidence_json'] = utils.canonical_json(evidence)

    _audit(conn, 'deletion_request', request_item['id'], 'deletion_request.finalized', evidence, actor=actor_name)
    return request_item

def finalize_deletion_request(
    request_id: str, 
    step_up_verified: bool = False, 
    actor_type: ActorType = ActorType.HUMAN,
    scheduled_and_due: bool = False
) -> dict[str, Any]:
    with get_conn() as conn:
        row = conn.execute('SELECT * FROM deletion_requests WHERE id = ?', (request_id,)).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail='Deletion request not found.')
        request_item = _row_to_dict(row) or {}

        if request_item['status'] == RequestStatus.finalized.value:
            return request_item
        if request_item['status'] != RequestStatus.scheduled.value:
             raise HTTPException(status_code=400, detail='Request is not scheduled.')

        # Policy Check
        holds = _find_active_holds(
            conn, request_item['tenant_id'], request_item['dataset_id'], request_item['subject_id']
        )
        # Fetch dataset for retention check
        ds_row = conn.execute("SELECT retention_days, created_at FROM datasets WHERE id = ?", (request_item['dataset_id'],)).fetchone()
        retention_expired = True
        if ds_row and ds_row['retention_days']:
            created_at = datetime.fromisoformat(ds_row['created_at'])
            expiry_date = created_at + timedelta(days=ds_row['retention_days'])
            retention_expired = datetime.now(timezone.utc) > expiry_date
            
        prior_execute_step_up_verified = (request_item.get('step_up_authorized') == 1)

        context = PolicyContext(
            action="finalize",
            tenant_id=request_item['tenant_id'],
            dataset_id=request_item['dataset_id'],
            subject_id=request_item['subject_id'],
            active_hold_present=len(holds) > 0,
            step_up_verified=step_up_verified,
            actor_type=actor_type,
            scheduled_and_due=scheduled_and_due,
            prior_execute_step_up_verified=prior_execute_step_up_verified,
            retention_expired=retention_expired
        )
        decision = engine.evaluate(context)
        if decision.decision == PolicyDecision.DENY:
            _handle_policy_deny(conn, request_id, decision, "deletion_request", actor_type)

        now = utils.utc_now()
        evidence_payload = {}
        if actor_type == ActorType.SYSTEM_WORKER:
             evidence_payload = {
                "actor_type": "system_worker",
                "authorization": {
                    "source": "persisted_execute_step_up",
                    "prior_execute_step_up_verified": prior_execute_step_up_verified
                },
                "observations": {
                    "scheduled_and_due": scheduled_and_due,
                    "active_hold_present": len(holds) > 0,
                    "pending_deletion_until": request_item.get('pending_deletion_until')
                }
            }

        return _finalize_deletion_internal(conn, request_item, now, evidence_payload=evidence_payload, actor_type=actor_type)

def cancel_deletion_request(request_id: str, step_up_verified: bool = False, actor_type: ActorType = ActorType.HUMAN) -> dict[str, Any]:
    with get_conn() as conn:
        row = conn.execute('SELECT * FROM deletion_requests WHERE id = ?', (request_id,)).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail='Deletion request not found.')
        request_item = _row_to_dict(row) or {}

        if request_item['status'] != RequestStatus.scheduled.value:
            raise HTTPException(status_code=400, detail='Only scheduled requests can be canceled.')

        # Policy Check
        context = PolicyContext(
            action="cancel",
            tenant_id=request_item['tenant_id'],
            dataset_id=request_item['dataset_id'],
            subject_id=request_item['subject_id'],
            step_up_verified=step_up_verified,
            actor_type=actor_type
        )
        decision = engine.evaluate(context)
        if decision.decision == PolicyDecision.DENY:
            _handle_policy_deny(conn, request_id, decision, "deletion_request", actor_type)

        now = utils.utc_now()
        
        # Revert keys
        conn.execute(
            """
            UPDATE subject_keys
            SET key_state = ?, pending_deletion_until = NULL
            WHERE tenant_id = ? AND dataset_id = ? AND subject_id = ? AND key_state = ?
            """,
            (KeyState.active.value, request_item['tenant_id'], request_item['dataset_id'], request_item['subject_id'], KeyState.pending_erasure.value)
        )

        conn.execute(
            'UPDATE deletion_requests SET status = ?, canceled_at = ? WHERE id = ?',
            (RequestStatus.canceled.value, now, request_id),
        )
        request_item['status'] = RequestStatus.canceled.value
        request_item['canceled_at'] = now
        
        _audit(conn, 'deletion_request', request_id, 'deletion_request.canceled', {'canceled_at': now})
        return request_item


def get_evidence(request_id: str) -> dict[str, Any]:
    with get_conn() as conn:
        row = conn.execute(
            'SELECT dr.*, ae.id as audit_id, ae.event_hash, ae.prev_hash FROM deletion_requests dr '
            'LEFT JOIN audit_events ae ON ae.entity_id = dr.id AND ae.action = "deletion_request.finalized" '
            'WHERE dr.id = ?',
            (request_id,)
        ).fetchone()
        
        if row is None:
            raise HTTPException(status_code=404, detail='Deletion request not found.')
        if row['evidence_json'] is None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail='Deletion request has no evidence yet. Execute it first.',
            )
            
        data = _row_to_dict(row) or {}
        return {
            'request_id': data['id'],
            'status': data['status'],
            'evidence': json.loads(data['evidence_json']),
            'audit_event_id': data['audit_id'],
            'event_hash': data['event_hash'],
            'prev_hash': data['prev_hash'],
            'chain_version': data.get('chain_version', 1)
        }


def get_audit_head() -> str:
    with get_conn() as conn:
        row = conn.execute("SELECT event_hash FROM audit_events ORDER BY rowid DESC LIMIT 1").fetchone()
        return row['event_hash'] if row else "none"


def verify_audit_chain() -> dict[str, Any]:
    """
    Cryptographically verifies the entire audit chain.
    Returns a result dict with success status and any found error.
    """
    verified_count = 0
    with get_conn() as conn:
        # We order by rowid to ensure stable insertion order verification
        rows = conn.execute("SELECT * FROM audit_events ORDER BY rowid ASC").fetchall()
        
        expected_prev_hash = "none"
        head_hash = "none"
        
        for row in rows:
            event = _row_to_dict(row) or {}
            
            # 1. Verify prev_hash link
            if event['prev_hash'] != expected_prev_hash:
                return {
                    "ok": False,
                    "verified_count": verified_count,
                    "first_bad_event_id": event['id'],
                    "expected_hash": expected_prev_hash,
                    "actual_hash": event['prev_hash'],
                    "head_hash": head_hash
                }
            
            # 2. Recompute current hash
            payload = json.loads(event['payload_json'])
            event_core = {
                "event_type": event['action'],
                "timestamp": event['created_at'],
                "actor": "system",
                "tenant_id": payload.get("tenant_id", "none"),
                "entity_type": event['entity_type'],
                "entity_id": event['entity_id'],
                "payload": payload
            }
            core_json = utils.canonical_json(event_core)
            hash_input = f"erasekey.audit.v1\n{event['prev_hash']}\n{core_json}"
            calculated_hash = utils.sha256_hex(hash_input)
            
            if event['event_hash'] != calculated_hash:
                return {
                    "ok": False,
                    "verified_count": verified_count,
                    "first_bad_event_id": event['id'],
                    "expected_hash": calculated_hash,
                    "actual_hash": event['event_hash'],
                    "head_hash": head_hash
                }
            
            expected_prev_hash = calculated_hash
            head_hash = calculated_hash
            verified_count += 1
            
    return {
        "ok": True,
        "verified_count": verified_count,
        "head_hash": head_hash
    }


def list_audit_events(entity_type: Optional[str] = None, entity_id: Optional[str] = None) -> list[dict[str, Any]]:
    with get_conn() as conn:
        sql = 'SELECT * FROM audit_events'
        params: list[Any] = []
        clauses: list[str] = []
        if entity_type:
            clauses.append('entity_type = ?')
            params.append(entity_type)
        if entity_id:
            clauses.append('entity_id = ?')
            params.append(entity_id)
        if clauses:
            sql += ' WHERE ' + ' AND '.join(clauses)
        sql += ' ORDER BY rowid DESC LIMIT 200'
        rows = conn.execute(sql, params).fetchall()
        results: list[dict[str, Any]] = []
        for row in rows:
            item = _row_to_dict(row) or {}
            item['payload_json'] = json.loads(item['payload_json'])
            results.append(item)
        return results


def finalize_due_deletions() -> list[str]:
    """
    Finds and finalizes all 'scheduled' deletion requests that have passed their waiting period.
    Returns a list of request IDs that were successfully finalized.
    """
    due_request_ids = []
    with get_conn() as conn:
        now = utils.utc_now()
        # Join deletion_requests with subject_keys to find requests where keys are ready for destruction
        rows = conn.execute(
            """
            SELECT DISTINCT dr.id
            FROM deletion_requests dr
            JOIN subject_keys sk ON dr.tenant_id = sk.tenant_id
               AND dr.dataset_id = sk.dataset_id
               AND dr.subject_id = sk.subject_id
            WHERE dr.status = 'scheduled'
              AND sk.key_state = 'pending_erasure'
              AND sk.pending_deletion_until <= ?
            """,
            (now,),
        ).fetchall()
        due_request_ids = [row['id'] for row in rows]

    finalized_ids = []
    for request_id in due_request_ids:
        try:
            # Re-use manual finalization path to ensure legal holds are checked
            # and audit events are properly recorded.
            # Worker operates as SYSTEM_WORKER and passes scheduled_and_due=True
            finalize_deletion_request(request_id, actor_type=ActorType.SYSTEM_WORKER, scheduled_and_due=True)
            finalized_ids.append(request_id)
        except HTTPException as exc:
            # This is expected if a legal hold was added in the interim
            # or if another process finalized it first.
            print(f"INFO: Automatic finalization skipped for {request_id}: {exc.detail}")
        except Exception as exc:
            print(f"ERROR: Failed to finalize {request_id} automatically: {exc}")

    return finalized_ids

