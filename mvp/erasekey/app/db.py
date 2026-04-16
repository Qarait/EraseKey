from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from .config import settings


SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS tenants (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    kms_key_id TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS datasets (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    retention_days INTEGER,
    created_at TEXT NOT NULL,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_dataset_unique_name
ON datasets(tenant_id, name);

CREATE TABLE IF NOT EXISTS subject_keys (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    dataset_id TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    key_version INTEGER NOT NULL,
    kms_key_id TEXT,
    encryption_context_json TEXT NOT NULL,
    wrapped_key BLOB,
    wrapped_key_nonce BLOB,
    key_state TEXT NOT NULL,
    created_at TEXT NOT NULL,
    pending_deletion_until TEXT,
    destroyed_at TEXT,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id),
    FOREIGN KEY (dataset_id) REFERENCES datasets(id)
);

CREATE INDEX IF NOT EXISTS idx_subject_keys_lookup
ON subject_keys(tenant_id, dataset_id, subject_id, key_state, key_version DESC);

CREATE TABLE IF NOT EXISTS records (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    dataset_id TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    subject_key_id TEXT NOT NULL,
    record_type TEXT NOT NULL,
    ciphertext BLOB NOT NULL,
    nonce BLOB NOT NULL,
    aad TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id),
    FOREIGN KEY (dataset_id) REFERENCES datasets(id),
    FOREIGN KEY (subject_key_id) REFERENCES subject_keys(id)
);

CREATE INDEX IF NOT EXISTS idx_records_subject
ON records(tenant_id, dataset_id, subject_id, created_at DESC);

CREATE TABLE IF NOT EXISTS legal_holds (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    dataset_id TEXT,
    subject_id TEXT,
    reason TEXT NOT NULL,
    active INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    released_at TEXT,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id),
    FOREIGN KEY (dataset_id) REFERENCES datasets(id)
);

CREATE INDEX IF NOT EXISTS idx_legal_holds_active
ON legal_holds(tenant_id, dataset_id, subject_id, active);

CREATE TABLE IF NOT EXISTS deletion_requests (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    dataset_id TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    requested_by TEXT NOT NULL,
    reason TEXT NOT NULL,
    status TEXT NOT NULL,
    blocked_reason TEXT,
    created_at TEXT NOT NULL,
    executed_at TEXT,
    canceled_at TEXT,
    finalized_at TEXT,
    evidence_json TEXT,
    request_hash TEXT NOT NULL,
    step_up_authorized INTEGER DEFAULT 0,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id),
    FOREIGN KEY (dataset_id) REFERENCES datasets(id)
);

CREATE INDEX IF NOT EXISTS idx_deletion_request_lookup
ON deletion_requests(tenant_id, dataset_id, subject_id, status, created_at DESC);

CREATE TABLE IF NOT EXISTS audit_events (
    id TEXT PRIMARY KEY,
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    action TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    prev_hash TEXT,
    event_hash TEXT,
    chain_version INTEGER DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_audit_events_entity
ON audit_events(entity_type, entity_id, created_at DESC);
"""


def init_db() -> None:
    db_path = Path(settings.database_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    try:
        # 1. Ensure core schema exists
        conn.executescript(SCHEMA)
        
        # 2. Add columns if missing (additive migration)
        cursor = conn.execute("PRAGMA table_info(audit_events)")
        existing_audit_cols = [row[1] for row in cursor.fetchall()]
        if 'prev_hash' not in existing_audit_cols:
            conn.execute("ALTER TABLE audit_events ADD COLUMN prev_hash TEXT")
        if 'event_hash' not in existing_audit_cols:
            conn.execute("ALTER TABLE audit_events ADD COLUMN event_hash TEXT")
        if 'chain_version' not in existing_audit_cols:
            conn.execute("ALTER TABLE audit_events ADD COLUMN chain_version INTEGER DEFAULT 1")
            
        cursor = conn.execute("PRAGMA table_info(deletion_requests)")
        existing_delreq_cols = [row[1] for row in cursor.fetchall()]
        if 'step_up_authorized' not in existing_delreq_cols:
            conn.execute("ALTER TABLE deletion_requests ADD COLUMN step_up_authorized INTEGER DEFAULT 0")
            
            # Strict Backfill: Only authorize requests that have a verifiable 'scheduled' audit event
            conn.execute(
                """
                UPDATE deletion_requests 
                SET step_up_authorized = 1 
                WHERE status = 'scheduled' 
                  AND id IN (SELECT entity_id FROM audit_events WHERE action = 'deletion_request.scheduled')
                """
            )
            
        conn.commit()
    finally:
        conn.close()



@contextmanager
def get_conn() -> Iterator[sqlite3.Connection]:
    conn = sqlite3.connect(settings.database_path)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute('PRAGMA foreign_keys = ON;')
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
