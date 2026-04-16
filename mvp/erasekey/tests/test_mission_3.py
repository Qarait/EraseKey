import pytest
import time
from fastapi.testclient import TestClient
from app.main import app
from app.config import settings
from app.auth import verifier
from app.db import get_conn
import json
import uuid

client = TestClient(app)

def test_security_status():
    response = client.get("/admin/security-status")
    assert response.status_code == 200
    data = response.json()
    assert "step_up_mode" in data
    assert "policy_engine_mode" in data
    assert data["operator_public_key_id"] == settings.mock_stepup_pubkey_id

def test_step_up_replay_prevention():
    # 1. Generate challenge
    resp = client.post("/auth/step-up/challenge?action=execute&target_resource_id=test-1&operator_id=op1")
    assert resp.status_code == 200
    challenge = resp.json()["challenge"]
    
    # 2. First mock assertion envelope
    auth_envelope = {
        "challenge": challenge,
        "operator_id": "op1",
        "assertion_payload": {
            "clientDataJSON": "{}",
            "authenticatorData": "{}",
            "signature": f"mock-sig-{settings.mock_stepup_pubkey_id}-{challenge}"
        }
    }
    
    from app.main import verify_step_up
    assert verify_step_up("execute", "test-1", auth_envelope) is True
    
    # 3. Replayed assertion should fail because challenge is consumed
    assert verify_step_up("execute", "test-1", auth_envelope) is False

def test_step_up_expiry():
    from app.main import verify_step_up
    bad_auth = {
        "challenge": "invalid-challenge",
        "operator_id": "op1",
        "assertion_payload": {
            "clientDataJSON": "{}", "authenticatorData": "{}", "signature": "..."
        }
    }
    assert verify_step_up("execute", "test-1", bad_auth) is False

def test_step_up_binding_mismatch():
    resp = client.post("/auth/step-up/challenge?action=execute&target_resource_id=res-1&operator_id=op1")
    challenge = resp.json()["challenge"]
    
    auth_envelope = {
        "challenge": challenge,
        "operator_id": "op1",
        "assertion_payload": {
            "clientDataJSON": "{}",
            "authenticatorData": "{}",
            "signature": f"mock-sig-{settings.mock_stepup_pubkey_id}-{challenge}"
        }
    }
    
    from app.main import verify_step_up
    # Action mismatch
    assert verify_step_up("finalize", "res-1", auth_envelope) is False
    
    # Re-generate for resource mismatch check
    resp = client.post("/auth/step-up/challenge?action=execute&target_resource_id=res-1&operator_id=op1")
    challenge = resp.json()["challenge"]
    auth_envelope["challenge"] = challenge
    auth_envelope["assertion_payload"]["signature"] = f"mock-sig-{settings.mock_stepup_pubkey_id}-{challenge}"
    
    # Resource mismatch
    assert verify_step_up("execute", "res-2", auth_envelope) is False

def test_malformed_auth_envelope():
    # 1. Missing fields in top-level envelope
    resp = client.post("/deletion-requests/any/execute", json={"challenge": "missing-operator"})
    assert resp.status_code == 422
    
    # 2. Bad shape in nested payload
    resp = client.post("/deletion-requests/any/execute", json={
        "challenge": "c", "operator_id": "op", "assertion_payload": {"sig": "bad-key-name"}
    })
    assert resp.status_code == 422

def test_missing_auth_body_results_in_deny():
    # For destructive actions, missing body results in step_up_verified=False -> 403
    resp = client.post("/deletion-requests/any/execute")
    assert resp.status_code == 403
    assert "STEP_UP_REQUIRED" in resp.json()["detail"]

def test_audit_chain_integrity():
    client.post("/tenants", json={"name": "Audit Chain Test"})
    resp = client.get("/admin/audit/verify")
    assert resp.status_code == 200
    assert resp.json()["ok"] is True
    
    with get_conn() as conn:
        conn.execute("UPDATE audit_events SET action = 'tampered' WHERE rowid = (SELECT rowid FROM audit_events LIMIT 1)")
        conn.commit()
    
    resp = client.get("/admin/audit/verify")
    assert resp.json()["ok"] is False

def test_policy_denies_even_if_step_up_succeeds():
    # Setup resources
    tenant = client.post("/tenants", json={"name": "Hold Test Unified"}).json()
    dataset = client.post("/datasets", json={"tenant_id": tenant["id"], "name": "DS1"}).json()
    req = client.post("/deletion-requests", json={
        "tenant_id": tenant["id"], "dataset_id": dataset["id"], "subject_id": "sub1",
        "requested_by": "tester", "reason": "test"
    }).json()
    client.post("/legal-holds", json={
        "tenant_id": tenant["id"], "dataset_id": dataset["id"], "subject_id": "sub1", "reason": "Hold it!"
    })
    
    # Generate valid step-up assertion
    step_resp = client.post(f"/auth/step-up/challenge?action=execute&target_resource_id={req['id']}&operator_id=op1")
    challenge = step_resp.json()["challenge"]
    auth_envelope = {
        "challenge": challenge,
        "operator_id": "op1",
        "assertion_payload": {
            "clientDataJSON": "{}",
            "authenticatorData": "{}",
            "signature": f"mock-sig-{settings.mock_stepup_pubkey_id}-{challenge}"
        }
    }
    
    # Execute with valid step-up envelope in body
    resp = client.post(f"/deletion-requests/{req['id']}/execute", json=auth_envelope)
    
    # Policy should still deny due to ACTIVE_LEGAL_HOLD
    assert resp.status_code == 403
    assert "ACTIVE_LEGAL_HOLD" in resp.json()["detail"]
