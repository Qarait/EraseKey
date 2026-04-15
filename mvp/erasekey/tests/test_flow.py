from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock
import json

BASE_TEMP = tempfile.mkdtemp(prefix='erasekey_test_')
os.environ['ERASEKEY_DB_PATH'] = str(Path(BASE_TEMP) / 'test.db')
os.environ['ERASEKEY_ROOT_KEY_PATH'] = str(Path(BASE_TEMP) / '.root_kek')
os.environ['ERASEKEY_KMS_MODE'] = 'mock'
os.environ['ERASEKEY_DELETION_WINDOW_DAYS'] = '7'

from fastapi.testclient import TestClient

from app.db import init_db, get_conn
from app.main import app
from app.key_providers import MockKmsProvider, KeyProviderError


class EraseKeyFlowTests(unittest.TestCase):
    def setUp(self) -> None:
        db_path = Path(os.environ['ERASEKEY_DB_PATH'])
        if db_path.exists():
            db_path.unlink()
        init_db()
        self.client = TestClient(app)

    def test_end_to_end_scheduled_lifecycle(self) -> None:
        os.environ['ERASEKEY_DELETION_WINDOW_DAYS'] = '7'
        from app.config import settings
        # Force reload config in test for window
        object.__setattr__(settings, 'deletion_window_days', 7)

        tenant = self.client.post('/tenants', json={'name': 'Acme'}).json()
        dataset = self.client.post(
            '/datasets', json={'tenant_id': tenant['id'], 'name': 'support_tickets', 'description': 'Support cases'}
        ).json()
        record = self.client.post(
            '/records',
            json={
                'tenant_id': tenant['id'], 'dataset_id': dataset['id'], 'subject_id': 'user_123',
                'record_type': 'ticket', 'payload': {'email': 'user@example.com', 'message': 'Please delete.'},
            },
        ).json()

        # Step 1: Active/Readable
        readable = self.client.get(f"/records/{record['id']}")
        self.assertEqual(readable.status_code, 200)
        self.assertEqual(readable.json()['erase_status'], 'readable')
        self.assertEqual(readable.json()['payload']['email'], 'user@example.com')

        # Step 2: Schedule Deletion
        deletion_request = self.client.post(
            '/deletion-requests',
            json={
                'tenant_id': tenant['id'], 'dataset_id': dataset['id'], 'subject_id': 'user_123',
                'requested_by': 'privacy-team', 'reason': 'GDPR erasure request',
            },
        ).json()
        self.assertEqual(deletion_request['status'], 'pending')

        executed = self.client.post(f"/deletion-requests/{deletion_request['id']}/execute")
        self.assertEqual(executed.status_code, 200)
        self.assertEqual(executed.json()['status'], 'scheduled')

        # Step 3: Verify read is blocked
        blocked_record = self.client.get(f"/records/{record['id']}")
        self.assertEqual(blocked_record.status_code, 200)
        self.assertEqual(blocked_record.json()['erase_status'], 'scheduled_for_erasure')
        self.assertIsNone(blocked_record.json()['payload'])

        # Step 4: Verify scheduled evidence
        sched_evidence = self.client.get(f"/deletion-requests/{deletion_request['id']}/evidence")
        self.assertEqual(sched_evidence.json()['status'], 'scheduled')
        self.assertIn('pending timeline expiration', sched_evidence.json()['evidence']['message'])

        # Step 5: Cancel
        canceled = self.client.post(f"/deletion-requests/{deletion_request['id']}/cancel")
        self.assertEqual(canceled.status_code, 200)
        self.assertEqual(canceled.json()['status'], 'canceled')

        # Step 6: Verify readable again
        readable_again = self.client.get(f"/records/{record['id']}")
        self.assertEqual(readable_again.json()['erase_status'], 'readable')
        self.assertIsNotNone(readable_again.json()['payload'])

        # Step 7: Schedule again and Finalize
        sched_again = self.client.post(f"/deletion-requests/{deletion_request['id']}/execute")
        self.assertEqual(sched_again.json()['status'], 'scheduled')

        finalized = self.client.post(f"/deletion-requests/{deletion_request['id']}/finalize")
        self.assertEqual(finalized.status_code, 200)
        self.assertEqual(finalized.json()['status'], 'finalized')

        # Step 8: Verify cryptographically erased
        erased = self.client.get(f"/records/{record['id']}")
        self.assertEqual(erased.json()['erase_status'], 'cryptographically_erased')
        self.assertIsNone(erased.json()['payload'])

        # Step 9: Final evidence
        fin_evidence = self.client.get(f"/deletion-requests/{deletion_request['id']}/evidence")
        self.assertEqual(fin_evidence.json()['status'], 'finalized')
        self.assertIn('destroyed', fin_evidence.json()['evidence']['message'])

    def test_immediate_finalization(self) -> None:
        from app.config import settings
        object.__setattr__(settings, 'deletion_window_days', 0)

        tenant = self.client.post('/tenants', json={'name': 'Acme'}).json()
        dataset = self.client.post('/datasets', json={'tenant_id': tenant['id'], 'name': 'dataset_b'}).json()
        record = self.client.post(
            '/records',
            json={
                'tenant_id': tenant['id'], 'dataset_id': dataset['id'], 'subject_id': 'user_imm',
                'record_type': 'ticket', 'payload': {'foo': 'bar'},
            },
        ).json()

        del_req = self.client.post(
            '/deletion-requests',
            json={
                'tenant_id': tenant['id'], 'dataset_id': dataset['id'], 'subject_id': 'user_imm',
                'requested_by': 'admin', 'reason': 'Immediate',
            },
        ).json()

        executed = self.client.post(f"/deletion-requests/{del_req['id']}/execute")
        self.assertEqual(executed.status_code, 200)
        self.assertEqual(executed.json()['status'], 'finalized')

        erased = self.client.get(f"/records/{record['id']}")
        self.assertEqual(erased.json()['erase_status'], 'cryptographically_erased')

    def test_legal_hold_blocks(self) -> None:
        from app.config import settings
        object.__setattr__(settings, 'deletion_window_days', 7)

        tenant = self.client.post('/tenants', json={'name': 'Acme'}).json()
        dataset = self.client.post('/datasets', json={'tenant_id': tenant['id'], 'name': 'contracts'}).json()
        
        hold = self.client.post(
            '/legal-holds',
            json={'tenant_id': tenant['id'], 'dataset_id': dataset['id'], 'subject_id': 'user_456', 'reason': 'Hold'},
        )

        del_req = self.client.post(
            '/deletion-requests',
            json={
                'tenant_id': tenant['id'], 'dataset_id': dataset['id'], 'subject_id': 'user_456',
                'requested_by': 'privacy', 'reason': 'req',
            },
        ).json()
        self.assertEqual(del_req['status'], 'blocked')

        # Execute fails
        execute = self.client.post(f"/deletion-requests/{del_req['id']}/execute")
        self.assertEqual(execute.json()['status'], 'blocked')
        
        # Release hold
        self.client.post(f"/legal-holds/{hold.json()['id']}/release")
        
        # Execute succeeds
        execute = self.client.post(f"/deletion-requests/{del_req['id']}/execute")
        self.assertEqual(execute.json()['status'], 'scheduled')

        # Place hold again
        self.client.post(
            '/legal-holds',
            json={'tenant_id': tenant['id'], 'dataset_id': dataset['id'], 'subject_id': 'user_456', 'reason': 'Hold 2'},
        )
        
        # Finalize fails due to new hold
        fin = self.client.post(f"/deletion-requests/{del_req['id']}/finalize")
        self.assertEqual(fin.status_code, 400)
        self.assertIn('Active legal hold', fin.json()['detail'])

    def test_encryption_context_mismatch_fails_decrypt(self) -> None:
        provider = MockKmsProvider()
        context = {"app": "erasekey", "tenant_id": "T1"}
        plaintext, ciphertext = provider.generate_data_key(context)
        
        # Good context
        unwrapped = provider.unwrap_data_key(ciphertext, context)
        self.assertEqual(plaintext, unwrapped)
        
        # Bad context
        bad_context = {"app": "erasekey", "tenant_id": "T2"}
        with self.assertRaises(KeyProviderError) as context_err:
            provider.unwrap_data_key(ciphertext, bad_context)
        self.assertIn("mismatched encryption context", str(context_err.exception))

if __name__ == '__main__':
    unittest.main()
