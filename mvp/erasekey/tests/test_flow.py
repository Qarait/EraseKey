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

    def test_admin_provider_status(self) -> None:
        response = self.client.get('/admin/provider-status')
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data['kms_mode'], 'mock')
        self.assertIn('kms_key_id', data)
        self.assertEqual(data['deletion_window_days'], 7)
        self.assertTrue(data['auto_finalization_enabled'])

    @mock.patch('app.utils.utc_now_dt')
    def test_automatic_finalization_worker(self, mock_now_dt) -> None:
        # 1. Setup: Start at T=0
        mock_now_dt.return_value = datetime(2026, 4, 15, tzinfo=timezone.utc)
        
        tenant = self.client.post('/tenants', json={'name': 'WorkerTest'}).json()
        dataset = self.client.post('/datasets', json={'tenant_id': tenant['id'], 'name': 'ds'}).json()
        record = self.client.post(
            '/records',
            json={'tenant_id': tenant['id'], 'dataset_id': dataset['id'], 'subject_id': 's1', 'record_type': 't', 'payload': {'x': 1}}
        ).json()
        
        del_req = self.client.post(
            '/deletion-requests',
            json={'tenant_id': tenant['id'], 'dataset_id': dataset['id'], 'subject_id': 's1', 'requested_by': 'bot', 'reason': 'test'}
        ).json()
        
        # 2. Execute: Scheduling happens at T=0. Window is 7 days.
        self.client.post(f"/deletion-requests/{del_req['id']}/execute")
        
        # 3. Run worker at T+1 day: Should do nothing
        mock_now_dt.return_value = datetime(2026, 4, 16, tzinfo=timezone.utc)
        from app.services import finalize_due_deletions
        finalized = finalize_due_deletions()
        self.assertEqual(len(finalized), 0)
        
        # 4. Run worker at T+8 days: Should finalize
        mock_now_dt.return_value = datetime(2026, 4, 23, tzinfo=timezone.utc)
        finalized = finalize_due_deletions()
        self.assertEqual(len(finalized), 1)
        self.assertEqual(finalized[0], del_req['id'])
        
        # 5. Verify records are erased
        erased = self.client.get(f"/records/{record['id']}")
        self.assertEqual(erased.json()['erase_status'], 'cryptographically_erased')

    @mock.patch('app.utils.utc_now_dt')
    def test_worker_respects_new_legal_hold(self, mock_now_dt) -> None:
        mock_now_dt.return_value = datetime(2026, 4, 15, tzinfo=timezone.utc)
        tenant = self.client.post('/tenants', json={'name': 'HoldTest'}).json()
        dataset = self.client.post('/datasets', json={'tenant_id': tenant['id'], 'name': 'ds'}).json()
        
        del_req = self.client.post(
            '/deletion-requests',
            json={'tenant_id': tenant['id'], 'dataset_id': dataset['id'], 'subject_id': 's2', 'requested_by': 'bot', 'reason': 'test'}
        ).json()
        
        self.client.post(f"/deletion-requests/{del_req['id']}/execute")
        
        # Time passes...
        mock_now_dt.return_value = datetime(2026, 4, 25, tzinfo=timezone.utc)
        
        # BUT: A legal hold is added at the last minute
        self.client.post(
            '/legal-holds',
            json={'tenant_id': tenant['id'], 'dataset_id': dataset['id'], 'subject_id': 's2', 'reason': 'New Hold'}
        )
        
        from app.services import finalize_due_deletions
        finalized = finalize_due_deletions()
        
        # Worker should skip it despite being due
        self.assertEqual(len(finalized), 0)
        
        # Status should still be 'scheduled'
        updated_req = self.client.get(f"/deletion-requests/{del_req['id']}").json()
        self.assertEqual(updated_req['status'], 'scheduled')

if __name__ == '__main__':
    unittest.main()
