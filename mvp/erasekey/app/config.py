from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / 'data'
DATA_DIR.mkdir(parents=True, exist_ok=True)


@dataclass(frozen=True)
class Settings:
    app_name: str = os.getenv('ERASEKEY_APP_NAME', 'EraseKey')
    database_path: str = os.getenv('ERASEKEY_DB_PATH', str(DATA_DIR / 'erasekey.db'))
    root_key_path: str = os.getenv('ERASEKEY_ROOT_KEY_PATH', str(DATA_DIR / '.demo_root_kek'))
    receipt_log_path: str = os.getenv(
        'ERASEKEY_RECEIPT_LOG_PATH',
        str(DATA_DIR / 'deletion_receipts.jsonl'),
    )
    receipt_signing_key_path: str = os.getenv(
        'ERASEKEY_RECEIPT_SIGNING_KEY_PATH',
        str(DATA_DIR / '.receipt_signing_key'),
    )
    
    kms_mode: str = os.getenv('ERASEKEY_KMS_MODE', 'mock').lower()
    aws_kms_key_id: str | None = os.getenv('ERASEKEY_AWS_KMS_KEY_ID')
    
    # Allow specifying 0 for immediate deletion
    deletion_window_days: int = int(os.getenv('ERASEKEY_DELETION_WINDOW_DAYS', '7'))

    step_up_mode: str = os.getenv('ERASEKEY_STEP_UP_MODE', 'mock').lower()
    # mock_stepup_pubkey_id is used for the mock verification pattern in mock mode
    mock_stepup_pubkey_id: str = os.getenv('ERASEKEY_MOCK_STEPUP_PUBKEY_ID', 'mock-operator-pubkey-001')

    policy_engine_mode: str = os.getenv('ERASEKEY_POLICY_ENGINE_MODE', 'legacy').lower()
    # gate1_socket or gate1_cli_path could be added here if needed for gate1 integration
    gate1_cli_path: str = os.getenv('ERASEKEY_GATE1_CLI_PATH', 'gate1')

settings = Settings()
