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
    
    kms_mode: str = os.getenv('ERASEKEY_KMS_MODE', 'mock').lower()
    aws_kms_key_id: str | None = os.getenv('ERASEKEY_AWS_KMS_KEY_ID')
    
    # Allow specifying 0 for immediate deletion
    deletion_window_days: int = int(os.getenv('ERASEKEY_DELETION_WINDOW_DAYS', '7'))

settings = Settings()
