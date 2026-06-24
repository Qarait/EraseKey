from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / 'data'
DATA_DIR.mkdir(parents=True, exist_ok=True)


def _env_bool(name: str, default: bool = False) -> bool:
    raw_value = os.getenv(name)
    if raw_value is None:
        return default
    return raw_value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    app_name: str = os.getenv("ERASEKEY_APP_NAME", "EraseKey")
    database_path: str = os.getenv("ERASEKEY_DB_PATH", str(DATA_DIR / "erasekey.db"))
    receipt_log_path: str = os.getenv(
        "ERASEKEY_RECEIPT_LOG_PATH",
        str(DATA_DIR / "deletion_receipts.jsonl"),
    )
    receipt_signing_key_path: str = os.getenv(
        "ERASEKEY_RECEIPT_SIGNING_KEY_PATH",
        str(DATA_DIR / ".receipt_signing_key"),
    )

    kms_mode: str = os.getenv("ERASEKEY_KMS_MODE", "mock").lower()
    aws_kms_key_id: str | None = os.getenv("ERASEKEY_AWS_KMS_KEY_ID")
    deletion_window_days: int = int(
        os.getenv("ERASEKEY_DELETION_WINDOW_DAYS", "7")
    )

    step_up_mode: str = os.getenv("ERASEKEY_STEP_UP_MODE", "mock").lower()
    mock_stepup_pubkey_id: str = os.getenv(
        "ERASEKEY_MOCK_STEPUP_PUBKEY_ID",
        "mock-operator-pubkey-001",
    )
    policy_engine_mode: str = os.getenv(
        "ERASEKEY_POLICY_ENGINE_MODE",
        "local",
    ).lower()
    gate1_cli_path: str = os.getenv("ERASEKEY_GATE1_CLI_PATH", "gate1")
    public_demo_mode: bool = _env_bool("ERASEKEY_PUBLIC_DEMO_MODE")
    public_demo_rate_limit_per_minute: int = int(
        os.getenv("ERASEKEY_PUBLIC_DEMO_RATE_LIMIT_PER_MINUTE", "12")
    )
    demo_endpoint_enabled: bool = _env_bool("ERASEKEY_ENABLE_DEMO_ENDPOINT", True)

settings = Settings()
