import logging
from typing import Any

from .config import settings

logger = logging.getLogger(__name__)


class Gate1Client:
    """Fail-closed boundary for the optional Gate1 policy evaluator."""

    def __init__(self, cli_path: str = settings.gate1_cli_path) -> None:
        self.cli_path = cli_path

    def evaluate_policy(self, context: dict[str, Any]) -> dict[str, Any]:
        logger.warning(
            "Gate1 policy mode is configured, but no evaluator is installed at %s",
            self.cli_path,
        )
        return {"decision": "deny", "reason_code": "POLICY_ENGINE_UNAVAILABLE"}
