from __future__ import annotations

import secrets
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

from .config import settings


@dataclass(frozen=True)
class StepUpChallengeData:
    challenge: str
    action: str
    target_resource_id: str
    operator_id: str
    expires_at: float


class StepUpVerifier(ABC):
    @abstractmethod
    def generate_challenge(self, action: str, target_resource_id: str, operator_id: str) -> str:
        """Create a bound, one-time challenge."""
        pass

    @abstractmethod
    def verify_assertion(
        self,
        challenge_token: str,
        assertion_payload: dict[str, Any],
        action: str,
        target_resource_id: str,
        operator_id: str,
    ) -> bool:
        """Verify the assertion against the challenge and bindings."""
        pass


class MockStepUpVerifier(StepUpVerifier):
    """In-memory challenge verifier for local tests."""

    def __init__(self) -> None:
        self._challenges: dict[str, StepUpChallengeData] = {}

    def generate_challenge(self, action: str, target_resource_id: str, operator_id: str) -> str:
        token = secrets.token_urlsafe(32)
        self._challenges[token] = StepUpChallengeData(
            challenge=token,
            action=action,
            target_resource_id=target_resource_id,
            operator_id=operator_id,
            expires_at=time.time() + 300,
        )
        return token

    def verify_assertion(
        self,
        challenge_token: str,
        assertion_payload: dict[str, Any],
        action: str,
        target_resource_id: str,
        operator_id: str,
    ) -> bool:
        challenge = self._challenges.pop(challenge_token, None)
        if challenge is None:
            return False

        if time.time() > challenge.expires_at:
            return False

        if (
            challenge.action != action
            or challenge.target_resource_id != target_resource_id
            or challenge.operator_id != operator_id
        ):
            return False

        required_fields = {"clientDataJSON", "authenticatorData", "signature"}
        if not required_fields.issubset(assertion_payload):
            return False

        expected_sig = f"mock-sig-{settings.mock_stepup_pubkey_id}-{challenge_token}"
        return assertion_payload["signature"] == expected_sig


class WebAuthnVerifier(StepUpVerifier):
    """Placeholder for a real WebAuthn implementation."""

    def generate_challenge(self, action: str, target_resource_id: str, operator_id: str) -> str:
        raise NotImplementedError("WebAuthn mode is not implemented yet. Use 'mock' mode.")

    def verify_assertion(
        self,
        challenge_token: str,
        assertion_payload: dict[str, Any],
        action: str,
        target_resource_id: str,
        operator_id: str,
    ) -> bool:
        raise NotImplementedError("WebAuthn mode is not implemented yet. Use 'mock' mode.")


if settings.step_up_mode == "mock":
    verifier = MockStepUpVerifier()
else:
    verifier = WebAuthnVerifier()
