from __future__ import annotations

import secrets
import time
from abc import ABC, abstractmethod
from typing import Dict, Optional
from .config import settings

class StepUpChallengeData:
    def __init__(self, challenge: str, action: str, target_resource_id: str, operator_id: str, expires_at: float):
        self.challenge = challenge
        self.action = action
        self.target_resource_id = target_resource_id
        self.operator_id = operator_id
        self.expires_at = expires_at

class StepUpVerifier(ABC):
    @abstractmethod
    def generate_challenge(self, action: str, target_resource_id: str, operator_id: str) -> str:
        """Create a bound, one-time challenge."""
        pass

    @abstractmethod
    def verify_assertion(self, 
                       challenge_token: str, 
                       assertion_payload: Dict[str, Any], 
                       action: str, 
                       target_resource_id: str, 
                       operator_id: str) -> bool:
        """Verify the assertion against the challenge and bindings."""
        pass

class MockStepUpVerifier(StepUpVerifier):
    """
    Mock verifier implements the full challenge-response state machine.
    Follows WebAuthn-like binding and structural shape.
    Used for MVP 'step-up mock mode'.
    """
    def __init__(self):
        # In-memory storage for nonces/challenges for MVP
        self._challenges: Dict[str, StepUpChallengeData] = {}

    def generate_challenge(self, action: str, target_resource_id: str, operator_id: str) -> str:
        token = secrets.token_urlsafe(32)
        # Short expiry: 5 minutes
        expires_at = time.time() + 300 
        self._challenges[token] = StepUpChallengeData(
            challenge=token,
            action=action,
            target_resource_id=target_resource_id,
            operator_id=operator_id,
            expires_at=expires_at
        )
        return token

    def verify_assertion(self, 
                       challenge_token: str, 
                       assertion_payload: Dict[str, Any], 
                       action: str, 
                       target_resource_id: str, 
                       operator_id: str) -> bool:
        data = self._challenges.get(challenge_token)
        if not data:
            # Challenge not found (already used or never existed)
            return False
            
        # Replay prevention: consume challenge IMMEDIATELY
        del self._challenges[challenge_token]

        # 1. Check expiry
        if time.time() > data.expires_at:
            return False
        
        # 2. Verify bindings in the challenge data
        if data.action != action or data.target_resource_id != target_resource_id or data.operator_id != operator_id:
            return False

        # 3. Verify 'WebAuthn' shape in the assertion payload
        # Required fields for mock 'WebAuthn' shape
        required = ["clientDataJSON", "authenticatorData", "signature"]
        if not all(k in assertion_payload for k in required):
            return False

        # In Mock mode, we accept signatures that match a known mock pattern
        # The signature includes the public key ID to demonstrate 'security honesty'
        expected_sig = f"mock-sig-{settings.mock_stepup_pubkey_id}-{challenge_token}"
        return assertion_payload["signature"] == expected_sig

class WebAuthnVerifier(StepUpVerifier):
    """
    Stub for future real WebAuthn integration.
    """
    def generate_challenge(self, action: str, target_resource_id: str, operator_id: str) -> str:
        # Real WebAuthn challenges would be stored in a DB with proper session association
        raise NotImplementedError("WebAuthn mode is not implemented yet. Use 'mock' mode.")

    def verify_assertion(self, challenge_token: str, assertion_payload: Dict[str, Any], action: str, target_resource_id: str, operator_id: str) -> bool:
        raise NotImplementedError("WebAuthn mode is not implemented yet. Use 'mock' mode.")

# Global instance initialized based on config
if settings.step_up_mode == "mock":
    verifier = MockStepUpVerifier()
else:
    verifier = WebAuthnVerifier()
