from __future__ import annotations

from abc import ABC, abstractmethod
from enum import Enum
from typing import Optional, Any
from pydantic import BaseModel

from .config import settings
from .gate1_client import Gate1Client

class PolicyDecision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"

class ActorType(str, Enum):
    HUMAN = "human"
    SYSTEM_WORKER = "system_worker"

class PolicyContext(BaseModel):
    action: str
    tenant_id: str
    dataset_id: Optional[str] = None
    subject_id: Optional[str] = None
    active_hold_present: bool = False
    retention_expired: bool = True
    step_up_verified: bool = False
    actor_type: ActorType = ActorType.HUMAN
    scheduled_and_due: bool = False
    prior_execute_step_up_verified: bool = False
    operator_role: str = "operator"
    approvals_count: int = 0
    deletion_window_state: str = "active"

class PolicyResponse(BaseModel):
    decision: PolicyDecision
    reason_code: str

class PolicyEngine(ABC):
    @abstractmethod
    def evaluate(self, context: PolicyContext) -> PolicyResponse:
        """Evaluate the context against authoritative policies. Must fail-closed."""
        pass

class Gate1PolicyEngine(PolicyEngine):
    """
    Adapter for the Gate1 authoritative policy kernel.
    """
    def __init__(self, client: Gate1Client):
        self.client = client

    def evaluate(self, context: PolicyContext) -> PolicyResponse:
        # Forward context to the gate1 client
        resp_data = self.client.evaluate_policy(context.dict())
        
        # Explicit fail-closed mapping
        decision = PolicyDecision.DENY
        if resp_data.get("decision") == "allow":
            decision = PolicyDecision.ALLOW
            
        return PolicyResponse(
            decision=decision,
            reason_code=resp_data.get("reason_code", "UNKNOWN_POLICY_RESPONSE")
        )

class LegacyPolicyEngine(PolicyEngine):
    """
    Temporary local policy engine mimicking future gate1 behaviors.
    """
    def evaluate(self, context: PolicyContext) -> PolicyResponse:
        # Destructive actions across all actor types
        destructive_actions = ["execute", "finalize", "release_hold", "release_legal_hold", "cancel"]
        
        # 1. System Worker Rules
        if context.actor_type == ActorType.SYSTEM_WORKER:
            if context.action == "finalize":
                if not context.prior_execute_step_up_verified:
                    return PolicyResponse(decision=PolicyDecision.DENY, reason_code="PRIOR_STEP_UP_MISSING")
                if not context.scheduled_and_due:
                    return PolicyResponse(decision=PolicyDecision.DENY, reason_code="NOT_DUE")
                if context.active_hold_present:
                    return PolicyResponse(decision=PolicyDecision.DENY, reason_code="ACTIVE_LEGAL_HOLD")
                return PolicyResponse(decision=PolicyDecision.ALLOW, reason_code="OK")
            
            # System worker is NOT authorized for any other destructive actions
            if context.action in destructive_actions:
                 return PolicyResponse(decision=PolicyDecision.DENY, reason_code="SYSTEM_WORKER_UNAUTHORIZED")

        # 2. Human Rules
        # Fail-closed: Ensure step-up is verified for destructive actions initiated by humans
        if context.action in destructive_actions and not context.step_up_verified:
            return PolicyResponse(decision=PolicyDecision.DENY, reason_code="STEP_UP_REQUIRED")

        # Legal holds block execute and finalize
        if context.action in ["execute", "finalize"] and context.active_hold_present:
            return PolicyResponse(decision=PolicyDecision.DENY, reason_code="ACTIVE_LEGAL_HOLD")

        # Finalize requires retention to be expired (if applicable)
        if context.action == "finalize" and not context.retention_expired:
            return PolicyResponse(decision=PolicyDecision.DENY, reason_code="RETENTION_NOT_EXPIRED")

        # 3. Default: allow for now in Legacy mode if no blocks triggered
        return PolicyResponse(decision=PolicyDecision.ALLOW, reason_code="OK")

# Global engine instance
if settings.policy_engine_mode == "gate1":
    engine = Gate1PolicyEngine(Gate1Client())
else:
    engine = LegacyPolicyEngine()
