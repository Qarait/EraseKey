from __future__ import annotations

from abc import ABC, abstractmethod
from enum import Enum
from typing import Optional

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
        """Evaluate an operation against the configured policy rules."""
        pass


class Gate1PolicyEngine(PolicyEngine):
    def __init__(self, client: Gate1Client) -> None:
        self.client = client

    def evaluate(self, context: PolicyContext) -> PolicyResponse:
        response = self.client.evaluate_policy(context.model_dump())
        return PolicyResponse(
            decision=(
                PolicyDecision.ALLOW
                if response.get("decision") == "allow"
                else PolicyDecision.DENY
            ),
            reason_code=response.get("reason_code", "UNKNOWN_POLICY_RESPONSE"),
        )


class LocalPolicyEngine(PolicyEngine):
    destructive_actions = {
        "execute",
        "finalize",
        "release_hold",
        "release_legal_hold",
        "cancel",
    }

    def evaluate(self, context: PolicyContext) -> PolicyResponse:
        if context.actor_type == ActorType.SYSTEM_WORKER:
            if context.action == "finalize":
                if not context.prior_execute_step_up_verified:
                    return PolicyResponse(decision=PolicyDecision.DENY, reason_code="PRIOR_STEP_UP_MISSING")
                if not context.scheduled_and_due:
                    return PolicyResponse(decision=PolicyDecision.DENY, reason_code="NOT_DUE")
                if context.active_hold_present:
                    return PolicyResponse(decision=PolicyDecision.DENY, reason_code="ACTIVE_LEGAL_HOLD")
                return PolicyResponse(decision=PolicyDecision.ALLOW, reason_code="OK")

            if context.action in self.destructive_actions:
                return PolicyResponse(
                    decision=PolicyDecision.DENY,
                    reason_code="SYSTEM_WORKER_UNAUTHORIZED",
                )

        if context.action in self.destructive_actions and not context.step_up_verified:
            return PolicyResponse(decision=PolicyDecision.DENY, reason_code="STEP_UP_REQUIRED")

        if context.action in {"execute", "finalize"} and context.active_hold_present:
            return PolicyResponse(decision=PolicyDecision.DENY, reason_code="ACTIVE_LEGAL_HOLD")

        if context.action == "finalize" and not context.retention_expired:
            return PolicyResponse(decision=PolicyDecision.DENY, reason_code="RETENTION_NOT_EXPIRED")

        return PolicyResponse(decision=PolicyDecision.ALLOW, reason_code="OK")


if settings.policy_engine_mode == "gate1":
    engine = Gate1PolicyEngine(Gate1Client())
else:
    engine = LocalPolicyEngine()
