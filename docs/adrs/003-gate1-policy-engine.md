# ADR 003: Policy Engine Boundary

## Context
Decisions requiring destruction (like `.execute()`, `.finalize()`), or modifying constraints (like `release_legal_hold`) sit atop complex business requirements. Hardcoding rules like `_find_active_holds()` inside the database access tier creates tightly coupled logic. The eventual target for EraseKey is `gate1`, an authoritative external policy kernel. Recreating `gate1` entirely within Python would be misleading and architecturally divergent from its future role as a decoupled sidecar or dedicated service.

## Decision
We establish a clean service abstraction boundary via `app/policy_engine.py` without faking `gate1` implementations directly in this repository.

1.  **Interface Over Implementation**:
    *   We introduce a strict `PolicyEngine` interface.
    *   For the MVP transition, we implement a `LegacyPolicyEngine` that serves real policy decisions locally (maintaining parity and introducing new constraints) without misrepresenting itself as the future `gate1`.
2.  **Expanded Policy Scope**:
    *   Input context explicitly includes: `active_hold_present`, `retention_expired`, `step_up_verified`, `operator_role`, `approvals_count`, `deletion_window_state`, `tenant_id`, and `dataset_id`.
    *   Destructive actions (`execute`, `finalize`, `release_legal_hold`) MUST hit the policy interface, passing the comprehensive state.
3.  **Output Mandates**:
    *   The `PolicyEngine` exclusively yields a strict `ALLOW` or `DENY`.
    *   A `DENY` decision carries a specific standard reason code.
    *   Fail-Closed Rule: Missing variables, missing initialization, or internal engine panics naturally degrade to `DENY`.

## Consequences
- Policy definitions (like "are dual approvers required?") live naturally in the `LegacyPolicyEngine` implementation space rather than cluttering CRUD services.
- Later missions can seamlessly swap `LegacyPolicyEngine` for `Gate1PolicyEngine` (communicating over CLI/subprocess/HTTP to an external Open Policy Agent derivative) without refactoring the core execution cycle.
- Demands rigorous test structures mimicking valid and denied context environments separately from typical endpoint parameter tests.
