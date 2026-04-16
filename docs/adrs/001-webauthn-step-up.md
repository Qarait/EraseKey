# ADR 001: WebAuthn Step-Up Authentication

## Context
EraseKey exposes highly sensitive, destructive operations: scheduling, finalization, compilation of deletion requests, and the release of legal holds. These actions demand more stringent non-repudiation and operator presence checks, moving beyond generic bearer tokens to cryptographically verified "step-up" FIDO2/WebAuthn assertions.

Due to the scoped nature of the MVP, we need an abstraction boundary that prepares the system perfectly for the actual client-driven FIDO2 ceremony, without forcing full frontend WebAuthn integrations in this cycle.

## Decision
We will enforce step-up authentication using a robust challenge/response architecture, abstracted through a `StepUpVerifier` interface.

1.  **Challenge Lifecycle**:
    *   Operators orchestrate a flow by requesting a cryptographic challenge (e.g., via `POST /auth/step-up/challenge`).
    *   The challenge will be strictly bound to: `operator_identity`, `action` (e.g., execute, finalize), `target_resource_id`, and `expiry` (short-lived, e.g., 5 minutes).
2.  **API Contract**:
    *   Destructive endpoints will expect an authentication envelope (e.g., via headers like `X-StepUp-Assertion` or a dedicated payload component) containing the signed challenge and the consumed challenge token. This step-up material is passed cleanly as a FastAPI dependency, keeping business schemas unpolluted.
3.  **Interface and Implementations**:
    *   We introduce `StepUpVerifier` in `app/auth.py`.
    *   For the MVP, we supply two implementations: `MockStepUpVerifier` and a placeholder `WebAuthnStubVerifier`.
    *   The `MockStepUpVerifier` guarantees the real challenge-response state machine (asserting expiry, target/action binding, and replay prevention via consumed nonces).
4.  **Operational Honesty**:
    *   `STEP_UP_MODE=mock|webauthn_stub` controls the operational mode. 
    *   Hardcoded keys are forbidden. Authorized mock credentials or pubkeys must be loaded via config or bootstrap tables.
    *   The `/admin/security-status` (or `provider-status`) endpoint must explicitly surface when the application is operating in `mock` step-up mode to assure operators are aware of diminished FIDO limits.

## Consequences
- Protects destructive workflows precisely the way FIDO2 expects (explicit binding and replay protection).
- Validates the infrastructure layout immediately, saving heavy frontend WebAuthn implementations for future missions.
- Strict tests rule against replayed assertions, expired challenges, and action-mismatched targets.
