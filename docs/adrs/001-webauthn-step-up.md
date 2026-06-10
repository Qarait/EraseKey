# ADR 001: Step-up authentication boundary

## Status

Accepted for the local implementation. Real WebAuthn verification is not
implemented.

## Context

Scheduling deletion, finalizing key destruction, canceling a scheduled request,
and releasing a legal hold are sensitive operations. They need stronger
authorization than ordinary reads and writes.

The local project does not have a browser client or credential store, but the
service boundary should still model the properties required by WebAuthn:

- short-lived challenges;
- binding to the operator, action, and resource;
- one-time use;
- a stable request envelope.

## Decision

`StepUpVerifier` defines challenge creation and assertion verification.
`MockStepUpVerifier` implements the lifecycle with an in-memory challenge store
and a deterministic test signature. `WebAuthnVerifier` raises
`NotImplementedError`.

The API reports the active mode through `/admin/security-status` so mock mode is
not mistaken for real authentication.

## Consequences

- Destructive routes exercise replay prevention and request binding.
- Challenges are lost on restart and do not work across multiple processes.
- Mock signatures provide no security and are suitable only for local testing.
- A production implementation needs persistent challenges, operator identity,
  origin and RP-ID checks, credential lookup, and signature verification.
