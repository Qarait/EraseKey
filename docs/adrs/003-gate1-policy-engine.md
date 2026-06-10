# ADR 003: Policy evaluation boundary

## Status

Accepted. The local evaluator is the default.

## Context

Deletion decisions depend on legal holds, step-up verification, retention, the
calling actor, and whether a scheduled request is due. Keeping those checks
behind one interface makes the decision path easier to test and replace.

## Decision

`PolicyEngine.evaluate()` accepts a `PolicyContext` and returns an allow or deny
decision with a reason code.

`LocalPolicyEngine` implements the rules used by this repository.
`Gate1PolicyEngine` is an adapter for an external command-line evaluator. The
adapter denies requests when the external evaluator is unavailable or returns an
unrecognized response.

## Consequences

- Services receive a small, consistent policy result.
- External policy mode fails closed.
- Some fields in `PolicyContext` are reserved for policy experiments and are not
  currently used by the local evaluator.
