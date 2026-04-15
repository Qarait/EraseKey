# Antigravity playbook

This repo is structured so an agent-first IDE can pick up small, verifiable tasks.

## Recommended workflow

- Use planning mode for architecture changes or AWS integration.
- Use fast mode for small endpoint changes, tests, or docs.
- Require review before terminal commands if you are attaching this repo to real cloud accounts.
- Keep browser allowlists narrow when the agent browses docs.

## Mission 1: verify the baseline

Paste this into Antigravity:

```text
Open the EraseKey repository. Inspect the FastAPI app, run the test suite, and produce a walkthrough artifact that explains the cryptographic erasure flow end to end. Do not change code unless a test fails.
```

## Mission 2: add AWS KMS integration

```text
Replace the demo root key provider with an AWS KMS adapter behind an interface. Preserve local demo mode. Add environment-driven configuration, error handling, and tests around wrap/unwrap failure modes. Produce an implementation plan artifact before editing code.
```

## Mission 3: add restore-safe re-deletion

```text
Design and implement a restore-detection mechanism that marks datasets as needing re-delete after a restore event. Start with a local simulation mechanism and document how it would map to RDS snapshot restores and S3 object version recovery. Produce architecture and test artifacts.
```

## Mission 4: add tenant auth

```text
Add API key authentication with per-tenant authorization. Ensure a tenant can access only its own datasets, records, deletion requests, and evidence. Add tests and update the README.
```

## Mission 5: add evidence signing

```text
Extend deletion evidence so it is signed and can be verified offline. Use a local signing key for demo mode and document how a production signing service would work. Produce a walkthrough artifact showing verification.
```

## Mission 6: add a simple dashboard

```text
Build a minimal dashboard for tenants, datasets, records, deletion requests, legal holds, and evidence views. Keep styling simple and prioritize working flows over polish. Add screenshots and a walkthrough artifact.
```

## Guardrails

- Never change cryptographic semantics without updating tests.
- Never auto-delete root key material in demo mode.
- Treat subject IDs as sensitive identifiers.
- Keep evidence append-only.
