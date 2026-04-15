# Product brief

## Working title
EraseKey

## Positioning
Deletion Assurance for cloud SaaS teams.

## The problem
Teams promise deletion, but modern cloud systems replicate data into snapshots, versioned object stores, analytics pipelines, and long-lived backups. A row delete in the primary database does not reliably erase those copies.

## The product wedge
Start with a narrow buyer and a narrow stack:

- Buyer: B2B SaaS companies with privacy/compliance pressure
- Stack: AWS-first
- Initial systems: app database + S3-like object store + deletion evidence

## Core promise
When a valid deletion request arrives, EraseKey destroys the wrapped subject keys that protect the encrypted data. The ciphertext may remain in place, but it becomes unreadable. The system also records legal-hold checks and emits machine-readable evidence.

## Ideal first customer
A startup or mid-market SaaS team that:

- stores customer-generated content
- needs deletion workflows that are more credible than soft delete
- uses AWS and wants a path to stronger privacy controls without rebuilding everything at once

## MVP scope
- Subject-scoped envelope encryption
- Dataset registration
- Record ingestion under active subject keys
- Legal holds
- Deletion request workflow
- Cryptographic erasure execution
- Audit events and evidence export

## Non-goals for MVP
- Full privacy request intake portal
- Cross-cloud support
- Automatic discovery of all copies across every system
- Machine unlearning
- Immutable compliance archive design

## Why the design is defensible
The hard part is not a pretty dashboard. The hard part is making deletion behavior technically honest, operationally safe, and auditable.
