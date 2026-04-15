# AWS KMS Migration & Deletion Assurance

EraseKey has evolved from a simple AES-GCM local wrapper to a production-ready deletion assurance platform utilizing AWS Key Management Service (KMS).

## 1. Local Scheduled Erasure vs Per-Subject KMS Keys

**Why don't we just create an AWS KMS CMK for every subject and call `ScheduleKeyDeletion`?**

AWS KMS imposes hard limits on the number of Customer Master Keys (CMKs) you can provision (typically in the tens of thousands per region) and charges a monthly fee per key. Creating a CMK for every individual user/subject in a multi-tenant SaaS application is both financially and operationally prohibitive.

Instead, EraseKey uses a **single deployment-wide KMS key** (or a per-tenant override) to generate and wrap individual **Subject Data Keys**. When a subject requests deletion, we implement a *local* scheduled erasure lifecycle within our own metadata store (`subject_keys`). When the time comes to finalize the deletion, we execute the cryptographic erasure by destroying the wrapped ciphertext blob of the subject key from our SQLite database. Because the encryption context is securely bound, regenerating the key is impossible.

## 2. Scheduled vs Finalized States

EraseKey's local deletion lifecycle directly mimics the AWS KMS `PendingDeletion` state.

### Scheduled (`pending_erasure`)
If a deletion request is executed with an `ERASEKEY_DELETION_WINDOW_DAYS > 0` (e.g., 7 days):
- The `subject_key` transitions to `pending_erasure`.
- The `deletion_request` transitions to `scheduled`.
- **System Behavior**: EraseKey's application logic artificially blocks access. If a client attempts to fetch related records, the API will return a `null` payload and an `erase_status` of `scheduled_for_erasure`. Decryption is explicitly short-circuited.
- **Cancellation**: During this window, an administrator can call `POST /deletion-requests/{id}/cancel` to revert the keys to `active` and resume normal access.

### Finalized (`destroyed`)
When the `pending_deletion_until` timestamp expires (or if the window was set to `0`), the deletion can be finalized.
- The `wrapped_key` blob is permanently wiped from the database.
- The `subject_key` transitions to `destroyed`.
- The `deletion_request` transitions to `finalized`.
- **System Behavior**: Access is physically impossible. Records will return `cryptographically_erased`. 

## 3. Evidence Interpretation

The `/evidence` endpoint dynamically adjusts its attestation depending on the current phase of the deletion request:

- **Scheduled Evidence**: Clearly states that access is blocked *by policy* and that the final cryptographic erasure is pending a timeline expiration. It **does not** claim the data is cryptographically erased yet.
- **Finalized Evidence**: A robust attestation that the actual `wrapped_key` representing the subject was irrevocably destroyed.

## 4. Local Mock vs AWS KMS

EraseKey provides a `MockKmsProvider` used for local testing and CI (`ERASEKEY_KMS_MODE=mock`). 

The mock provider achieves 100% parity with the critical `AwsKmsProvider` (`boto3`) behaviors:
- It returns separate plaintext and ciphertext blobs.
- It strictly enforces the exact `EncryptionContext` parameters. Changing even one byte of the `dataset_id` or `tenant_id` on the decryption call will intentionally hard-fail the mock provider, simulating a KMS `InvalidCiphertextException`.

To run against real AWS infrastructure, ensure standard AWS credentials (`~/.aws/credentials` or environment variables) are loaded and set `ERASEKEY_KMS_MODE=aws` and `ERASEKEY_AWS_KMS_KEY_ID=arn:aws:kms...`.

## 5. Privacy Logic: The Encryption Context

AWS KMS logs the `EncryptionContext` in AWS CloudTrail for every `GenerateDataKey` and `Decrypt` request. 

**Rule:** `EncryptionContext` must never contain Personally Identifiable Information (PII) such as emails, raw User IDs, or full names.

For this reason, EraseKey hashes the `subject_id` into a deterministic `subject_ref` (`sha256_hex`) before attaching it to the `EncryptionContext`. This guarantees cryptographic binding at the key provider level without leaking PII into your enterprise CloudTrail logs.
