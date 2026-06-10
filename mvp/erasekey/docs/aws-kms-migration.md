# AWS KMS Notes

EraseKey can use AWS KMS to generate and unwrap data keys. The integration is
an example control-plane adapter, not a production-ready AWS deployment.

## Key model

A deployment or tenant KMS key generates plaintext data keys and matching
encrypted key blobs. EraseKey stores only the encrypted blob with application
metadata. The plaintext key exists in memory only while encrypting or
decrypting a subject key.

## Encryption context

The adapter binds wrapped keys to an encryption context containing identifiers
such as:

- tenant ID
- dataset ID
- subject reference
- key purpose

AWS KMS requires the same context when decrypting. Keep personal data out of
the context because AWS records it in CloudTrail.

## Local provider

The local provider uses a fixed AES-GCM key from configuration. It mirrors only
the generate-and-unwrap shape and context mismatch behavior needed for local
development. It does not emulate KMS permissions, grants, throttling,
availability, audit logging, or key lifecycle behavior.

## Trying the AWS provider

Set these values before starting the API:

```bash
ERASEKEY_KMS_MODE=aws
ERASEKEY_AWS_KMS_KEY_ID=alias/erasekey-demo
```

Use a dedicated test account and key. The process also needs standard AWS
credentials with permission to call `kms:GenerateDataKey` and `kms:Decrypt`.

## Operational gaps

Before treating this as a production integration, add:

- narrowly scoped IAM policies
- retry and timeout handling
- KMS latency and error metrics
- managed credential delivery
- tests against real AWS failure modes
- documented key rotation and disaster-recovery procedures
