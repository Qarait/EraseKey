# Finished Scope

EraseKey intentionally avoids becoming a general privacy-request platform.

The finished hobby-project scope is:

1. Encrypt records with subject-scoped envelope keys.
2. Schedule or immediately finalize cryptographic erasure.
3. Block writes while a deletion is scheduled or finalized.
4. Prevent overlapping deletion requests for the same subject scope.
5. Maintain an actor-aware tamper-evident audit chain.
6. Write signed deletion receipts outside the application database.
7. Detect and re-erase wrapped keys resurrected by a stale database restore.
8. Demonstrate the full behavior with automated tests.

Production authentication, a privacy request portal, connector marketplaces,
and multi-cloud orchestration are deliberate non-goals.
