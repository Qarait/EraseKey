# EraseKey

EraseKey is a small FastAPI project that explores cryptographic deletion across
database restores.

Records are encrypted with per-subject data keys. Finalizing a deletion removes
the wrapped key and writes a signed receipt outside the application database. If
an old database snapshot later restores that key, the receipt can be used to
find and destroy it again.

The implementation lives in [`mvp/erasekey`](mvp/erasekey). See its
[README](mvp/erasekey/README.md) for setup, API details, and the restore
simulation.
