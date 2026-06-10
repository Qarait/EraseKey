# EraseKey Restore Lab

EraseKey is a security engineering lab for one narrow question:

> If an old database snapshot resurrects encrypted user data, can the system
> remember that the subject was deleted and make the restored copy unreadable
> again?

It combines subject-scoped envelope encryption with an external signed deletion
receipt journal. The journal survives independently of SQLite, blocks new writes
for erased subjects, and drives re-erasure after a stale restore.

## Project Structure

- **[mvp/erasekey/](mvp/erasekey/)**: FastAPI restore-safety lab.
- **docs/**: Architectural and product documentation.

Please refer to [mvp/erasekey/README.md](mvp/erasekey/README.md) for installation and usage instructions.
