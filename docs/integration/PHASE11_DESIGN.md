# Phase 11 design note: the vault (encrypted backups)

Gate CL-16 (`tests/vault.test.ts`). No migration. User guide and the exact file format: `docs/VAULT.md`.

## What it delivers

Backup bundles are encrypted before they are stored (the spec's gap: "bundles are stored unencrypted in `BACKUP_DIR`"). The download stays the plain bundle, so nothing a creator does changes.

## Decisions made while designing, for review

1. **On by default, with no new setting.** The key is derived (HKDF, own label) from `MFA_ENCRYPTION_KEY`, which every server already has; `VAULT_ENCRYPTION_KEY` overrides it (recommended, so the login key and the backups can be lost and rotated separately). If no key exists, **a snapshot is not taken** (it is retried, and the failure is recorded) rather than stored in the clear.
2. **A chunked, authenticated format, not one big GCM message.** Bundles can be large; a single GCM message would have to be fully read before any of it can be trusted. Each chunk (1 MiB) is its own AES-256-GCM message with a counter nonce, the last one marked, so reordering, repeating, cutting off or adding to a file fails a tag, and nothing wrong is ever handed on. A fresh random data key per file, wrapped by the vault key (envelope encryption), so changing the key means re-wrapping 32 bytes per file, not re-encrypting the backups.
3. **Self-describing and documented byte for byte** (`docs/VAULT.md`). A test decrypts with a reader written only from the document, so backups do not depend on this code surviving. The offline tool `npm run vault -- decrypt` needs only the key.
4. **The record never changes, so nothing about the encryption is in it**: `mirror_snapshot` is immutable. The recorded SHA-256 and size are the bundle's (plaintext). Locked files keep the same names; legacy plain files are told apart by their first bytes (`CCVAULT1` versus `# v2 git bundle`). Hence no migration, and `encrypt-existing` can lock old backups in place.
5. **Downloads are authenticated while streaming and checked at the end**: damage in the first part is found before anything is sent (a clean 503); damage later, or a file that is not the recorded bundle, **cuts the download off** (the connection is destroyed) instead of letting it end as if it were whole.
6. **A way to find out a backup is bad before it is needed**: `POST .../verify` opens the file completely, compares with the record, and writes `mirror.verified` or `mirror.corrupt` to the project's record. (No automatic schedule yet: a periodic check is a small addition once someone wants the alerts.)
7. **Key changes are routine**: `VAULT_ENCRYPTION_KEY_PREVIOUS` keeps old files readable; `npm run vault -- rewrap` re-locks data keys without touching content; the derived key is always accepted for reading so adding a configured key strands nothing.
8. **The key is never exposed**: errors name a key by the id (8 bytes of its hash) only; `/health` reveals only whether backups are being locked.
9. **One existing test changed deliberately**: `tests/scheduler.test.ts` read the stored file and cloned it directly; it now checks that the stored file is locked, opens it with the vault, and then clones. The download test is unchanged and still passes (the download is plain).

## Not guaranteed, stated plainly

At rest only: whoever holds the running server's environment holds the key. Not covered: the database, the gateway's temporary working copies (deleted when a session or door ends), the project's record (meant to be readable). Lose every copy of the key and the backups are gone for good.
