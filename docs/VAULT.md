# The vault: encrypted backups

Everything the server keeps as a backup for you is **locked before it is stored**: a backup snapshot of a closed door (a git bundle) is encrypted with AES-256-GCM, so the files in `BACKUP_DIR` (or a disk image, a volume snapshot, a stolen copy of the directory) are unreadable without the vault key.
(Phase 11 of `docs/integration/PHASE0_SPEC.md`; design: `docs/integration/PHASE11_DESIGN.md`.)

What you see does not change: the download is the ordinary bundle (decrypted on the way out), restores with plain `git clone`, and its SHA-256 is the one recorded in the project's record. The encryption is in the storage, not in the workflow.

## The key

- **By default there is nothing to set up.** The vault key is derived (HKDF-SHA256, with its own label `custody-core/vault/v1`) from `MFA_ENCRYPTION_KEY`, which every server already has.
- **Recommended for serious use:** set a key of its own, `VAULT_ENCRYPTION_KEY` (32 random bytes, base64: `openssl rand -base64 32`), and keep a copy somewhere other than the server. Then losing the login key does not also lose the backups, and the two can be rotated separately.
- **Keep a copy.** Without the key a backup cannot be opened by anyone, including us. That is the point, and the risk.
- `npm run vault -- status` shows which key backups are locked with, by its id (the first 8 bytes of its SHA-256); never the key.
- `/api/v1/health` says `"vault": { "encrypting": true }` (or false if no key is available: then new snapshots are not taken, and are retried, rather than stored unlocked).

## Changing the key

1. Put the new key in `VAULT_ENCRYPTION_KEY`, and the old one(s) in `VAULT_ENCRYPTION_KEY_PREVIOUS` (comma-separated). The key derived from `MFA_ENCRYPTION_KEY` is always accepted for reading, so adding a configured key never strands earlier backups.
2. `npm run vault -- rewrap` locks every backup's data key with the new key. It does not touch the content, so it is quick whatever the size.
3. When it reports nothing left to do, the old key is no longer needed.

## Backups made before the vault

They stay readable as they are. `npm run vault -- encrypt-existing` locks them in place (same file name, so the record, which never changes, still points at it; the recorded SHA-256 is still the bundle's). Each is checked after it is locked, and `mirror.encrypted` is written to the project's record.

## Checking a backup

`POST /api/v1/projects/:id/snapshots/:snapshotId/verify` opens the stored file completely (decrypting and authenticating every part) and compares it with the recorded SHA-256 and size. The answer is `{ ok: true, encrypted, bytes }`, or `409 { ok: false, problem: "missing" | "unreadable" | "mismatch" }`; either way it is written to the project's record (`mirror.verified` / `mirror.corrupt`). Do this from time to time: a backup nobody has opened is a hope, not a backup.
`GET .../bundle` is the plain bundle. `GET .../bundle?encrypted=1` is the file as stored (`.bundle.vault`), for keeping a copy somewhere else.

## Recovering without this server

`npm run vault -- decrypt <file.bundle.vault> <out.bundle>` with the key in the environment, then `git clone <out.bundle>`. Or write your own: the format is below and a test (`tests/vault.test.ts`) decrypts with a reader written only from this page.

## The file format, "vault-v1"

All numbers big-endian. AES-256-GCM everywhere, 16-byte tags.

```
header, 78 bytes
   0   8   "CCVAULT1"
   8   1   version = 1
   9   1   chunk size as a power of two (12 to 24; 20 = 1 MiB)
  10   8   key id: the first 8 bytes of SHA-256(vault key)
  18  12   IV for the key wrap
  30  32   the file's data key, encrypted with the vault key (AES-256-GCM, IV above, AAD = header bytes 0..17)
  62  16   the wrap's tag
body: chunks, each  ciphertext (up to 2^n bytes) || tag (16)
```

- Every file has its own random 32-byte **data key**. The vault key only ever wraps data keys.
- The plaintext is cut into chunks of 2^n bytes; every chunk but the last is exactly that long. The last chunk is whatever is left, from 0 to 2^n bytes (an empty file is one empty chunk, 16 bytes).
- Chunk *i* (counting from 0) is encrypted with the data key, nonce = `uint64 i` (8 bytes) `|| final flag` (1 byte: 1 for the last chunk, 0 otherwise) `|| 3 zero bytes`, AAD = header bytes 0..9 (magic, version, chunk size).
- To decrypt: unwrap the data key; the chunk with nothing after it is the last one (its flag is 1). A file cut short, added to, or with chunks repeated, dropped or reordered fails a tag. Hand on a chunk only after its tag has verified.
- Key derivation (when no `VAULT_ENCRYPTION_KEY` is set): `HKDF-SHA256(ikm = MFA_ENCRYPTION_KEY bytes, salt = empty, info = "custody-core/vault/v1", length = 32)`.
- A plain git bundle starts `# v2 git bundle`, so locked and legacy files are told apart by their first bytes.

## What this does not do

It protects backups **at rest**. Anyone who has the server's running environment has the key; anyone who has the owner's login can download the plain bundle (that is what the download is for). It does not hide that a backup exists, its size, or its name. It protects the stored bundles only, not the database, the gateway's working copies (which are deleted when a session or door ends), or the project's record (which is meant to be readable and verifiable).
The key never reaches the database, the browser, the logs or the health check. Backups on storage you own yourself (your own bucket or Drive) are still not connected.
