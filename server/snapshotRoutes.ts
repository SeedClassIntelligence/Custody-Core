import fs from 'node:fs';
import express from 'express';
import { Readable } from 'node:stream';
import crypto from 'node:crypto';
import { getDbPool, insertEvent } from './db';
import { creatorOf } from './auth';
import { checkSnapshot, openSnapshotStream, snapshotFile } from './snapshots';
import { VaultError } from './vault';

/**
 * /api/v1/projects/:id/snapshots (after login): the project's backup snapshots, each bundle's download (decrypted on the way out, so it restores with plain git;
 * `?encrypted=1` gives the file as it is stored, locked, for keeping elsewhere), and a check that a stored snapshot still opens and is the recorded bundle.
 */
export const snapshotsRouter = express.Router({ mergeParams: true });

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const projectId = (req: express.Request) => (req.params as Record<string, string>).id;

snapshotsRouter.get('/', async (req, res) => {
  const db = getDbPool();
  if (!db) return res.status(503).json({ error: 'Database not connected.' });
  if (!UUID.test(projectId(req))) return res.status(404).json({ error: 'Project not found.' });
  try {
    const rows = (await db.query(
      `SELECT s.id, s.door_id, s.trigger, s.refs, s.sha256, s.size_bytes, s.created_at, r.full_name
         FROM mirror_snapshot s JOIN repository r ON r.id = s.repository_id JOIN project p ON p.id = r.project_id
        WHERE p.id = $1 AND p.creator_id = $2 ORDER BY s.created_at DESC`,
      [projectId(req), creatorOf(res).id]
    )).rows;
    res.json({ snapshots: rows.map((r) => ({ ...r, size_bytes: Number(r.size_bytes) })) });
  } catch (err: any) {
    console.error('[snapshots] list:', err?.message ?? err);
    res.status(500).json({ error: 'Something went wrong on the server.' });
  }
});

snapshotsRouter.get('/:snapshotId/bundle', async (req, res) => {
  const db = getDbPool();
  if (!db) return res.status(503).json({ error: 'Database not connected.' });
  if (!UUID.test(projectId(req)) || !UUID.test(req.params.snapshotId)) return res.status(404).json({ error: 'Snapshot not found.' });
  try {
    const row = (await db.query(
      `SELECT s.storage_uri, s.sha256, s.size_bytes, r.full_name, s.created_at FROM mirror_snapshot s JOIN repository r ON r.id = s.repository_id
         JOIN project p ON p.id = r.project_id WHERE s.id = $1 AND p.id = $2 AND p.creator_id = $3`,
      [req.params.snapshotId, projectId(req), creatorOf(res).id]
    )).rows[0];
    if (!row) return res.status(404).json({ error: 'Snapshot not found.' });
    const file = snapshotFile(row.storage_uri);
    if (!file) return res.status(410).json({ error: 'The snapshot file is no longer in the backup directory.' });
    const base = `${row.full_name.replace('/', '__')}-${new Date(row.created_at).toISOString().slice(0, 10)}`;
    // The recorded SHA-256 is that of the bundle (not of the locked file), so the download can be checked against the event record.
    res.setHeader('X-Snapshot-SHA256', row.sha256);
    res.setHeader('Content-Type', 'application/octet-stream');
    if (req.query.encrypted === '1') {
      res.setHeader('Content-Disposition', `attachment; filename="${base}.bundle.vault"`);
      res.setHeader('X-Snapshot-Encryption', 'vault-v1');
      return void fs.createReadStream(file).pipe(res);
    }
    let opened: Awaited<ReturnType<typeof openSnapshotStream>>;
    try {
      opened = await openSnapshotStream(file);
    } catch (err) {
      if (err instanceof VaultError) return res.status(503).json({ error: `The snapshot cannot be opened: ${err.message}`, code: `vault_${err.code}` });
      throw err;
    }
    res.setHeader('Content-Disposition', `attachment; filename="${base}.bundle"`);
    const hash = crypto.createHash('sha256');
    let bytes = 0;
    async function* checked() {
      for await (const chunk of opened.stream) {
        hash.update(chunk);
        bytes += chunk.length;
        yield chunk;
      }
      // Every part authenticated on its way out; and the whole must be the bundle that was recorded, or the download is cut off rather than ended.
      if (hash.digest('hex') !== row.sha256 || bytes !== Number(row.size_bytes)) throw new Error('the snapshot is not the recorded bundle');
    }
    Readable.from(checked(), { objectMode: false }).on('error', (e) => {
      console.error('[snapshots] download stopped:', e?.message ?? e);
      res.destroy(e);
    }).pipe(res);
  } catch (err: any) {
    console.error('[snapshots] download:', err?.message ?? err);
    if (!res.headersSent) res.status(500).json({ error: 'Something went wrong on the server.' });
  }
});

/** Opens the stored snapshot completely (decrypting and authenticating every part) and compares it with the record. Writes the result to the project's record. */
snapshotsRouter.post('/:snapshotId/verify', async (req, res) => {
  const db = getDbPool();
  if (!db) return res.status(503).json({ error: 'Database not connected.' });
  if (!UUID.test(projectId(req)) || !UUID.test(req.params.snapshotId)) return res.status(404).json({ error: 'Snapshot not found.' });
  try {
    const row = (await db.query(
      `SELECT s.id, s.storage_uri, s.sha256, s.size_bytes FROM mirror_snapshot s JOIN repository r ON r.id = s.repository_id JOIN project p ON p.id = r.project_id
        WHERE s.id = $1 AND p.id = $2 AND p.creator_id = $3`,
      [req.params.snapshotId, projectId(req), creatorOf(res).id]
    )).rows[0];
    if (!row) return res.status(404).json({ error: 'Snapshot not found.' });
    const result = await checkSnapshot(row);
    await insertEvent({
      project_id: projectId(req), actor_type: 'creator', actor_id: creatorOf(res).id, action: result.ok ? 'mirror.verified' : 'mirror.corrupt', subject_type: 'snapshot', subject_id: row.id,
      payload: result.ok ? { snapshot_id: row.id, sha256: row.sha256, encrypted: result.encrypted } : { snapshot_id: row.id, sha256: row.sha256, problem: result.problem }
    });
    res.status(result.ok ? 200 : 409).json(result.ok ? { ok: true, encrypted: result.encrypted, bytes: result.bytes } : { ok: false, problem: result.problem, error: result.detail });
  } catch (err: any) {
    console.error('[snapshots] verify:', err?.message ?? err);
    res.status(500).json({ error: 'Something went wrong on the server.' });
  }
});
