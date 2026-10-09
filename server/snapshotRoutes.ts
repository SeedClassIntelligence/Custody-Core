import fs from 'node:fs';
import express from 'express';
import { getDbPool } from './db';
import { creatorOf } from './auth';
import { snapshotFile } from './snapshots';

/** /api/v1/projects/:id/snapshots (after login): the project's backup snapshots, and each bundle's download. */
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
      `SELECT s.storage_uri, s.sha256, r.full_name, s.created_at FROM mirror_snapshot s JOIN repository r ON r.id = s.repository_id
         JOIN project p ON p.id = r.project_id WHERE s.id = $1 AND p.id = $2 AND p.creator_id = $3`,
      [req.params.snapshotId, projectId(req), creatorOf(res).id]
    )).rows[0];
    if (!row) return res.status(404).json({ error: 'Snapshot not found.' });
    const file = snapshotFile(row.storage_uri);
    if (!file) return res.status(410).json({ error: 'The snapshot file is no longer in the backup directory.' });
    const name = `${row.full_name.replace('/', '__')}-${new Date(row.created_at).toISOString().slice(0, 10)}.bundle`;
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Disposition', `attachment; filename="${name}"`);
    // The recorded SHA-256, so the download can be checked against the event record.
    res.setHeader('X-Snapshot-SHA256', row.sha256);
    fs.createReadStream(file).pipe(res);
  } catch (err: any) {
    console.error('[snapshots] download:', err?.message ?? err);
    res.status(500).json({ error: 'Something went wrong on the server.' });
  }
});
