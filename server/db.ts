import pg from 'pg';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import dotenv from 'dotenv';
dotenv.config({ override: true });

import { computeEventHash, GENESIS_PREV_HASH, verifyHashChain, VerificationResult } from '../shared/crypto';

const { Pool } = pg;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

let appPool: pg.Pool | null = null;
let adminPool: pg.Pool | null = null;
let isMigrated = false;

export function getResolvedDatabaseUrl(): string | null {
  const host = process.env.PGHOST || process.env.DB_HOST;
  const user = process.env.PGUSER || process.env.DB_USER || 'postgres';
  const password = process.env.PGPASSWORD || process.env.DB_PASSWORD || process.env.SUPABASE_DB_PASSWORD;
  const database = process.env.PGDATABASE || process.env.DB_NAME || 'postgres';
  const port = process.env.PGPORT || process.env.DB_PORT || '5432';

  let databaseUrl = process.env.DATABASE_URL;

  // Handle bracketed password in URL e.g. postgresql://user:[pass]@host...
  if (databaseUrl) {
    const bracketMatch = databaseUrl.match(/^(postgresql:\/\/[^:]+:)(?:\[([^\]]+)\])(@.+)$/);
    if (bracketMatch) {
      const rawPw = bracketMatch[2];
      if (rawPw !== 'YOUR-PASSWORD') {
        databaseUrl = `${bracketMatch[1]}${encodeURIComponent(rawPw)}${bracketMatch[3]}`;
      }
    }
  }

  // If databaseUrl has [YOUR-PASSWORD] and password is provided separately
  if (databaseUrl && databaseUrl.includes('[YOUR-PASSWORD]') && password) {
    databaseUrl = databaseUrl.replace('[YOUR-PASSWORD]', encodeURIComponent(password));
  }

  // If databaseUrl is missing but host and password are provided
  if ((!databaseUrl || databaseUrl.includes('[YOUR-PASSWORD]')) && host && password) {
    databaseUrl = `postgresql://${encodeURIComponent(user)}:${encodeURIComponent(password)}@${host}:${port}/${database}`;
  }

  if (!databaseUrl || databaseUrl.includes('[YOUR-PASSWORD]') || databaseUrl === 'MY_DATABASE_URL') {
    return null;
  }

  return databaseUrl;
}

export function getAdminDatabaseUrl(): string | null {
  return process.env.ADMIN_DATABASE_URL || getResolvedDatabaseUrl();
}

export function getAppDatabaseUrl(): string | null {
  if (process.env.APP_DATABASE_URL) {
    return process.env.APP_DATABASE_URL;
  }
  const baseResolved = getResolvedDatabaseUrl();
  if (!baseResolved) return null;

  // The application must connect as the restricted custody_app role, never as postgres superuser
  try {
    const parsed = new URL(baseResolved);
    if (parsed.username === 'postgres') {
      parsed.username = 'custody_app';
      parsed.password = process.env.APP_DB_PASSWORD || 'CustodyAppPass702!';
      return parsed.toString();
    }
    return parsed.toString();
  } catch {
    return baseResolved;
  }
}

export function getDbPool(): pg.Pool | null {
  const databaseUrl = getAppDatabaseUrl();
  if (!databaseUrl) {
    return null;
  }
  if (!appPool) {
    appPool = new Pool({
      connectionString: databaseUrl,
      ssl: databaseUrl.includes('localhost') ? false : { rejectUnauthorized: false }
    });
  }
  return appPool;
}

export function getAdminPool(): pg.Pool | null {
  const adminUrl = getAdminDatabaseUrl();
  if (!adminUrl) return null;
  if (!adminPool) {
    adminPool = new Pool({
      connectionString: adminUrl,
      ssl: adminUrl.includes('localhost') ? false : { rejectUnauthorized: false }
    });
  }
  return adminPool;
}

export async function runMigrations(): Promise<{ success: boolean; message: string }> {
  const adminDb = getAdminPool();
  if (!adminDb) {
    return {
      success: false,
      message: 'DATABASE_URL is not configured in the environment.'
    };
  }

  if (isMigrated) {
    return { success: true, message: 'Migrations already applied.' };
  }

  const migrationFile = path.join(__dirname, 'migrations', '001_initial_schema.sql');
  const sql = fs.readFileSync(migrationFile, 'utf8');

  const client = await adminDb.connect();
  try {
    await client.query('BEGIN');
    await client.query(sql);
    await client.query('COMMIT');

    const rolesFile = path.join(__dirname, 'roles.sql');
    if (fs.existsSync(rolesFile)) {
      const rolesSql = fs.readFileSync(rolesFile, 'utf8');
      try {
        await client.query(rolesSql);
      } catch (roleErr: any) {
        console.warn('[DB Roles Notice]', roleErr.message);
      }
    }

    isMigrated = true;
    return { success: true, message: 'PostgreSQL schema initialized with append-only event trigger and custody_app role.' };
  } catch (err: any) {
    await client.query('ROLLBACK');
    return { success: false, message: `Migration failed: ${err.message}` };
  } finally {
    client.release();
  }
}

export interface InsertEventParams {
  project_id: string;
  actor_type: 'creator' | 'developer' | 'system' | 'gateway';
  actor_id: string;
  action: string;
  subject_type: string;
  subject_id: string;
  payload: Record<string, any>;
  timestamp?: string;
}

export interface DbEventRow {
  id: string;
  seq: number;
  project_id: string;
  actor_type: string;
  actor_id: string;
  action: string;
  subject_type: string;
  subject_id: string;
  payload: Record<string, any>;
  prev_hash: string;
  hash: string;
  seed_signature_id: string;
  hashed_timestamp: string;
  created_at: string;
  updated_at: string;
}

/**
 * Inserts an event into the append-only event log.
 * Sequence and previous hash are assigned inside a database transaction
 * so two concurrent events for the same project cannot receive the same seq or branch.
 */
export async function insertEvent(params: InsertEventParams): Promise<DbEventRow> {
  const db = getDbPool();
  if (!db) {
    throw new Error('Database is not connected. Set DATABASE_URL to record events.');
  }

  const client = await db.connect();
  try {
    await client.query('BEGIN');

    // Lock the project row or latest event to prevent race conditions on sequence
    // First, lock project row if available
    await client.query(
      `SELECT id FROM project WHERE id = $1 FOR UPDATE`,
      [params.project_id]
    );

    // Get the latest event for this project
    const lastEventRes = await client.query(
      `SELECT seq, hash FROM event WHERE project_id = $1 ORDER BY seq DESC LIMIT 1`,
      [params.project_id]
    );

    let nextSeq = 1;
    let prevHash = GENESIS_PREV_HASH;

    if (lastEventRes.rows.length > 0) {
      nextSeq = Number(lastEventRes.rows[0].seq) + 1;
      prevHash = lastEventRes.rows[0].hash;
    }

    const timestamp = params.timestamp || new Date().toISOString();

    const hash = await computeEventHash({
      seq: nextSeq,
      project_id: params.project_id,
      actor_type: params.actor_type,
      actor_id: params.actor_id,
      action: params.action,
      subject_type: params.subject_type,
      subject_id: params.subject_id,
      payload: params.payload,
      prev_hash: prevHash,
      timestamp
    });

    const insertRes = await client.query(
      `INSERT INTO event (
        seq, project_id, actor_type, actor_id, action, subject_type, subject_id,
        payload, prev_hash, hash, seed_signature_id, hashed_timestamp, created_at, updated_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
      RETURNING *`,
      [
        nextSeq,
        params.project_id,
        params.actor_type,
        params.actor_id,
        params.action,
        params.subject_type,
        params.subject_id,
        JSON.stringify(params.payload),
        prevHash,
        hash,
        '', // Empty in Phase 1, ready for Phase 2 Seed Signature
        timestamp, // Exact ISO string preserved for verification
        timestamp,
        timestamp
      ]
    );

    await client.query('COMMIT');
    const row = insertRes.rows[0];
    return {
      ...row,
      seq: Number(row.seq)
    };
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

export async function getProjectEvents(projectId: string): Promise<DbEventRow[]> {
  const db = getDbPool();
  if (!db) {
    return [];
  }

  const res = await db.query(
    `SELECT * FROM event WHERE project_id = $1 ORDER BY seq ASC`,
    [projectId]
  );

  return res.rows.map(r => ({
    ...r,
    seq: Number(r.seq)
  }));
}

export async function verifyServerProjectEvents(projectId: string): Promise<VerificationResult> {
  const events = await getProjectEvents(projectId);
  return await verifyHashChain(
    events.map(e => ({
      seq: e.seq,
      project_id: e.project_id,
      actor_type: e.actor_type,
      actor_id: e.actor_id,
      action: e.action,
      subject_type: e.subject_type,
      subject_id: e.subject_id,
      payload: typeof e.payload === 'string' ? JSON.parse(e.payload) : e.payload,
      prev_hash: e.prev_hash,
      hash: e.hash,
      timestamp: e.hashed_timestamp || (typeof e.created_at === 'string' ? e.created_at : new Date(e.created_at).toISOString()),
      seed_signature_id: e.seed_signature_id
    }))
  );
}
