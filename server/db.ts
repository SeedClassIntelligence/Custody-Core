import pg from 'pg';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import dotenv from 'dotenv';
dotenv.config();

import { applyMigrations } from './migrationRunner';
import { verifyHashChain, VerificationResult } from '../shared/crypto';

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

  // Closes Supabase's built-in REST API to our tables and functions (see the file). Runs inside every
  // migration, and again after the roles below.
  const lockdown = fs.readFileSync(path.join(__dirname, 'lockdown.sql'), 'utf8');
  try {
    await applyMigrations(adminDb, path.join(__dirname, 'migrations'), lockdown);
  } catch (err: any) {
    return { success: false, message: err.message };
  }

  const rolesFile = path.join(__dirname, 'roles.sql');
  if (fs.existsSync(rolesFile)) {
    const client = await adminDb.connect();
    try {
      await client.query(fs.readFileSync(rolesFile, 'utf8'));
      await client.query(lockdown);
    } catch (roleErr: any) {
      return { success: false, message: `Migrations applied, but configuring the custody_app role failed: ${roleErr.message}` };
    } finally {
      client.release();
    }
  }

  isMigrated = true;
  return { success: true, message: 'PostgreSQL schema is up to date (versioned migrations applied, custody_app role configured).' };
}

export interface InsertEventParams {
  project_id: string;
  actor_type: 'creator' | 'developer' | 'system' | 'gateway';
  actor_id: string;
  action: string;
  subject_type: string;
  subject_id: string;
  payload: Record<string, any>;
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
  hash_version: number;
  canonical_payload: string | null;
  created_at: string;
  updated_at: string;
}

/**
 * Records an event. The database assigns the sequence number, previous hash, timestamp and hash
 * (the append_event() function); this code can only say what happened.
 */
export async function insertEvent(params: InsertEventParams, client?: pg.PoolClient): Promise<DbEventRow> {
  // Pass `client` to record the event inside a transaction the caller controls.
  const runner = client ?? getDbPool();
  if (!runner) {
    throw new Error('Database is not connected. Set DATABASE_URL to record events.');
  }

  const res = await runner.query(
    'SELECT * FROM append_event($1, $2, $3, $4, $5, $6, $7::jsonb)',
    [
      params.project_id,
      params.actor_type,
      params.actor_id,
      params.action,
      params.subject_type,
      params.subject_id,
      JSON.stringify(params.payload)
    ]
  );
  const row = res.rows[0];
  return { ...row, seq: Number(row.seq) };
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
      seed_signature_id: e.seed_signature_id,
      hash_version: e.hash_version,
      canonical_payload: e.canonical_payload
    }))
  );
}
