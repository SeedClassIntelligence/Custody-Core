import dotenv from 'dotenv';
dotenv.config({ override: true });

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import pg from 'pg';
import { getResolvedDatabaseUrl } from './db';

const { Pool } = pg;
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function runCliMigrations() {
  const dbUrl = getResolvedDatabaseUrl() || process.env.DATABASE_URL;
  if (!dbUrl) {
    console.error('[Migration Error] No DATABASE_URL configured.');
    process.exit(1);
  }

  console.log('[Migration] Connecting to database...');
  const pool = new Pool({
    connectionString: dbUrl,
    ssl: dbUrl.includes('localhost') ? false : { rejectUnauthorized: false }
  });

  const client = await pool.connect();
  try {
    console.log('[Migration] Applying 001_initial_schema.sql...');
    const schemaSql = fs.readFileSync(path.join(__dirname, 'migrations', '001_initial_schema.sql'), 'utf8');
    await client.query(schemaSql);
    console.log('[Migration] Schema and triggers applied successfully.');

    console.log('[Migration] Applying roles and permissions from roles.sql...');
    const rolesSql = fs.readFileSync(path.join(__dirname, 'roles.sql'), 'utf8');
    try {
      await client.query(rolesSql);
      console.log('[Migration] Roles and permissions configured.');
    } catch (roleErr: any) {
      console.warn('[Migration Role Notice]', roleErr.message);
    }

    console.log('[Migration] All migrations complete.');
  } finally {
    client.release();
    await pool.end();
  }
}

runCliMigrations().catch(err => {
  console.error('[Migration Fatal]', err);
  process.exit(1);
});
