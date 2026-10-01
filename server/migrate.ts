import dotenv from 'dotenv';
dotenv.config();

import { runMigrations, getAdminPool } from './db';

async function runCliMigrations() {
  console.log('[Migration] Applying versioned migrations...');
  const res = await runMigrations();
  if (!res.success) {
    console.error('[Migration Error]', res.message);
    process.exitCode = 1;
  } else {
    console.log('[Migration]', res.message);
  }
  await getAdminPool()?.end();
}

runCliMigrations().catch(err => {
  console.error('[Migration Fatal]', err);
  process.exit(1);
});
