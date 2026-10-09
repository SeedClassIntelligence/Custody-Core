import dotenv from 'dotenv';
dotenv.config();

import { runMigrations, getAdminPool, appDatabaseConfigProblem } from './db';

async function runCliMigrations() {
  // Same rule as the server: the app account's password must be given, so it can be set here.
  const problem = appDatabaseConfigProblem();
  if (problem) {
    console.error('[Migration Error]', problem);
    process.exitCode = 1;
    return;
  }
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
