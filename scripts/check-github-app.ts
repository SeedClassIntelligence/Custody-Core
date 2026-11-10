import dotenv from 'dotenv';
dotenv.config();

import { checkGitHubApp } from '../server/githubAppCheck';

/**
 * Is the GitHub App still in place? `npm run github-app:check` (run where the server's GITHUB_APP_* settings are: your computer with a .env, or the host's shell).
 * Asks GitHub as the App itself and prints PASS / WARN / FAIL lines. Exit status 1 if anything FAILs. It never prints a secret.
 */
const mark = { pass: 'PASS', warn: 'WARN', fail: 'FAIL' } as const;
const findings = await checkGitHubApp();
for (const f of findings) {
  console.log(`[${mark[f.level]}] ${f.what}`);
  if (f.detail) console.log(`       ${f.detail}`);
}
const fails = findings.filter((f) => f.level === 'fail').length;
const warns = findings.filter((f) => f.level === 'warn').length;
console.log(fails ? `\n${fails} problem${fails === 1 ? '' : 's'} to fix.` : `\nThe App is in place.${warns ? ` ${warns} thing${warns === 1 ? '' : 's'} to look at (WARN).` : ''}`);
process.exit(fails ? 1 : 0);
