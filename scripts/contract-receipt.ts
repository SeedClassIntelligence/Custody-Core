import { spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * Runs the contract test (tests/attestation_submission.test.ts) against a throwaway database and writes
 *   docs/contracts/commit-attribution-submission.v1.receipt.json   what ran, what passed, and the hashes of what it ran against
 *   docs/contracts/commit-attribution-submission.v1.examples.json the real request and answers of that run
 * Nothing is written unless every test passed. `npm run contract:receipt`.
 */
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const sha = (f: string) => crypto.createHash('sha256').update(fs.readFileSync(path.join(root, f))).digest('hex');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'contract-'));
const report = path.join(tmp, 'report.json');
const examples = path.join(tmp, 'examples.json');

const run = spawnSync('npx', ['vitest', 'run', 'tests/attestation_submission.test.ts', '--reporter=json', `--outputFile=${report}`], {
  cwd: root, env: { ...process.env, CONTRACT_EXAMPLES_OUT: examples }, stdio: ['ignore', 'inherit', 'inherit']
});
if (run.status !== 0 || !fs.existsSync(report) || !fs.existsSync(examples)) {
  console.error('The contract tests did not pass; nothing was written.');
  process.exit(1);
}
const r = JSON.parse(fs.readFileSync(report, 'utf8'));
const tests = r.testResults.flatMap((f: any) => f.assertionResults.map((t: any) => ({ name: t.fullName.replace(/^Machine submission of commit attributions /, ''), status: t.status })));
if (r.numFailedTests !== 0 || tests.some((t: any) => t.status !== 'passed')) {
  console.error('Some contract tests did not pass; nothing was written.');
  process.exit(1);
}
const git = (...a: string[]) => spawnSync('git', a, { cwd: root, encoding: 'utf8' }).stdout.trim();
const dir = path.join(root, 'docs', 'contracts');
fs.mkdirSync(dir, { recursive: true });
fs.writeFileSync(path.join(dir, 'commit-attribution-submission.v1.examples.json'), fs.readFileSync(examples, 'utf8') + '\n');
fs.writeFileSync(
  path.join(dir, 'commit-attribution-submission.v1.receipt.json'),
  JSON.stringify(
    {
      contract: 'commit-attribution-submission',
      version: '1',
      result: 'passed',
      tests_passed: tests.length,
      tests,
      ran_at: new Date().toISOString(),
      base_commit: git('rev-parse', 'HEAD'),
      sha256: {
        'tests/attestation_submission.test.ts': sha('tests/attestation_submission.test.ts'),
        'server/attestation.ts': sha('server/attestation.ts'),
        'server/migrations/020_attestation_submission.sql': sha('server/migrations/020_attestation_submission.sql'),
        'docs/openapi.json': sha('docs/openapi.json')
      },
      note: 'Run against a disposable database with disposable signing keys and repositories. The hashes identify the files that were tested; re-run with `npm run contract:receipt` to reproduce.'
    },
    null,
    2
  ) + '\n'
);
console.log(`contract receipt written: ${tests.length} tests passed`);
