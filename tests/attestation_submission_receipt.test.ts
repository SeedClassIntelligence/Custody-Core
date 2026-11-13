import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

/** The published receipt must describe the code in this repository: change the contract's code or tests and `npm run contract:receipt` has to be run again. */
describe('Published contract receipt (commit-attribution-submission v1)', () => {
  const root = path.resolve(__dirname, '..');
  const receipt = JSON.parse(fs.readFileSync(path.join(root, 'docs/contracts/commit-attribution-submission.v1.receipt.json'), 'utf8'));
  it('records a full pass', () => {
    expect(receipt).toMatchObject({ contract: 'commit-attribution-submission', version: '1', result: 'passed' });
    expect(receipt.tests_passed).toBe(receipt.tests.length);
    expect(receipt.tests.every((t: any) => t.status === 'passed')).toBe(true);
  });
  it('was produced against the files that are here now', () => {
    for (const f of ['tests/attestation_submission.test.ts', 'server/attestation.ts', 'server/migrations/020_attestation_submission.sql']) {
      expect(receipt.sha256[f], f).toBe(crypto.createHash('sha256').update(fs.readFileSync(path.join(root, f))).digest('hex'));
    }
  });
  it('is the contract the server advertises', async () => {
    const { openApiDocument } = await import('../server/openapi');
    expect((openApiDocument as any).info['x-custody-contracts'][receipt.contract].version).toBe(receipt.version);
  });
});
