import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { PathRules } from '../server/pathRules';
import { buildView, verifyBaseCommit } from '../server/viewBuilder';

/**
 * How long a session's filtered view takes to build on a large repository (docs/integration/PHASE5_DESIGN.md, 8).
 *   npm run bench:view [-- <number of files>]        default 20000, the design's limit
 *   BENCH_ALL=1 npm run bench:view                   a session allowed to read every file (the most expensive case)
 * Builds a synthetic repository with plain git (about a fifth of it in a directory the session may not read), then builds
 * the view and reports the time of each step and the size. Nothing leaves a temporary directory.
 */
const total = Number(process.argv[2] ?? 20_000);
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'custody-bench-'));
const env = { PATH: process.env.PATH ?? '', HOME: tmp, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null' };
const ms = (t: number) => `${((Date.now() - t) / 1000).toFixed(2)} s`;

try {
  const repo = path.join(tmp, 'real.git');
  spawnSync('git', ['init', '-q', '--bare', repo], { env });
  let t = Date.now();
  const lines: string[] = ['commit refs/heads/main', 'committer Bench <bench@example.com> 1700000000 +0000', 'data 5', 'bulk'];
  for (let i = 0; i < total; i++) {
    const dir = i % 5 === 0 ? 'private' : i % 5 === 1 ? 'docs' : `src/module${i % 211}/part${i % 17}`;
    const body = `file ${i}\n${'x'.repeat(i % 1500)}\n`;
    lines.push(`M 100644 inline ${dir}/file${i}.txt`, `data ${Buffer.byteLength(body)}`, body.replace(/\n$/, ''));
  }
  const imp = spawnSync('git', ['--git-dir', repo, 'fast-import', '--quiet'], { env, input: lines.join('\n') + '\n', maxBuffer: 1 << 28 });
  if (imp.status !== 0) throw new Error(`fast-import failed: ${imp.stderr}`);
  const base = spawnSync('git', ['--git-dir', repo, 'rev-parse', 'main'], { env, encoding: 'utf8' }).stdout.trim();
  console.log(`built a repository of ${total} files in ${ms(t)}`);

  t = Date.now();
  const check = await verifyBaseCommit(repo, base, 'refs/heads/main');
  console.log(`verified the base commit (${check.ok ? 'on the default branch' : 'NOT OK'}) in ${ms(t)}`);

  // BENCH_ALL=1: the most expensive case, a session allowed to read every file (the design's file limit)
  const everything = process.env.BENCH_ALL === '1';
  const rules = new PathRules(everything ? { allowedRead: ['**'], allowedWrite: [], prohibited: [] } : { allowedRead: ['src/**', 'docs/**'], allowedWrite: [], prohibited: ['**/file1*.txt'] });
  t = Date.now();
  const result = await buildView({ mirrorDir: repo, baseCommit: base, rules, outDir: path.join(tmp, 'view.git'), limits: { maxFiles: Math.max(total, 1), maxBytes: 2 ** 40 } });
  console.log(`built the view in ${ms(t)}: ${result.fileCount} files, ${(result.totalBytes / (1024 * 1024)).toFixed(1)} MiB of content, ${result.excludedCount} left out`);
  const du = spawnSync('du', ['-sk', path.join(tmp, 'view.git')], { encoding: 'utf8' }).stdout.split('\t')[0];
  console.log(`the view repository takes ${(Number(du) / 1024).toFixed(1)} MiB on disk`);

  t = Date.now();
  const again = await buildView({ mirrorDir: repo, baseCommit: base, rules, outDir: path.join(tmp, 'view2.git'), limits: { maxFiles: Math.max(total, 1), maxBytes: 2 ** 40 } });
  console.log(`rebuilt it in ${ms(t)}; identical commit: ${again.viewCommit === result.viewCommit}`);
} finally {
  fs.rmSync(tmp, { recursive: true, force: true });
}
