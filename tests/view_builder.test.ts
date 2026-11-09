import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { PathRules } from '../server/pathRules';
import { ViewBuildError, buildView, listAllObjects, verifyBaseCommit, viewLimits } from '../server/viewBuilder';

/**
 * The filtered view (Phase 5b, docs/integration/PHASE5_DESIGN.md 3 and 4.4), against real git repositories built in
 * temporary directories. The point of the whole phase is tested directly here: a session's view holds exactly what it may
 * read, none of the history, none of the excluded objects, and building it twice gives the identical commit.
 */
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'custody-view-test-'));
const ENV = {
  PATH: process.env.PATH ?? '',
  HOME: tmp,
  GIT_CONFIG_NOSYSTEM: '1',
  GIT_CONFIG_GLOBAL: '/dev/null',
  GIT_TERMINAL_PROMPT: '0',
  GIT_AUTHOR_NAME: 'Alice',
  GIT_AUTHOR_EMAIL: 'alice@example.com',
  GIT_AUTHOR_DATE: '2026-01-01T00:00:00Z',
  GIT_COMMITTER_NAME: 'Alice',
  GIT_COMMITTER_EMAIL: 'alice@example.com',
  GIT_COMMITTER_DATE: '2026-01-01T00:00:00Z'
};
function git(cwd: string, args: string[], input?: string | Buffer) {
  const r = spawnSync('git', args, { cwd, env: ENV, input, timeout: 120_000 });
  if (r.status !== 0) throw new Error(`git ${args.join(' ')} failed: ${r.stderr.toString()}`);
  return r.stdout.toString('utf8').trim();
}
const gitDirOf = (dir: string, args: string[], input?: string | Buffer) => git(dir, ['--git-dir', dir, ...args], input);
const write = (root: string, file: string, content: string | Buffer, mode?: number) => {
  const p = path.join(root, file);
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, content, mode ? { mode } : undefined);
  if (mode) fs.chmodSync(p, mode);
};

interface Fixture {
  work: string;
  mirror: string;
  base: string;
  sideCommit: string;
  oldEnvBlob: string;
  migrationBlob: string;
  excludedBlobs: string[];
}
let fx: Fixture;

function makeFixture(): Fixture {
  const work = path.join(tmp, 'work');
  fs.mkdirSync(work, { recursive: true });
  git(work, ['init', '-q', '-b', 'main']);
  write(work, '.env', 'SECRET=old-value-that-was-later-removed\n');
  write(work, 'server/app.ts', 'v1\n');
  write(work, 'server/empty.ts', '');
  write(work, 'server/gateway/router.ts', 'g1\n');
  write(work, 'server/migrations/001.sql', 'create table x();\n');
  write(work, 'shared/util.ts', 's1\n');
  write(work, 'shared/run.sh', '#!/bin/sh\necho hi\n', 0o755);
  write(work, 'shared/café.ts', 'composed\n');
  write(work, 'shared/café.ts', 'decomposed\n');
  write(work, 'shared/.env.sample', 'KEY=example\n');
  write(work, '.github/workflows/ci.yml', 'name: ci\n');
  write(work, 'docs/readme.md', 'docs\n');
  write(work, 'Server/readme.txt', 'capital S\n');
  fs.symlinkSync('../.env', path.join(work, 'shared/link'));
  git(work, ['add', '-A']);
  // a submodule entry (a gitlink) and a path that is not valid UTF-8, which only the index can hold
  git(work, ['update-index', '--add', '--cacheinfo', `160000,${'a'.repeat(40)},shared/sub`]);
  const blob = git(work, ['hash-object', '-w', '--stdin'], 'bad name\n');
  git(work, ['update-index', '-z', '--index-info'], Buffer.concat([Buffer.from(`100644 ${blob}\t`), Buffer.from('shared/bad'), Buffer.from([0xff]), Buffer.from('.ts'), Buffer.from([0])]));
  git(work, ['commit', '-q', '-m', 'first']);
  const oldEnvBlob = git(work, ['rev-parse', 'HEAD:.env']);
  const migrationBlob = git(work, ['rev-parse', 'HEAD:server/migrations/001.sql']);
  // later commits name what they change: "add -A" would also stage the deletion of the two entries that exist only in the index
  git(work, ['rm', '-q', '-f', '.env']);
  write(work, 'docs/more.md', 'more docs\n');
  git(work, ['add', 'docs/more.md']);
  git(work, ['commit', '-q', '-m', 'remove .env (the old value stays in history)']);
  write(work, 'server/app.ts', 'v2\n');
  git(work, ['add', 'server/app.ts']);
  git(work, ['commit', '-q', '-m', 'second']);
  const base = git(work, ['rev-parse', 'HEAD']);
  git(work, ['checkout', '-q', '-b', 'feature']);
  write(work, 'server/feature.ts', 'unreviewed work\n');
  git(work, ['add', 'server/feature.ts']);
  git(work, ['commit', '-q', '-m', 'unreviewed side work']);
  const sideCommit = git(work, ['rev-parse', 'HEAD']);
  git(work, ['checkout', '-q', 'main']);
  const mirror = path.join(tmp, 'mirror.git');
  git(tmp, ['clone', '-q', '--bare', work, mirror]);
  const excludedBlobs = [oldEnvBlob, migrationBlob, git(work, ['rev-parse', `${base}:docs/readme.md`]), git(work, ['rev-parse', `${base}:Server/readme.txt`]), git(work, ['rev-parse', `${base}:shared/.env.sample`])];
  return { work, mirror, base, sideCommit, oldEnvBlob, migrationBlob, excludedBlobs };
}

const RULES = () => new PathRules({ allowedRead: ['server/**', 'shared/**', '.github/**'], allowedWrite: [], prohibited: ['server/migrations/**', '.env*'] });
const EXPECTED_FILES = [
  '.github/workflows/ci.yml',
  'server/app.ts',
  'server/empty.ts',
  'server/gateway/router.ts',
  'shared/café.ts',
  'shared/café.ts',
  'shared/run.sh',
  'shared/util.ts'
].sort();
let n = 0;
const out = () => path.join(tmp, `out-${++n}`, 'view.git');
const filesOf = (viewDir: string) => gitDirOf(viewDir, ['ls-tree', '-r', '--name-only', '-z', 'main']).split('\0').filter(Boolean).sort();

beforeAll(() => {
  fx = makeFixture();
});
afterAll(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

describe('what the view holds', () => {
  it('exactly the files the rules allow to be read, and nothing else', async () => {
    const dir = out();
    const r = await buildView({ mirrorDir: fx.mirror, baseCommit: fx.base, rules: RULES(), outDir: dir });
    expect(filesOf(dir)).toEqual(EXPECTED_FILES);
    expect(r.fileCount).toBe(EXPECTED_FILES.length);
    expect(r.baseCommit).toBe(fx.base);
  });

  it('is built from the content at the BASE commit, not the latest', async () => {
    const dir = out();
    await buildView({ mirrorDir: fx.mirror, baseCommit: fx.base, rules: RULES(), outDir: dir });
    expect(gitDirOf(dir, ['show', 'main:server/app.ts'])).toBe('v2');
    // and the same view built at the first commit shows the first version of the file
    const first = git(fx.work, ['rev-list', '--max-parents=0', 'HEAD']);
    const dirFirst = out();
    await buildView({ mirrorDir: fx.mirror, baseCommit: first, rules: RULES(), outDir: dirFirst });
    expect(gitDirOf(dirFirst, ['show', 'main:server/app.ts'])).toBe('v1');
  });

  it('is one commit with no history, no parents, and a fixed author, committer and date', async () => {
    const dir = out();
    const r = await buildView({ mirrorDir: fx.mirror, baseCommit: fx.base, rules: RULES(), outDir: dir });
    expect(gitDirOf(dir, ['rev-list', '--count', '--all'])).toBe('1');
    expect(gitDirOf(dir, ['rev-parse', 'main'])).toBe(r.viewCommit);
    expect(gitDirOf(dir, ['log', '-1', '--format=%P', 'main'])).toBe(''); // no parent
    expect(gitDirOf(dir, ['log', '-1', '--format=%an <%ae>|%cn <%ce>|%aI|%cI', 'main'])).toBe('Custody Core <gateway@custody.invalid>|Custody Core <gateway@custody.invalid>|2000-01-01T00:00:00+00:00|2000-01-01T00:00:00+00:00');
    expect(gitDirOf(dir, ['log', '-1', '--format=%s', 'main'])).toBe(`Session base: a view of ${fx.base}`);
    expect(gitDirOf(dir, ['symbolic-ref', 'HEAD'])).toBe('refs/heads/main');
  });

  it('keeps the executable bit, empty files, and file names in either Unicode spelling', async () => {
    const dir = out();
    await buildView({ mirrorDir: fx.mirror, baseCommit: fx.base, rules: RULES(), outDir: dir });
    const modes = Object.fromEntries(
      gitDirOf(dir, ['ls-tree', '-r', '-z', 'main']).split('\0').filter(Boolean).map((l) => [l.split('\t')[1], l.split(' ')[0]])
    );
    expect(modes['shared/run.sh']).toBe('100755');
    expect(modes['server/app.ts']).toBe('100644');
    expect(modes['server/empty.ts']).toBe('100644');
    expect(gitDirOf(dir, ['cat-file', '-s', 'main:server/empty.ts'])).toBe('0');
    expect(gitDirOf(dir, ['show', 'main:shared/café.ts'])).toBe('composed');
    expect(gitDirOf(dir, ['show', 'main:shared/café.ts'])).toBe('decomposed');
  });

  it('applies prohibited patterns at any depth, and case-insensitively, when choosing what to include', async () => {
    const dir = out();
    await buildView({ mirrorDir: fx.mirror, baseCommit: fx.base, rules: RULES(), outDir: dir });
    expect(filesOf(dir)).not.toContain('shared/.env.sample'); // ".env*" without a slash: any depth
    const r2 = new PathRules({ allowedRead: ['**'], allowedWrite: [], prohibited: ['SERVER/Migrations/**', 'docs'] });
    const dir2 = out();
    await buildView({ mirrorDir: fx.mirror, baseCommit: fx.base, rules: r2, outDir: dir2 });
    const files = filesOf(dir2);
    expect(files).not.toContain('server/migrations/001.sql'); // a different capital letter is not a way around a prohibition
    expect(files.some((f) => f.startsWith('docs/'))).toBe(false);
    expect(files).toContain('Server/readme.txt');
  });

  it('reads of CI files are allowed when the rules allow them (only writing is restricted)', async () => {
    const dir = out();
    await buildView({ mirrorDir: fx.mirror, baseCommit: fx.base, rules: RULES(), outDir: dir });
    expect(filesOf(dir)).toContain('.github/workflows/ci.yml');
  });
});

describe('what the view must not hold (the leak tests)', () => {
  it('none of the excluded content, by object: the old .env that exists only in history, the migration, the docs, the lookalike directory', async () => {
    const dir = out();
    await buildView({ mirrorDir: fx.mirror, baseCommit: fx.base, rules: RULES(), outDir: dir });
    const { names } = await listAllObjects(dir);
    for (const blob of fx.excludedBlobs) expect(names.has(blob), `blob ${blob} must not be in the view`).toBe(false);
    expect(names.has(fx.sideCommit)).toBe(false); // nothing from another branch
    expect(names.has(fx.base)).toBe(false); // not even the real base commit: the view's commit is its own
    // the strongest form: every object in the real repository that is not part of the view is absent from it
    const mirrorObjects = (await listAllObjects(fx.mirror)).names;
    const inView = new Set(names);
    const allowedBlobs = new Set(EXPECTED_FILES.map((f) => git(fx.work, ['rev-parse', `${fx.base}:${f}`])));
    for (const o of mirrorObjects) {
      const type = git(fx.mirror, ['--git-dir', fx.mirror, 'cat-file', '-t', o].slice(2)) ;
      if (type === 'blob' && !allowedBlobs.has(o)) expect(inView.has(o), `blob ${o}`).toBe(false);
    }
  });

  it('exactly one commit, the trees and files of that commit, no other objects, no other branch, no tags, no alternates', async () => {
    const dir = out();
    const r = await buildView({ mirrorDir: fx.mirror, baseCommit: fx.base, rules: RULES(), outDir: dir });
    const { counts } = await listAllObjects(dir);
    expect(counts.commits).toBe(1);
    expect(counts.other).toBe(0);
    expect(counts.blobs).toBeLessThanOrEqual(EXPECTED_FILES.length); // identical files share one object
    expect(gitDirOf(dir, ['for-each-ref', '--format=%(refname)'])).toBe('refs/heads/main');
    expect(fs.existsSync(path.join(dir, 'objects', 'info', 'alternates'))).toBe(false);
    expect(gitDirOf(dir, ['rev-list', '--objects', '--all']).split('\n').length).toBe(counts.total);
    expect(r.viewCommit).toMatch(/^[0-9a-f]{40}$/);
  });

  it('a clone of the view cannot ask for an excluded object by its id', async () => {
    const dir = out();
    await buildView({ mirrorDir: fx.mirror, baseCommit: fx.base, rules: RULES(), outDir: dir });
    const clone = path.join(tmp, `clone-${n}`);
    git(tmp, ['clone', '-q', dir, clone]);
    for (const blob of [fx.oldEnvBlob, fx.migrationBlob]) {
      expect(() => git(clone, ['cat-file', '-e', blob])).toThrow();
      expect(() => git(clone, ['fetch', '-q', dir, blob])).toThrow();
    }
    // and it checks out exactly the allowed files, with the right contents
    const checkedOut = git(clone, ['ls-files', '-z']).split('\0').filter(Boolean).sort();
    expect(checkedOut).toEqual(EXPECTED_FILES);
    for (const f of EXPECTED_FILES) expect(fs.readFileSync(path.join(clone, f), 'utf8')).toBe(git(fx.work, ['show', `${fx.base}:${f}`]).replace(/$/, f === 'server/empty.ts' ? '' : '\n').replace(/\n\n$/, '\n'));
    expect(git(clone, ['fsck', '--strict', '--no-dangling'])).toBeDefined();
  });

  it('symlinks, submodules and names that are not valid UTF-8 are left out, counted, and never named', async () => {
    const dir = out();
    const r = await buildView({ mirrorDir: fx.mirror, baseCommit: fx.base, rules: RULES(), outDir: dir });
    expect(r.omitted).toEqual({ symlinks: 1, submodules: 1, invalidPaths: 1 });
    const files = filesOf(dir);
    expect(files).not.toContain('shared/link');
    expect(files).not.toContain('shared/sub');
    expect(files.some((f) => f.includes('bad'))).toBe(false);
    // counts only: nothing in the result says what was left out
    const text = JSON.stringify(r);
    for (const name of ['shared/link', 'shared/sub', 'shared/bad', '001.sql', '.env', 'docs/', 'readme', 'Server/', '.env.sample']) expect(text, name).not.toContain(name);
    expect(r.excludedCount).toBeGreaterThanOrEqual(r.omitted.symlinks + r.omitted.submodules + r.omitted.invalidPaths);
  });

  it('the count of excluded entries is exact', async () => {
    const dir = out();
    const r = await buildView({ mirrorDir: fx.mirror, baseCommit: fx.base, rules: RULES(), outDir: dir });
    const total = git(fx.work, ['ls-tree', '-r', '--name-only', '-z', fx.base]).split('\0').filter(Boolean).length;
    expect(r.fileCount + r.excludedCount).toBe(total);
  });
});

describe('determinism', () => {
  it('building twice gives the identical commit and tree; so does building after the view was deleted', async () => {
    const a = out();
    const b = out();
    const r1 = await buildView({ mirrorDir: fx.mirror, baseCommit: fx.base, rules: RULES(), outDir: a });
    const r2 = await buildView({ mirrorDir: fx.mirror, baseCommit: fx.base, rules: RULES(), outDir: b });
    expect(r2.viewCommit).toBe(r1.viewCommit);
    expect(r2.viewTree).toBe(r1.viewTree);
    fs.rmSync(path.dirname(a), { recursive: true, force: true });
    const r3 = await buildView({ mirrorDir: fx.mirror, baseCommit: fx.base, rules: RULES(), outDir: a });
    expect(r3.viewCommit).toBe(r1.viewCommit);
  });

  it('does not depend on the order or spelling of the rules, only on what they allow', async () => {
    const r1 = await buildView({ mirrorDir: fx.mirror, baseCommit: fx.base, rules: RULES(), outDir: out() });
    const r2 = await buildView({
      mirrorDir: fx.mirror,
      baseCommit: fx.base,
      rules: new PathRules({ allowedRead: ['.github/**', 'shared/**', 'server/**', 'server/app.ts'], allowedWrite: ['x/**'], prohibited: ['.ENV*', 'server/migrations/**'] }),
      outDir: out()
    });
    expect(r2.viewCommit).toBe(r1.viewCommit);
  });

  it('a different base commit or a different rule set gives a different view', async () => {
    const r1 = await buildView({ mirrorDir: fx.mirror, baseCommit: fx.base, rules: RULES(), outDir: out() });
    const first = git(fx.work, ['rev-list', '--max-parents=0', 'HEAD']);
    const r2 = await buildView({ mirrorDir: fx.mirror, baseCommit: first, rules: RULES(), outDir: out() });
    const r3 = await buildView({ mirrorDir: fx.mirror, baseCommit: fx.base, rules: new PathRules({ allowedRead: ['server/app.ts'], allowedWrite: [], prohibited: [] }), outDir: out() });
    expect(new Set([r1.viewCommit, r2.viewCommit, r3.viewCommit]).size).toBe(3);
  });

  it('building leaves the real repository unchanged (only unreachable tree and commit objects may be added)', async () => {
    const refsBefore = gitDirOf(fx.mirror, ['for-each-ref', '--format=%(refname) %(objectname)']);
    await buildView({ mirrorDir: fx.mirror, baseCommit: fx.base, rules: RULES(), outDir: out() });
    expect(gitDirOf(fx.mirror, ['for-each-ref', '--format=%(refname) %(objectname)'])).toBe(refsBefore);
    expect(gitDirOf(fx.mirror, ['fsck', '--no-dangling'])).toBeDefined();
  });
});

describe('the view repository itself', () => {
  it('is set up for what comes next: no rewriting, no deleting, strict object checks, no sample hooks, no hidden objects on request', async () => {
    const dir = out();
    await buildView({ mirrorDir: fx.mirror, baseCommit: fx.base, rules: RULES(), outDir: dir });
    const cfg = (k: string) => gitDirOf(dir, ['config', '--get', k]);
    expect(cfg('receive.denyNonFastForwards')).toBe('true');
    expect(cfg('receive.denyDeletes')).toBe('true');
    expect(cfg('receive.fsckObjects')).toBe('true');
    expect(cfg('transfer.fsckObjects')).toBe('true');
    expect(cfg('uploadpack.allowAnySHA1InWant')).toBe('false');
    expect(cfg('uploadpack.allowReachableSHA1InWant')).toBe('false');
    expect(cfg('gc.auto')).toBe('0');
    expect(fs.readdirSync(path.join(dir, 'hooks'))).toEqual([]);
  });

  it('replaces an existing view at the destination, completely', async () => {
    const dir = out();
    await buildView({ mirrorDir: fx.mirror, baseCommit: fx.base, rules: new PathRules({ allowedRead: ['**'], allowedWrite: [], prohibited: [] }), outDir: dir });
    expect(filesOf(dir).length).toBeGreaterThan(EXPECTED_FILES.length);
    fs.writeFileSync(path.join(dir, 'stale-marker'), 'x');
    await buildView({ mirrorDir: fx.mirror, baseCommit: fx.base, rules: RULES(), outDir: dir });
    expect(filesOf(dir)).toEqual(EXPECTED_FILES);
    expect(fs.existsSync(path.join(dir, 'stale-marker'))).toBe(false);
  });

  it('leaves no scratch directories behind, whether the build worked or not', async () => {
    const parent = path.join(tmp, 'clean-parent');
    await buildView({ mirrorDir: fx.mirror, baseCommit: fx.base, rules: RULES(), outDir: path.join(parent, 'view.git') });
    await expect(buildView({ mirrorDir: fx.mirror, baseCommit: fx.base, rules: RULES(), outDir: path.join(parent, 'v2.git'), limits: { maxFiles: 2, maxBytes: 1e9 } })).rejects.toThrow(ViewBuildError);
    expect(fs.readdirSync(parent).sort()).toEqual(['view.git']);
  });
});

describe('limits and refusals', () => {
  const expectCode = async (p: Promise<unknown>, code: string, text?: RegExp) => {
    const err: any = await p.then(() => null, (e) => e);
    expect(err, 'expected a failure').toBeInstanceOf(ViewBuildError);
    expect(err.code).toBe(code);
    if (text) expect(err.message).toMatch(text);
  };

  it('too many files: refused with the limit in the message, and no view is left', async () => {
    const dir = out();
    await expectCode(buildView({ mirrorDir: fx.mirror, baseCommit: fx.base, rules: RULES(), outDir: dir, limits: { maxFiles: 3, maxBytes: 1e9 } }), 'too_many_files', /limit of 3/);
    expect(fs.existsSync(dir)).toBe(false);
  });

  it('exactly at the file limit is accepted; one over is not', async () => {
    const at = await buildView({ mirrorDir: fx.mirror, baseCommit: fx.base, rules: RULES(), outDir: out(), limits: { maxFiles: EXPECTED_FILES.length, maxBytes: 1e9 } });
    expect(at.fileCount).toBe(EXPECTED_FILES.length);
    await expectCode(buildView({ mirrorDir: fx.mirror, baseCommit: fx.base, rules: RULES(), outDir: out(), limits: { maxFiles: EXPECTED_FILES.length - 1, maxBytes: 1e9 } }), 'too_many_files');
  });

  it('too many bytes: refused, with the limit in the message', async () => {
    const dir = out();
    await expectCode(buildView({ mirrorDir: fx.mirror, baseCommit: fx.base, rules: RULES(), outDir: dir, limits: { maxFiles: 1000, maxBytes: 10 } }), 'too_large', /larger than the limit/);
    expect(fs.existsSync(dir)).toBe(false);
  });

  it('nothing to give: when no file matches, refused plainly, not an empty repository', async () => {
    await expectCode(buildView({ mirrorDir: fx.mirror, baseCommit: fx.base, rules: new PathRules({ allowedRead: ['nothing/**'], allowedWrite: [], prohibited: [] }), outDir: out() }), 'no_files', /nothing to give/);
    await expectCode(buildView({ mirrorDir: fx.mirror, baseCommit: fx.base, rules: new PathRules({ allowedRead: ['**'], allowedWrite: [], prohibited: ['**'] }), outDir: out() }), 'no_files');
    await expectCode(buildView({ mirrorDir: fx.mirror, baseCommit: fx.base, rules: new PathRules({ allowedRead: [], allowedWrite: [], prohibited: [] }), outDir: out() }), 'no_files');
  });

  it('a base that is not a commit of this repository: refused', async () => {
    const tree = git(fx.work, ['rev-parse', `${fx.base}^{tree}`]);
    const blob = git(fx.work, ['rev-parse', `${fx.base}:server/app.ts`]);
    for (const bad of ['', 'abc123', 'A'.repeat(40), 'x'.repeat(40), '0'.repeat(40), crypto.randomBytes(20).toString('hex'), tree, blob]) {
      await expectCode(buildView({ mirrorDir: fx.mirror, baseCommit: bad, rules: RULES(), outDir: out() }), 'base_invalid');
    }
  });

  it('reads the limits from the environment, with the defaults of the design, and refuses nonsense', () => {
    expect(viewLimits({})).toEqual({ maxFiles: 20_000, maxBytes: 500 * 1024 * 1024 });
    expect(viewLimits({ SESSION_VIEW_MAX_FILES: '5', SESSION_VIEW_MAX_BYTES: '1000' })).toEqual({ maxFiles: 5, maxBytes: 1000 });
    expect(viewLimits({ SESSION_VIEW_MAX_FILES: '' })).toEqual({ maxFiles: 20_000, maxBytes: 500 * 1024 * 1024 });
    for (const bad of ['0', '-1', 'abc', '1.5', '1e3']) expect(() => viewLimits({ SESSION_VIEW_MAX_FILES: bad }), bad).toThrow(/positive whole number/);
  });
});

describe('the base commit must be on the default branch', () => {
  it('accepts the tip and any earlier commit of the default branch', async () => {
    expect(await verifyBaseCommit(fx.mirror, fx.base)).toEqual({ ok: true });
    const first = git(fx.work, ['rev-list', '--max-parents=0', 'HEAD']);
    expect(await verifyBaseCommit(fx.mirror, first)).toEqual({ ok: true });
    expect(await verifyBaseCommit(fx.mirror, git(fx.work, ['rev-parse', `${fx.base}~1`]))).toEqual({ ok: true });
  });

  it('refuses a commit that exists but only on another branch (unreviewed work)', async () => {
    const r = await verifyBaseCommit(fx.mirror, fx.sideCommit);
    expect(r).toMatchObject({ ok: false, reason: 'not_on_default_branch' });
  });

  it('refuses ids that are malformed, missing, or not commits', async () => {
    expect(await verifyBaseCommit(fx.mirror, 'abc')).toMatchObject({ ok: false, reason: 'malformed' });
    expect(await verifyBaseCommit(fx.mirror, 'A'.repeat(40))).toMatchObject({ ok: false, reason: 'malformed' });
    expect(await verifyBaseCommit(fx.mirror, crypto.randomBytes(20).toString('hex'))).toMatchObject({ ok: false, reason: 'missing' });
    expect(await verifyBaseCommit(fx.mirror, git(fx.work, ['rev-parse', `${fx.base}^{tree}`]))).toMatchObject({ ok: false, reason: 'not_a_commit' });
    expect(await verifyBaseCommit(fx.mirror, git(fx.work, ['rev-parse', `${fx.base}:server/app.ts`]))).toMatchObject({ ok: false, reason: 'not_a_commit' });
  });

  it('says so when there is no default branch to compare with', async () => {
    expect(await verifyBaseCommit(fx.mirror, fx.base, 'refs/heads/does-not-exist')).toMatchObject({ ok: false, reason: 'no_default_branch' });
  });

  it('can be told which branch is the default', async () => {
    expect(await verifyBaseCommit(fx.mirror, fx.sideCommit, 'refs/heads/feature')).toEqual({ ok: true });
    expect(await verifyBaseCommit(fx.mirror, fx.base, 'refs/heads/feature')).toEqual({ ok: true }); // feature was made from main
  });
});

describe('scale', () => {
  it('a view of 5,000 files builds in well under a minute, and is still exact', async () => {
    const big = path.join(tmp, 'big.git');
    git(tmp, ['init', '-q', '--bare', big]);
    const lines: string[] = ['commit refs/heads/main', 'committer A <a@example.com> 1700000000 +0000', 'data 5', 'bulk'];
    for (let i = 0; i < 5000; i++) {
      const dir = i % 5 === 0 ? 'private' : i % 5 === 1 ? 'docs' : `src/d${i % 37}`;
      const body = `file ${i}\n`;
      lines.push(`M 100644 inline ${dir}/f${i}.txt`, `data ${Buffer.byteLength(body)}`, body.trimEnd());
    }
    spawnSync('git', ['--git-dir', big, 'fast-import', '--quiet'], { env: ENV, input: lines.join('\n') + '\n', encoding: 'utf8' });
    const base = gitDirOf(big, ['rev-parse', 'main']);
    const t = Date.now();
    const r = await buildView({ mirrorDir: big, baseCommit: base, rules: new PathRules({ allowedRead: ['src/**', 'docs/**'], allowedWrite: [], prohibited: [] }), outDir: out() });
    expect(Date.now() - t).toBeLessThan(60_000);
    expect(r.fileCount).toBe(4000);
    expect(r.excludedCount).toBe(1000);
    expect(filesOfCount(r)).toBe(4000);
  });
});
const filesOfCount = (r: { fileCount: number }) => r.fileCount;
