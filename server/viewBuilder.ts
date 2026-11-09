import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { gitEnv } from './gateway/mirror';
import { PathRules, isRegularFileMode, repoPathProblem } from './pathRules';

/**
 * The filtered view of a repository (docs/integration/PHASE5_DESIGN.md, 3 and 4.4).
 *
 * Git cannot restrict what a clone can read, so a session that may read only some paths is given a DIFFERENT repository:
 * one commit, no history, holding exactly the files the rules allow it to read at its base commit, and nothing else.
 * The real repository (the "mirror") is only read here; the view is a separate bare repository that shares no objects,
 * no alternates and no refs with it.
 *
 * Deterministic on purpose: the commit has a fixed author, committer and date, so building the same view twice gives
 * the same commit hash. A lost cache is rebuilt to the identical commit, and pushes made against it stay translatable.
 *
 * Fails closed: nothing is left at the destination unless the finished repository passes a check that it contains
 * exactly the objects of its one commit and no other reference.
 */

export const DEFAULT_MAX_FILES = 20_000;
export const DEFAULT_MAX_BYTES = 500 * 1024 * 1024;

export interface ViewLimits {
  maxFiles: number;
  maxBytes: number;
}

export function viewLimits(env: NodeJS.ProcessEnv = process.env): ViewLimits {
  const read = (name: string, fallback: number) => {
    const raw = env[name];
    if (raw === undefined || raw === '') return fallback;
    const n = /^[0-9]+$/.test(raw.trim()) ? Number(raw) : NaN; // digits only: no "1e3", no "1.5", no sign
    if (!Number.isSafeInteger(n) || n < 1) throw new Error(`${name} must be a positive whole number.`);
    return n;
  };
  return { maxFiles: read('SESSION_VIEW_MAX_FILES', DEFAULT_MAX_FILES), maxBytes: read('SESSION_VIEW_MAX_BYTES', DEFAULT_MAX_BYTES) };
}

export type ViewBuildErrorCode = 'base_invalid' | 'too_many_files' | 'too_large' | 'no_files' | 'git_failed' | 'not_exact';

export class ViewBuildError extends Error {
  constructor(
    readonly code: ViewBuildErrorCode,
    message: string
  ) {
    super(message);
  }
}

export interface ViewResult {
  viewCommit: string;
  viewTree: string;
  baseCommit: string;
  fileCount: number;
  totalBytes: number;
  /** Everything in the base tree that is not in the view, for any reason. Counts only: never names. */
  excludedCount: number;
  omitted: { symlinks: number; submodules: number; invalidPaths: number };
}

// ---- running git ------------------------------------------------------------------------------------------------------

interface Run {
  code: number;
  stdout: Buffer;
  stderr: string;
}

/** Runs git against one repository with the gateway's clean environment. Output stays as bytes: paths are not always UTF-8. */
function git(gitDir: string, args: string[], opts: { input?: Buffer | string; env?: Record<string, string>; timeoutMs?: number } = {}): Promise<Run> {
  return new Promise((resolve, reject) => {
    const child = spawn('git', ['--git-dir', gitDir, ...args], { env: gitEnv(opts.env ?? {}), stdio: ['pipe', 'pipe', 'pipe'] });
    const out: Buffer[] = [];
    let stderr = '';
    const timer = setTimeout(() => child.kill('SIGKILL'), opts.timeoutMs ?? 10 * 60_000);
    child.stdout.on('data', (c: Buffer) => out.push(c));
    child.stderr.on('data', (c) => (stderr = (stderr + c).slice(-4000)));
    child.on('error', (err) => {
      clearTimeout(timer);
      reject(err);
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      resolve({ code: code ?? 1, stdout: Buffer.concat(out), stderr });
    });
    child.stdin.on('error', () => undefined);
    child.stdin.end(opts.input ?? '');
  });
}

async function mustGit(gitDir: string, args: string[], what: string, opts: Parameters<typeof git>[2] = {}): Promise<Buffer> {
  const r = await git(gitDir, args, opts);
  if (r.code !== 0) throw new ViewBuildError('git_failed', `${what} failed: ${r.stderr.trim().split('\n').slice(-2).join(' | ') || `exit ${r.code}`}`);
  return r.stdout;
}

// ---- the base commit --------------------------------------------------------------------------------------------------

export type BaseCheck =
  | { ok: true }
  | { ok: false; reason: 'malformed' | 'missing' | 'not_a_commit' | 'no_default_branch' | 'not_on_default_branch'; detail: string };

/**
 * A base commit must be a real commit of this repository AND reachable from the default branch (design D9): a base on
 * someone's unreviewed side branch is refused. `defaultRef` is the mirror's HEAD unless told otherwise.
 */
export async function verifyBaseCommit(mirrorDir: string, baseCommit: string, defaultRef = 'HEAD'): Promise<BaseCheck> {
  if (!/^[0-9a-f]{40}$/.test(baseCommit)) return { ok: false, reason: 'malformed', detail: 'the base commit must be a full 40-character lowercase commit id' };
  const kind = await git(mirrorDir, ['cat-file', '-t', baseCommit]);
  if (kind.code !== 0) return { ok: false, reason: 'missing', detail: 'the repository has no such commit' };
  if (kind.stdout.toString().trim() !== 'commit') return { ok: false, reason: 'not_a_commit', detail: `that id is a ${kind.stdout.toString().trim()}, not a commit` };
  const tip = await git(mirrorDir, ['rev-parse', '--verify', '--quiet', `${defaultRef}^{commit}`]);
  if (tip.code !== 0) return { ok: false, reason: 'no_default_branch', detail: 'the repository has no default branch to check the base against' };
  const anc = await git(mirrorDir, ['merge-base', '--is-ancestor', baseCommit, tip.stdout.toString().trim()]);
  if (anc.code === 0) return { ok: true };
  if (anc.code === 1) return { ok: false, reason: 'not_on_default_branch', detail: 'the base commit is not part of the default branch' };
  throw new ViewBuildError('git_failed', `could not compare the base commit with the default branch: ${anc.stderr.trim()}`);
}

// ---- listing the base tree --------------------------------------------------------------------------------------------

interface TreeEntry {
  mode: string;
  type: string;
  sha: string;
  size: number;
  path: string | null; // null: the name is not valid UTF-8
}

/** `ls-tree -r -z -l`: "<mode> <type> <sha> <size>\t<path>\0" for every file in the tree. */
function parseLsTree(buf: Buffer): TreeEntry[] {
  const decoder = new TextDecoder('utf-8', { fatal: true });
  const entries: TreeEntry[] = [];
  let start = 0;
  while (start < buf.length) {
    let end = buf.indexOf(0, start);
    if (end < 0) end = buf.length;
    const record = buf.subarray(start, end);
    start = end + 1;
    const tab = record.indexOf(9);
    if (tab < 0) continue;
    const meta = record.subarray(0, tab).toString('latin1').trim().split(/\s+/);
    let name: string | null;
    try {
      name = decoder.decode(record.subarray(tab + 1));
    } catch {
      name = null;
    }
    entries.push({ mode: meta[0], type: meta[1], sha: meta[2], size: meta[3] === '-' ? 0 : Number(meta[3]), path: name });
  }
  return entries;
}

// ---- building ----------------------------------------------------------------------------------------------------------

const FIXED = {
  GIT_AUTHOR_NAME: 'Custody Core',
  GIT_AUTHOR_EMAIL: 'gateway@custody.invalid',
  GIT_AUTHOR_DATE: '2000-01-01T00:00:00Z',
  GIT_COMMITTER_NAME: 'Custody Core',
  GIT_COMMITTER_EMAIL: 'gateway@custody.invalid',
  GIT_COMMITTER_DATE: '2000-01-01T00:00:00Z'
};

export interface BuildViewOptions {
  /** The real repository (bare). Only read; never changed except for unreachable tree and commit objects. */
  mirrorDir: string;
  baseCommit: string;
  rules: PathRules;
  /** Where the view repository is created (replaced if it exists). */
  outDir: string;
  limits?: ViewLimits;
}

export async function buildView(opts: BuildViewOptions): Promise<ViewResult> {
  const { mirrorDir, baseCommit, rules } = opts;
  const limits = opts.limits ?? viewLimits();

  if (!/^[0-9a-f]{40}$/.test(baseCommit)) throw new ViewBuildError('base_invalid', 'The base commit must be a full 40-character lowercase commit id.');
  const kind = await git(mirrorDir, ['cat-file', '-t', baseCommit]);
  if (kind.code !== 0 || kind.stdout.toString().trim() !== 'commit') throw new ViewBuildError('base_invalid', 'The base commit is not a commit of this repository.');

  // 1. what the base commit contains, and what the rules let a session read
  const entries = parseLsTree(await mustGit(mirrorDir, ['ls-tree', '-r', '-z', '-l', '--full-tree', baseCommit], 'listing the base commit'));
  const included: TreeEntry[] = [];
  let totalBytes = 0;
  const omitted = { symlinks: 0, submodules: 0, invalidPaths: 0 };
  for (const e of entries) {
    if (e.type === 'commit' || e.mode === '160000') {
      omitted.submodules++;
      continue;
    }
    if (e.mode === '120000') {
      omitted.symlinks++;
      continue;
    }
    if (e.path === null || repoPathProblem(e.path) !== null) {
      omitted.invalidPaths++;
      continue;
    }
    if (e.type !== 'blob' || !isRegularFileMode(e.mode)) continue;
    if (!rules.canRead(e.path)) continue;
    included.push(e);
    totalBytes += e.size;
    if (included.length > limits.maxFiles) {
      throw new ViewBuildError('too_many_files', `The files this session may read are more than the limit of ${limits.maxFiles}. Narrow the allowed read paths.`);
    }
    if (totalBytes > limits.maxBytes) {
      throw new ViewBuildError('too_large', `The files this session may read are larger than the limit of ${Math.round(limits.maxBytes / (1024 * 1024))} MiB. Narrow the allowed read paths.`);
    }
  }
  if (included.length === 0) throw new ViewBuildError('no_files', 'None of the repository\'s files match the allowed read paths, so there is nothing to give the session.');

  // 2. build in a scratch place next to the destination, and move it into place only when it is complete and checked
  fs.mkdirSync(path.dirname(opts.outDir), { recursive: true });
  const scratch = fs.mkdtempSync(path.join(path.dirname(opts.outDir), '.view-build-'));
  try {
    const indexFile = path.join(scratch, 'index');
    const records = Buffer.concat(included.map((e) => Buffer.concat([Buffer.from(`${e.mode} ${e.sha}\t`), Buffer.from(e.path!, 'utf8'), Buffer.from([0])])));
    await mustGit(mirrorDir, ['update-index', '-z', '--index-info'], 'preparing the view index', { input: records, env: { GIT_INDEX_FILE: indexFile } });
    const tree = (await mustGit(mirrorDir, ['write-tree'], 'writing the view tree', { env: { GIT_INDEX_FILE: indexFile } })).toString().trim();
    const commit = (
      await mustGit(mirrorDir, ['commit-tree', tree, '-m', `Session base: a view of ${baseCommit}`], 'writing the view commit', { env: { ...FIXED } })
    )
      .toString()
      .trim();

    // 3. a new repository with only this commit's objects
    const viewDir = path.join(scratch, 'view.git');
    await initBare(viewDir);
    await packInto(mirrorDir, viewDir, commit);
    await mustGit(viewDir, ['update-ref', 'refs/heads/main', commit], 'setting the view branch');
    await mustGit(viewDir, ['symbolic-ref', 'HEAD', 'refs/heads/main'], 'setting the view HEAD');
    await assertExact(viewDir, commit, included.length);

    fs.rmSync(opts.outDir, { recursive: true, force: true });
    fs.renameSync(viewDir, opts.outDir);
    return {
      viewCommit: commit,
      viewTree: tree,
      baseCommit,
      fileCount: included.length,
      totalBytes,
      excludedCount: entries.length - included.length,
      omitted
    };
  } finally {
    fs.rmSync(scratch, { recursive: true, force: true });
  }
}

async function initBare(viewDir: string): Promise<void> {
  fs.mkdirSync(viewDir, { recursive: true });
  const r = await new Promise<Run>((resolve, reject) => {
    const child = spawn('git', ['init', '--bare', '--quiet', viewDir], { env: gitEnv(), stdio: ['ignore', 'pipe', 'pipe'] });
    let stderr = '';
    child.stderr.on('data', (c) => (stderr += c));
    child.on('error', reject);
    child.on('close', (code) => resolve({ code: code ?? 1, stdout: Buffer.alloc(0), stderr }));
  });
  if (r.code !== 0) throw new ViewBuildError('git_failed', `creating the view repository failed: ${r.stderr.trim()}`);
  const settings: Array<[string, string]> = [
    ['receive.fsckObjects', 'true'],
    ['transfer.fsckObjects', 'true'],
    ['receive.denyNonFastForwards', 'true'],
    ['receive.denyDeletes', 'true'],
    ['receive.denyCurrentBranch', 'ignore'],
    ['uploadpack.allowAnySHA1InWant', 'false'],
    ['uploadpack.allowReachableSHA1InWant', 'false'],
    ['http.receivepack', 'true'],
    ['gc.auto', '0']
  ];
  for (const [k, v] of settings) await mustGit(viewDir, ['config', k, v], `setting ${k}`);
  // No hooks are copied from anywhere: a hook directory with samples only. The gateway installs its own (a later step).
  fs.rmSync(path.join(viewDir, 'hooks'), { recursive: true, force: true });
  fs.mkdirSync(path.join(viewDir, 'hooks'));
}

/** Packs exactly the objects reachable from `commit` in the mirror and stores them in the view: nothing else crosses. */
function packInto(mirrorDir: string, viewDir: string, commit: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const pack = spawn('git', ['--git-dir', mirrorDir, 'pack-objects', '--revs', '--stdout', '-q'], { env: gitEnv(), stdio: ['pipe', 'pipe', 'pipe'] });
    const index = spawn('git', ['--git-dir', viewDir, 'index-pack', '--stdin', '--strict'], { env: gitEnv(), stdio: ['pipe', 'pipe', 'pipe'] });
    let packErr = '';
    let indexErr = '';
    pack.stderr.on('data', (c) => (packErr = (packErr + c).slice(-2000)));
    index.stderr.on('data', (c) => (indexErr = (indexErr + c).slice(-2000)));
    index.stdout.resume();
    pack.stdout.pipe(index.stdin);
    pack.stdin.on('error', () => undefined);
    index.stdin.on('error', () => undefined);
    pack.stdin.end(`${commit}\n`);
    let done = 0;
    const codes: number[] = [];
    const finish = (which: number) => (code: number | null) => {
      codes[which] = code ?? 1;
      if (++done < 2) return;
      if (codes[0] !== 0) return reject(new ViewBuildError('git_failed', `packing the view failed: ${packErr.trim()}`));
      if (codes[1] !== 0) return reject(new ViewBuildError('git_failed', `storing the view failed: ${indexErr.trim()}`));
      resolve();
    };
    pack.on('close', finish(0));
    index.on('close', finish(1));
    pack.on('error', reject);
    index.on('error', reject);
  });
}

export interface ObjectCounts {
  commits: number;
  trees: number;
  blobs: number;
  other: number;
  total: number;
}

/** Every object stored in a repository, by type (loose and packed), whether or not anything points at it. */
export async function listAllObjects(gitDir: string): Promise<{ counts: ObjectCounts; names: Set<string> }> {
  const out = (await mustGit(gitDir, ['cat-file', '--batch-all-objects', '--batch-check=%(objecttype) %(objectname)'], 'listing objects')).toString();
  const counts: ObjectCounts = { commits: 0, trees: 0, blobs: 0, other: 0, total: 0 };
  const names = new Set<string>();
  for (const line of out.split('\n')) {
    if (!line) continue;
    const [type, name] = line.split(' ');
    names.add(name);
    counts.total++;
    if (type === 'commit') counts.commits++;
    else if (type === 'tree') counts.trees++;
    else if (type === 'blob') counts.blobs++;
    else counts.other++;
  }
  return { counts, names };
}

/**
 * The view must hold the objects of its one commit and nothing else: no extra object, no other ref, no alternates, a
 * well-formed repository. This is the check a leak would have to get past.
 */
export async function assertExact(viewDir: string, commit: string, fileCount: number): Promise<void> {
  const reachable = new Set(
    (await mustGit(viewDir, ['rev-list', '--objects', commit], 'listing reachable objects'))
      .toString()
      .split('\n')
      .filter(Boolean)
      .map((l) => l.split(' ')[0])
  );
  const { counts, names } = await listAllObjects(viewDir);
  const stray = [...names].filter((n) => !reachable.has(n));
  if (stray.length > 0 || names.size !== reachable.size) {
    throw new ViewBuildError('not_exact', `The view holds ${stray.length} object(s) that its commit does not use.`);
  }
  if (counts.commits !== 1 || counts.other !== 0) throw new ViewBuildError('not_exact', 'The view must hold exactly one commit and only commits, trees and files.');
  const refs = (await mustGit(viewDir, ['for-each-ref', '--format=%(refname)'], 'listing references')).toString().split('\n').filter(Boolean);
  if (refs.length > 0 && !(refs.length === 1 && refs[0] === 'refs/heads/main')) throw new ViewBuildError('not_exact', 'The view has references other than its one branch.');
  if (fs.existsSync(path.join(viewDir, 'objects', 'info', 'alternates'))) throw new ViewBuildError('not_exact', 'The view must not borrow objects from another repository.');
  const files = (await mustGit(viewDir, ['ls-tree', '-r', '-z', '--name-only', commit], 'counting files')).toString().split('\0').filter(Boolean).length;
  if (files !== fileCount) throw new ViewBuildError('not_exact', `The view holds ${files} files, expected ${fileCount}.`);
  const fsck = await git(viewDir, ['fsck', '--strict', '--connectivity-only', '--no-dangling', '--no-progress']);
  if (fsck.code !== 0) throw new ViewBuildError('not_exact', `The view repository did not pass its integrity check: ${fsck.stderr.trim().split('\n').slice(-1)[0]}`);
}

