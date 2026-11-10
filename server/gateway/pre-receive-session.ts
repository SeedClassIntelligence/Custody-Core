// Custody Core gateway: the pre-receive hook of an automated session's view repository (docs/integration/PHASE5_DESIGN.md, 4.5).
//
// A session works in a FILTERED VIEW of the repository. Whatever it pushes is replayed onto the real history by this hook. git runs
// it while the pushed objects are still in quarantine; any non-zero exit refuses the whole push and nothing reaches the real
// repository. In order:
//   1. refs: only branches under refs/heads/session/<id>/, no tags, no deletes, fast-forward only;
//   2. shape: linear history from the view's base (no merges, no new roots), within the commit, path and size limits;
//   3. paths: every changed path (renames are a delete plus an add) is judged by the session's path rules; only regular files;
//      an added file may not overwrite anything in the real tree, a changed or deleted file must be what the real tree holds;
//   4. secrets: gitleaks over the new commits (no scanner, no push);
//   5. translate: each commit becomes a real commit on the real history. The AUTHOR is the session's declared executor, the pushed
//      author is kept only as a trailer, the COMMITTER is the gateway, and the result is a pure function of its inputs: pushing the
//      same commits again gives the same real commits;
//   6. push those to the real repository atomically, each branch leased to what is there. Only then does this hook succeed.
// The outcome goes to CUSTODY_RESULT_FILE for the server to record.
//
// Runs as its own process for every push (through tsx), with only the settings below, never the server's own environment.

import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { PathRules, isRegularFileMode } from '../pathRules';

const ZERO = '0000000000000000000000000000000000000000';
const env = process.env;

interface Limits {
  maxCommits: number;
  maxPathsPerCommit: number;
  maxFileBytes: number;
  maxPushBytes: number;
}
interface SessionConfig {
  sessionId: string;
  rules: { allowedRead: string[]; allowedWrite: string[]; prohibited: string[] };
  /** The real commit the session is based on, and the view commit that stands for it. */
  realBase: string;
  viewBase: string;
  author: { name: string; email: string };
  limits: Limits;
}

interface Update {
  old: string;
  new: string;
  ref: string;
  realNew?: string;
}
const updates: Update[] = [];
const resultFile = env.CUSTODY_RESULT_FILE;

function finish(accepted: boolean, details: Record<string, unknown>): never {
  if (resultFile) {
    try {
      fs.writeFileSync(resultFile, JSON.stringify({ accepted, updates, ...details }));
    } catch {
      // the server records "no result" instead
    }
  }
  process.exit(accepted ? 0 : 1);
}

class Refused extends Error {
  constructor(
    readonly reason: string,
    readonly lines: string[],
    readonly extra: Record<string, unknown> = {}
  ) {
    super(reason);
  }
}

function say(lines: string[]) {
  for (const l of lines) process.stderr.write(`${l}\n`);
}

// ---- running git ------------------------------------------------------------------------------------------------------

interface Out {
  code: number;
  stdout: Buffer;
  stderr: string;
}

function run(args: string[], opts: { cwd?: string; env: Record<string, string>; input?: Buffer | string; timeoutMs?: number }): Out {
  const r = spawnSync('git', args, { cwd: opts.cwd, env: opts.env, input: opts.input, maxBuffer: 512 * 1024 * 1024, timeout: opts.timeoutMs ?? 10 * 60_000 });
  return { code: r.status ?? 1, stdout: r.stdout ?? Buffer.alloc(0), stderr: String(r.stderr ?? '') };
}

const safe = (s: string) => s.split('\n').map((l) => l.trim()).filter((l) => l && !/authorization/i.test(l)).slice(-6);

/** The view repository, as git gave it to this hook (quarantine and all), without the real repository's credentials. */
const viewEnv: Record<string, string> = Object.fromEntries(Object.entries(env).filter(([k, v]) => v !== undefined && k !== 'CUSTODY_UPSTREAM_AUTH')) as Record<string, string>;

function viewGit(args: string[], input?: Buffer | string): Buffer {
  const r = run(args, { env: viewEnv, input });
  if (r.code !== 0) throw new Error(`git ${args[0]} failed in the view: ${safe(r.stderr).join(' | ')}`);
  return r.stdout;
}

/** Objects the view has, including the ones still in quarantine, so commands on the REAL repository can read the pushed objects. */
function alternates(): string {
  const out: string[] = [];
  const quarantine = env.GIT_OBJECT_DIRECTORY ?? path.join(path.resolve(env.GIT_DIR ?? '.'), 'objects');
  out.push(path.resolve(quarantine));
  for (const a of (env.GIT_ALTERNATE_OBJECT_DIRECTORIES ?? '').split(':').filter(Boolean)) out.push(path.resolve(a));
  return out.join(':');
}

function cleanBase(extra: Record<string, string> = {}): Record<string, string> {
  return {
    PATH: env.PATH ?? '/usr/local/bin:/usr/bin:/bin',
    HOME: env.HOME ?? os.tmpdir(),
    LANG: 'C.UTF-8',
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_CONFIG_GLOBAL: '/dev/null',
    GIT_TERMINAL_PROMPT: '0',
    ...extra
  };
}

let realDir = '';
function realGit(args: string[], opts: { input?: Buffer | string; extraEnv?: Record<string, string>; withViewObjects?: boolean; timeoutMs?: number } = {}): Out {
  const e = cleanBase({ ...(opts.withViewObjects === false ? {} : { GIT_ALTERNATE_OBJECT_DIRECTORIES: alternates() }), ...(opts.extraEnv ?? {}) });
  return run(['--git-dir', realDir, ...args], { env: e, input: opts.input, timeoutMs: opts.timeoutMs });
}
function mustRealGit(args: string[], what: string, opts: Parameters<typeof realGit>[1] = {}): Buffer {
  const r = realGit(args, opts);
  if (r.code !== 0) throw new Error(`${what} failed: ${safe(r.stderr).join(' | ')}`);
  return r.stdout;
}

// ---- reading what was pushed ------------------------------------------------------------------------------------------

interface Change {
  path: string;
  status: 'A' | 'M' | 'D';
  oldMode: string;
  newMode: string;
  oldSha: string;
  newSha: string;
}

interface CommitInfo {
  sha: string;
  parent: string;
  tree: string;
  authorLine: string; // "Name <email>"
  authorTime: number;
  committerTime: number;
  message: string;
  changes: Change[];
  declared: string;
}

const utf8 = new TextDecoder('utf-8', { fatal: true });

function readCommit(sha: string, parents: string[]): CommitInfo {
  if (parents.length !== 1) {
    throw new Refused(parents.length === 0 ? 'new_root' : 'merge_commit', [
      parents.length === 0 ? `Commit ${sha.slice(0, 12)} has no parent: a session's history must continue from the commit it was given.` : `Commit ${sha.slice(0, 12)} is a merge. A session's history must be a straight line.`,
      'Rebase onto the commit you cloned (no merges, no new root) and push again.'
    ]);
  }
  const raw = viewGit(['cat-file', 'commit', sha]);
  const split = raw.indexOf('\n\n');
  const head = raw.subarray(0, split < 0 ? raw.length : split);
  const body = split < 0 ? Buffer.alloc(0) : raw.subarray(split + 2);
  let message: string;
  try {
    message = utf8.decode(body);
  } catch {
    throw new Refused('bad_message', [`The message of commit ${sha.slice(0, 12)} is not valid UTF-8.`]);
  }
  if (message.includes('\0')) throw new Refused('bad_message', [`The message of commit ${sha.slice(0, 12)} contains a NUL character.`]);
  let tree = '';
  let author = '';
  let committer = '';
  for (const line of head.toString('utf8').split('\n')) {
    if (line.startsWith('tree ')) tree = line.slice(5);
    else if (line.startsWith('author ')) author = line.slice(7);
    else if (line.startsWith('committer ')) committer = line.slice(10);
  }
  const a = /^(.*) (\d+) ([+-]\d{4})$/.exec(author);
  const c = /^(.*) (\d+) ([+-]\d{4})$/.exec(committer);
  if (!a || !c || !/^[0-9a-f]{40}$/.test(tree)) throw new Refused('bad_commit', [`Commit ${sha.slice(0, 12)} is not a normal commit.`]);
  const authorTime = Number(a[2]);
  const committerTime = Number(c[2]);
  const now = Math.floor(Date.now() / 1000);
  for (const t of [authorTime, committerTime]) {
    if (!Number.isSafeInteger(t) || t < 946684800 || t > now + 86400) {
      throw new Refused('bad_date', [`Commit ${sha.slice(0, 12)} has a date outside 2000-01-01 .. tomorrow.`]);
    }
  }
  // eslint-disable-next-line no-control-regex
  const declared = a[1].replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, 200);
  return { sha, parent: parents[0], tree, authorLine: a[1], authorTime, committerTime, message, changes: [], declared };
}

/** diff against the parent with rename detection OFF: a rename is a delete plus an add and both are judged. */
function readChanges(info: CommitInfo, limits: Limits): Change[] {
  const out = viewGit(['diff-tree', '-r', '-z', '--no-renames', '--raw', '--no-abbrev', info.parent, info.sha]);
  const tokens = splitNul(out);
  const changes: Change[] = [];
  for (let i = 0; i + 1 < tokens.length; i += 2) {
    const m = /^:(\d{6}) (\d{6}) ([0-9a-f]{40}) ([0-9a-f]{40}) ([A-Z])\d*$/.exec(tokens[i].toString('latin1'));
    if (!m) throw new Error('unreadable diff output');
    let p: string;
    try {
      p = utf8.decode(tokens[i + 1]);
    } catch {
      throw new Refused('invalid_path', [`Commit ${info.sha.slice(0, 12)} changes a path whose name is not valid UTF-8.`]);
    }
    if (m[5] !== 'A' && m[5] !== 'M' && m[5] !== 'D') {
      throw new Refused('unsupported_change', [`Commit ${info.sha.slice(0, 12)} changes the type of a path (${p}). Replace a file with a different kind of file in two steps, or not at all.`]);
    }
    changes.push({ path: p, status: m[5], oldMode: m[1], newMode: m[2], oldSha: m[3], newSha: m[4] });
    if (changes.length > limits.maxPathsPerCommit) {
      throw new Refused('too_many_paths', [`Commit ${info.sha.slice(0, 12)} changes more than ${limits.maxPathsPerCommit} paths.`]);
    }
  }
  return changes;
}

function splitNul(buf: Buffer): Buffer[] {
  const parts: Buffer[] = [];
  let start = 0;
  for (;;) {
    const i = buf.indexOf(0, start);
    if (i < 0) {
      if (start < buf.length) parts.push(buf.subarray(start));
      return parts;
    }
    parts.push(buf.subarray(start, i));
    start = i + 1;
  }
}

// ---- the real tree, followed along ------------------------------------------------------------------------------------

interface Entry {
  mode: string;
  sha: string;
}
class TreeState {
  constructor(
    readonly files = new Map<string, Entry>(),
    readonly dirs = new Map<string, number>()
  ) {}
  clone(): TreeState {
    return new TreeState(new Map(this.files), new Map(this.dirs));
  }
  private bump(p: string, d: number) {
    let i = p.lastIndexOf('/');
    while (i > 0) {
      const dir = p.slice(0, i);
      const n = (this.dirs.get(dir) ?? 0) + d;
      if (n <= 0) this.dirs.delete(dir);
      else this.dirs.set(dir, n);
      i = dir.lastIndexOf('/');
    }
  }
  set(p: string, e: Entry) {
    if (!this.files.has(p)) this.bump(p, 1);
    this.files.set(p, e);
  }
  remove(p: string) {
    if (this.files.delete(p)) this.bump(p, -1);
  }
  /** Why a NEW file cannot go at this path in the real tree (something is there that the view did not show), or null. */
  blocker(p: string): string | null {
    if (this.files.has(p)) return 'the real repository already has something at this path that the session cannot see';
    if (this.dirs.has(p)) return 'the real repository has a directory at this path';
    let i = p.lastIndexOf('/');
    while (i > 0) {
      if (this.files.has(p.slice(0, i))) return 'the real repository has a file where this path needs a directory';
      i = p.lastIndexOf('/', i - 1);
    }
    return null;
  }
}

function loadRealTree(commit: string): TreeState {
  const out = mustRealGit(['ls-tree', '-r', '-z', '--full-tree', commit], 'reading the real tree');
  const st = new TreeState();
  for (const rec of splitNul(out)) {
    const tab = rec.indexOf(9);
    if (tab < 0) continue;
    const meta = rec.subarray(0, tab).toString('latin1').split(' ');
    st.set(rec.subarray(tab + 1).toString('utf8'), { mode: meta[0], sha: meta[2] });
  }
  return st;
}

// ---- main -------------------------------------------------------------------------------------------------------------

const input = fs.readFileSync(0, 'utf8');
for (const line of input.split('\n')) {
  const m = /^([0-9a-f]{40}) ([0-9a-f]{40}) (\S+)$/.exec(line.trim());
  if (m) updates.push({ old: m[1], new: m[2], ref: m[3] });
}

try {
  main();
} catch (err: any) {
  if (err instanceof Refused) {
    say(['', 'Custody Core refused this push.', ...err.lines, '']);
    finish(false, { reason: err.reason, ...err.extra });
  }
  say(['', 'Custody Core could not process this push, so nothing was changed.', `  ${String(err?.message ?? err).slice(0, 300)}`, '']);
  finish(false, { reason: 'internal_error' });
}

function main(): never {
  let cfg: SessionConfig;
  try {
    cfg = JSON.parse(env.CUSTODY_SESSION_JSON ?? '');
  } catch {
    throw new Refused('gateway_misconfigured', ['The gateway is not configured correctly. Nothing was changed.']);
  }
  const upstream = env.CUSTODY_UPSTREAM_URL;
  const auth = env.CUSTODY_UPSTREAM_AUTH;
  realDir = env.CUSTODY_REAL_MIRROR ?? '';
  if (!cfg?.sessionId || !upstream || !auth || !resultFile || !realDir || !env.CUSTODY_COMMIT_MAP) {
    throw new Refused('gateway_misconfigured', ['The gateway is not configured correctly. Nothing was changed.']);
  }
  if (updates.length === 0) throw new Refused('no_updates', ['Nothing to push.']);
  const limits = cfg.limits;
  const rules = new PathRules({ allowedRead: cfg.rules.allowedRead, allowedWrite: cfg.rules.allowedWrite, prohibited: cfg.rules.prohibited });

  // 1. Refs.
  const prefix = `refs/heads/session/${cfg.sessionId}/`;
  const outside = updates.filter((u) => !u.ref.startsWith(prefix) || u.ref.length === prefix.length || u.ref.length > 250);
  if (outside.length > 0) {
    throw new Refused(
      'ref_not_allowed',
      [`This session can only push branches under session/${cfg.sessionId}/.`, ...outside.map((u) => `  not allowed: ${u.ref.replace(/^refs\/heads\//, '').slice(0, 120)}`), `For example: git push origin HEAD:session/${cfg.sessionId}/work`],
      { refs: outside.map((u) => u.ref.slice(0, 250)) }
    );
  }
  const deletes = updates.filter((u) => u.new === ZERO);
  if (deletes.length > 0) throw new Refused('delete_not_allowed', ['A session cannot delete branches.', ...deletes.map((u) => `  ${u.ref.replace(/^refs\/heads\//, '')}`)]);
  for (const u of updates) {
    if (u.old !== ZERO) {
      const anc = run(['merge-base', '--is-ancestor', u.old, u.new], { env: viewEnv });
      if (anc.code !== 0) {
        throw new Refused('not_fast_forward', [`${u.ref.replace(/^refs\/heads\//, '')} would lose commits. A session's history only moves forward; to start over, push a new branch name.`]);
      }
    }
  }

  // 2. Which commits must be handled: everything on the way from the view's base to the pushed tips that has not been replayed yet.
  const known: Record<string, string> = JSON.parse(fs.readFileSync(env.CUSTODY_COMMIT_MAP, 'utf8'));
  known[cfg.viewBase] = cfg.realBase;
  const tips = [...new Set(updates.map((u) => u.new))];
  const listing = viewGit(['rev-list', '--reverse', '--topo-order', '--parents', ...tips, '--not', cfg.viewBase]).toString().split('\n').filter(Boolean);
  const todo: Array<{ sha: string; parents: string[] }> = [];
  for (const line of listing) {
    const [sha, ...parents] = line.split(' ');
    if (!known[sha]) todo.push({ sha, parents });
  }
  if (todo.length > limits.maxCommits) throw new Refused('too_many_commits', [`This push carries ${todo.length} commits; the limit is ${limits.maxCommits} per push. Push in smaller steps.`]);

  const infos = new Map<string, CommitInfo>();
  for (const t of todo) infos.set(t.sha, readCommit(t.sha, t.parents));
  const childCount = new Map<string, number>();
  for (const i of infos.values()) childCount.set(i.parent, (childCount.get(i.parent) ?? 0) + 1);

  // 3. Paths and the real tree.
  let totalBytes = 0;
  const seenBlobs = new Set<string>();
  const states = new Map<string, TreeState>(); // by the view commit they describe: what the real tree is AFTER that commit
  const realOf = (viewSha: string): string => {
    const r = known[viewSha];
    if (!r) throw new Error(`no real commit for ${viewSha}`);
    return r;
  };
  for (const t of todo) {
    const info = infos.get(t.sha)!;
    info.changes = readChanges(info, limits);

    // sizes of what is added or changed
    const wanted = [...new Set(info.changes.filter((c) => c.status !== 'D').map((c) => c.newSha))].filter((s) => !seenBlobs.has(s));
    if (wanted.length > 0) {
      const sizes = viewGit(['cat-file', '--batch-check=%(objectsize)'], wanted.join('\n') + '\n').toString().split('\n').filter(Boolean);
      wanted.forEach((s, i) => {
        const n = Number(sizes[i]);
        if (!Number.isFinite(n)) throw new Error('unreadable object size');
        if (n > limits.maxFileBytes) {
          const where = info.changes.find((c) => c.newSha === s)!.path;
          throw new Refused('file_too_large', [`${where} is larger than the limit of ${Math.round(limits.maxFileBytes / (1024 * 1024))} MiB.`]);
        }
        totalBytes += n;
        seenBlobs.add(s);
      });
      if (totalBytes > limits.maxPushBytes) throw new Refused('push_too_large', [`This push is larger than the limit of ${Math.round(limits.maxPushBytes / (1024 * 1024))} MiB.`]);
    }

    // the state of the real tree this commit starts from
    let state: TreeState;
    const parentState = states.get(info.parent);
    if (parentState) {
      const remaining = (childCount.get(info.parent) ?? 1) - 1;
      childCount.set(info.parent, remaining);
      state = remaining > 0 ? parentState.clone() : parentState;
      if (remaining <= 0) states.delete(info.parent);
    } else {
      state = loadRealTree(realOf(info.parent));
    }

    // Deletes first, then additions and changes, so replacing a file by a directory of the same name (or back) is judged on the result.
    const problems: Array<{ path: string; reason: string; detail: string }> = [];
    const ordered = [...info.changes.filter((c) => c.status === 'D'), ...info.changes.filter((c) => c.status !== 'D')];
    for (const c of ordered) {
      const d = rules.explainWrite(c.path);
      if (!d.allowed) {
        problems.push({ path: c.path, reason: d.reason, detail: d.detail });
        continue;
      }
      const modeOk = (m: string) => isRegularFileMode(m);
      if (c.status === 'A') {
        if (!modeOk(c.newMode)) problems.push({ path: c.path, reason: 'not_a_regular_file', detail: 'only regular files can be added (no symlinks or submodules)' });
        else {
          const b = state.blocker(c.path);
          if (b) problems.push({ path: c.path, reason: 'would_overwrite', detail: b });
          else state.set(c.path, { mode: c.newMode, sha: c.newSha });
        }
      } else {
        const cur = state.files.get(c.path);
        if (!modeOk(c.oldMode) || (c.status === 'M' && !modeOk(c.newMode))) problems.push({ path: c.path, reason: 'not_a_regular_file', detail: 'only regular files can be changed or deleted' });
        else if (!cur || cur.mode !== c.oldMode || cur.sha !== c.oldSha) problems.push({ path: c.path, reason: 'not_what_the_view_showed', detail: 'the real repository does not hold what the session was shown at this path' });
        else if (c.status === 'D') state.remove(c.path);
        else state.set(c.path, { mode: c.newMode, sha: c.newSha });
      }
    }
    if (problems.length > 0) {
      throw new Refused(
        'path_not_allowed',
        [
          `Commit ${info.sha.slice(0, 12)} changes ${problems.length} path${problems.length === 1 ? '' : 's'} this session may not change:`,
          ...problems.slice(0, 20).map((p) => `  ${p.path}  (${p.reason}: ${p.detail})`),
          'Write only inside the allowed write paths, and only regular files.'
        ],
        { paths: problems.slice(0, 50), path_count: problems.length }
      );
    }
    if ((childCount.get(info.sha) ?? 0) > 0) states.set(info.sha, state);
  }
  states.clear();

  // 4. Secrets: every commit this push adds (not the ones the view already held).
  let scanner = 'none';
  if (tips.length > 0 && todo.length > 0) {
    const gitleaks = env.CUSTODY_GITLEAKS;
    if (!gitleaks) throw new Refused('scanner_unavailable', ['The secret scanner is not installed on the gateway, so no push can be accepted.']);
    scanner = env.CUSTODY_GITLEAKS_VERSION ? `gitleaks ${env.CUSTODY_GITLEAKS_VERSION}` : 'gitleaks';
    const reportDir = fs.mkdtempSync(path.join(os.tmpdir(), 'custody-scan-'));
    const report = path.join(reportDir, 'report.json');
    const scan = spawnSync(
      gitleaks,
      ['git', '--no-banner', '--redact', '--log-level', 'error', '--exit-code', '42', '--report-format', 'json', '--report-path', report, '--log-opts', `${tips.join(' ')} --not --all`, '.'],
      { encoding: 'utf8', env: viewEnv, timeout: 5 * 60_000, maxBuffer: 16 * 1024 * 1024 }
    );
    let findings: any[] = [];
    try {
      findings = JSON.parse(fs.readFileSync(report, 'utf8'));
    } catch {
      findings = [];
    }
    fs.rmSync(reportDir, { recursive: true, force: true });
    if (scan.status === 42) {
      const found = findings.slice(0, 50).map((f) => ({ rule: String(f.RuleID ?? ''), description: String(f.Description ?? ''), file: String(f.File ?? ''), line: Number(f.StartLine ?? 0), commit: String(f.Commit ?? '') }));
      throw new Refused(
        'secret_found',
        [
          `The secret scanner found ${findings.length} possible secret${findings.length === 1 ? '' : 's'}:`,
          ...found.map((f) => `  ${f.file}:${f.line}  ${f.rule}  (commit ${f.commit.slice(0, 12)})`),
          'Remove it from these commits (not just from the latest one), then push again.'
        ],
        { findings: found, finding_count: findings.length, scanner }
      );
    }
    if (scan.status !== 0) throw new Refused('scanner_failed', ['The secret scanner could not check this push, so it was not accepted. Try again.'], { scanner });
  }

  // 5. Translate onto the real history. Every input is fixed by the pushed commit, so the same push always gives the same result.
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'custody-translate-'));
  const pairs: Array<{ view_sha: string; real_sha: string; parent_view_sha: string; declared_author: string }> = [];
  try {
    const index = path.join(work, 'index');
    for (const t of todo) {
      const info = infos.get(t.sha)!;
      const realParent = realOf(info.parent);
      mustRealGit(['read-tree', realParent], 'loading the real tree', { extraEnv: { GIT_INDEX_FILE: index } });
      if (info.changes.length > 0) {
        const lines = info.changes.map((c) => Buffer.concat([Buffer.from(c.status === 'D' ? `0 ${ZERO}\t` : `${c.newMode} ${c.newSha}\t`), Buffer.from(c.path, 'utf8'), Buffer.from([0])]));
        mustRealGit(['update-index', '-z', '--index-info'], 'applying the changes', { input: Buffer.concat(lines), extraEnv: { GIT_INDEX_FILE: index } });
      }
      const tree = mustRealGit(['write-tree'], 'writing the real tree', { extraEnv: { GIT_INDEX_FILE: index } }).toString().trim();
      const trailers = [`Custody-Work-Session: ${cfg.sessionId}`, `Custody-Declared-Author: ${info.declared}`];
      const kept = info.message.split('\n').filter((l) => !/^(Custody-Work-Session|Custody-Declared-Author):/i.test(l)).join('\n').trimEnd();
      const message = `${kept ? `${kept}\n\n` : ''}${trailers.join('\n')}\n`;
      const when = (ts: number) => `${ts} +0000`;
      const real = mustRealGit(['commit-tree', tree, '-p', realParent], 'writing the real commit', {
        input: message,
        extraEnv: {
          GIT_AUTHOR_NAME: cfg.author.name,
          GIT_AUTHOR_EMAIL: cfg.author.email,
          GIT_AUTHOR_DATE: when(info.authorTime),
          GIT_COMMITTER_NAME: 'Custody Core',
          GIT_COMMITTER_EMAIL: 'gateway@custody.invalid',
          GIT_COMMITTER_DATE: when(info.committerTime)
        }
      })
        .toString()
        .trim();
      known[info.sha] = real;
      pairs.push({ view_sha: info.sha, real_sha: real, parent_view_sha: info.parent, declared_author: info.declared });
    }
  } finally {
    fs.rmSync(work, { recursive: true, force: true });
  }
  for (const u of updates) u.realNew = realOf(u.new);

  // 6. Make the pushed objects part of the real mirror, then push to the real repository.
  const have = realGit(['for-each-ref', '--format=%(objectname)', 'refs/heads', 'refs/tags']);
  const excluded = have.stdout.toString().split('\n').filter(Boolean);
  const wantedTips = [...new Set(updates.map((u) => u.realNew!))];
  if (pairs.length > 0) {
    const list = mustRealGit(['rev-list', '--objects', ...wantedTips, '--not', ...excluded], 'listing objects to keep');
    const names = list.toString().split('\n').filter(Boolean).map((l) => l.split(' ')[0]).join('\n') + '\n';
    mustRealGit(['pack-objects', '-q', path.join(realDir, 'objects', 'pack', 'pack')], 'keeping the new objects', { input: names });
  }

  const authArgs = ['-c', `http.extraHeader=${auth}`, '-c', 'credential.helper='];
  const toPush: Array<{ ref: string; tip: string; lease: string }> = [];
  for (const u of updates) {
    const listed = realGit([...authArgs, 'ls-remote', upstream, u.ref], { withViewObjects: false });
    if (listed.code !== 0) throw new Refused('upstream_refused', ['The real repository could not be read, so nothing was changed.', ...safe(listed.stderr).map((l) => `  ${l}`)], { upstream_detail: safe(listed.stderr) });
    const remote = /^([0-9a-f]{40})\t/.exec(listed.stdout.toString())?.[1] ?? '';
    if (remote === u.realNew) continue; // already there (a retry after the earlier attempt got that far)
    if (remote) {
      const probe = `refs/custody/probe/${u.realNew!.slice(0, 12)}`;
      const got = realGit([...authArgs, 'fetch', '--quiet', '--no-tags', '--no-write-fetch-head', upstream, `+${u.ref}:${probe}`], { withViewObjects: false });
      const ancestor = got.code === 0 && realGit(['merge-base', '--is-ancestor', remote, u.realNew!], { withViewObjects: false }).code === 0;
      realGit(['update-ref', '-d', probe], { withViewObjects: false });
      if (!ancestor) {
        throw new Refused('upstream_changed', [`${u.ref.replace(/^refs\/heads\//, '')} was changed in the real repository by someone else, so this push was not applied.`, 'Push to a new branch name.'], { ref: u.ref });
      }
    }
    toPush.push({ ref: u.ref, tip: u.realNew!, lease: remote });
  }
  if (toPush.length > 0) {
    const args = [...authArgs, 'push', '--porcelain', '--atomic', '--no-verify'];
    for (const p of toPush) args.push(`--force-with-lease=${p.ref}:${p.lease}`);
    args.push(upstream, ...toPush.map((p) => `${p.tip}:${p.ref}`));
    const push = realGit(args, { withViewObjects: false, timeoutMs: 10 * 60_000 });
    if (push.code !== 0) {
      const detail = safe(`${push.stdout.toString()}\n${push.stderr}`);
      throw new Refused('upstream_refused', ['The real repository did not accept the push, so nothing was changed:', ...detail.map((l) => `  ${l}`), 'If someone else changed this branch, push to a new branch name.'], { scanner, upstream_detail: detail });
    }
  }

  say([`Custody Core: scanned (${scanner}) and saved to the creator's repository.`, ...pairs.map((p) => `  ${p.view_sha.slice(0, 12)} -> ${p.real_sha.slice(0, 12)}`)]);
  finish(true, { scanner, commits: pairs });
}
