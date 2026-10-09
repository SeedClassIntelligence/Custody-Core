import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';

/**
 * A door's mirrors: one bare repository per door and repository, on the gateway's own disk.
 *
 * Each mirror holds GitHub's branches and tags, except other doors' branches (door/<other id>/...), which are
 * never fetched into it. Git cannot reliably hide objects that are in a repository, so a developer can only
 * ever download what is in their own door's mirror. Mirrors are a cache: GitHub is the source of truth, every
 * fetch and push starts by refreshing from it, and closing the door deletes them.
 */

export function gatewayDataDir(): string {
  return process.env.GATEWAY_DATA_DIR || path.join(os.tmpdir(), 'custody-core-gateway');
}

export function doorDir(doorId: string): string {
  if (!/^[0-9a-f-]{36}$/.test(doorId)) throw new Error('bad door id');
  return path.join(gatewayDataDir(), 'doors', doorId);
}

export function mirrorPath(doorId: string, repositoryId: string): string {
  if (!/^[0-9a-f-]{36}$/.test(repositoryId)) throw new Error('bad repository id');
  return path.join(doorDir(doorId), `${repositoryId}.git`);
}

/**
 * The environment every git process of the gateway runs with: no user or system git configuration, no
 * prompts, and none of the server's own secrets.
 */
export function gitEnv(extra: Record<string, string> = {}): Record<string, string> {
  const home = path.join(gatewayDataDir(), 'home');
  fs.mkdirSync(home, { recursive: true });
  return {
    PATH: process.env.PATH || '/usr/local/bin:/usr/bin:/bin',
    HOME: home,
    LANG: 'C.UTF-8',
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_CONFIG_GLOBAL: '/dev/null',
    GIT_TERMINAL_PROMPT: '0',
    ...extra
  };
}

export interface GitResult {
  code: number;
  stdout: string;
  stderr: string;
}

export function git(args: string[], opts: { cwd?: string; input?: string; env?: Record<string, string>; timeoutMs?: number } = {}): Promise<GitResult> {
  return new Promise((resolve, reject) => {
    const child = spawn('git', args, { cwd: opts.cwd, env: opts.env ?? gitEnv(), stdio: ['pipe', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    const timer = setTimeout(() => child.kill('SIGKILL'), opts.timeoutMs ?? 5 * 60 * 1000);
    child.stdout.on('data', (c) => (stdout += c));
    child.stderr.on('data', (c) => (stderr += c));
    child.on('error', (err) => {
      clearTimeout(timer);
      reject(err);
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      resolve({ code: code ?? 1, stdout, stderr });
    });
    child.stdin.on('error', () => undefined);
    child.stdin.end(opts.input ?? '');
  });
}

// One operation at a time per mirror (refresh, push). Reads run alongside.
const locks = new Map<string, Promise<unknown>>();

export async function withMirrorLock<T>(key: string, fn: () => Promise<T>): Promise<T> {
  const previous = locks.get(key) ?? Promise.resolve();
  let release!: () => void;
  const mine = new Promise<void>((r) => (release = r));
  const chained = previous.then(() => mine);
  locks.set(key, chained);
  await previous.catch(() => undefined);
  try {
    return await fn();
  } finally {
    release();
    if (locks.get(key) === chained) locks.delete(key);
  }
}

const HOOK = `#!/bin/sh
# Custody Core gateway (written by the server). Refuses everything unless the server set it up for this push.
if [ -z "$CUSTODY_GATEWAY_HOOK" ] || [ -z "$CUSTODY_NODE" ]; then
  echo "Custody Core: pushes are only accepted through the gateway." >&2
  exit 1
fi
exec "$CUSTODY_NODE" "$CUSTODY_GATEWAY_HOOK"
`;

async function createMirror(dir: string): Promise<void> {
  fs.mkdirSync(path.dirname(dir), { recursive: true });
  const tmp = `${dir}.tmp-${process.pid}-${Date.now()}`;
  const init = await git(['init', '--bare', '--quiet', tmp]);
  if (init.code !== 0) throw new Error(`git init failed: ${init.stderr.trim()}`);
  const settings: Array<[string, string]> = [
    ['http.receivepack', 'true'],
    ['receive.fsckObjects', 'true'],
    ['transfer.fsckObjects', 'true'],
    ['receive.denyDeleteCurrent', 'true'],
    ['gc.auto', '0'],
    ['uploadpack.allowFilter', 'true']
  ];
  for (const [k, v] of settings) {
    const r = await git(['config', k, v], { cwd: tmp });
    if (r.code !== 0) throw new Error(`git config ${k} failed: ${r.stderr.trim()}`);
  }
  fs.rmSync(path.join(tmp, 'hooks'), { recursive: true, force: true });
  fs.mkdirSync(path.join(tmp, 'hooks'));
  fs.writeFileSync(path.join(tmp, 'hooks', 'pre-receive'), HOOK, { mode: 0o755 });
  fs.renameSync(tmp, dir);
}

export class UpstreamError extends Error {}

/**
 * Brings a door's mirror up to date with GitHub: creates it if needed, fetches every allowed branch and tag,
 * removes refs GitHub no longer has, and points HEAD at GitHub's default branch.
 */
export async function refreshMirror(doorId: string, repositoryId: string, upstreamUrl: string, authHeader: string): Promise<void> {
  const dir = mirrorPath(doorId, repositoryId);
  await withMirrorLock(dir, async () => {
    if (!fs.existsSync(path.join(dir, 'HEAD'))) await createMirror(dir);
    const auth = ['-c', `http.extraHeader=${authHeader}`, '-c', 'credential.helper='];

    const listed = await git([...auth, 'ls-remote', '--symref', upstreamUrl, 'HEAD', 'refs/heads/*', 'refs/tags/*'], { cwd: dir });
    if (listed.code !== 0) throw new UpstreamError(`Could not read the repository on GitHub: ${lastLine(listed.stderr)}`);

    const ownPrefix = `refs/heads/door/${doorId}/`;
    const wanted = new Map<string, string>();
    let headTarget: string | null = null;
    for (const line of listed.stdout.split('\n')) {
      const sym = /^ref: (refs\/heads\/\S+)\tHEAD$/.exec(line);
      if (sym) {
        headTarget = sym[1];
        continue;
      }
      const m = /^([0-9a-f]{40,64})\t(refs\/(?:heads|tags)\/\S+)$/.exec(line);
      if (!m || m[2].endsWith('^{}')) continue;
      const ref = m[2];
      if (ref.startsWith('refs/heads/door/') && !ref.startsWith(ownPrefix)) continue; // another door's work
      wanted.set(ref, m[1]);
    }

    if (wanted.size > 0) {
      const refspecs = [...wanted.keys()].map((r) => `+${r}:${r}`).join('\n') + '\n';
      const fetched = await git([...auth, 'fetch', '--quiet', '--no-tags', '--no-write-fetch-head', '--stdin', upstreamUrl], { cwd: dir, input: refspecs });
      if (fetched.code !== 0) throw new UpstreamError(`Could not fetch from GitHub: ${lastLine(fetched.stderr)}`);
    }

    // Refs GitHub no longer has (or that this door may not see) are removed from the mirror.
    const local = await git(['for-each-ref', '--format=%(refname)', 'refs/heads', 'refs/tags'], { cwd: dir });
    const stale = local.stdout.split('\n').filter((r) => r && !wanted.has(r));
    if (stale.length > 0) {
      const del = await git(['update-ref', '--stdin'], { cwd: dir, input: stale.map((r) => `delete ${r}\n`).join('') });
      if (del.code !== 0) throw new Error(`Could not remove old refs: ${lastLine(del.stderr)}`);
    }

    if (headTarget && wanted.has(headTarget)) await git(['symbolic-ref', 'HEAD', headTarget], { cwd: dir });
  });
}

/** Deletes every mirror of a door (on close). */
export function removeDoorMirrors(doorId: string): void {
  fs.rmSync(doorDir(doorId), { recursive: true, force: true });
}

function lastLine(s: string): string {
  const lines = s.split('\n').map((l) => l.trim()).filter((l) => l && !/authorization/i.test(l));
  return lines[lines.length - 1] ?? 'no details';
}
