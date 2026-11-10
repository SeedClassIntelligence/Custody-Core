import fs from 'node:fs';
import path from 'node:path';
import { UpstreamError, gatewayDataDir, git, withMirrorLock } from './mirror';

/**
 * The gateway's copy of a REAL repository (docs/integration/PHASE5_DESIGN.md, 4.4): one full mirror per repository, fetched from the
 * provider, holding every branch and tag. It is what filtered views are built from and where pushed work is replayed.
 * It is never served to anyone: no route, no hook and no credential reaches it, and nothing a session sends is written into it
 * until the session's push has passed every check.
 *
 * Like every mirror it is a cache. The provider is the source of truth, and the directory can be deleted at any time.
 */

export function realMirrorPath(repositoryId: string): string {
  if (!/^[0-9a-f-]{36}$/.test(repositoryId)) throw new Error('bad repository id');
  return path.join(gatewayDataDir(), 'real', `${repositoryId}.git`);
}

export function sessionDir(sessionId: string): string {
  if (!/^[0-9a-f-]{36}$/.test(sessionId)) throw new Error('bad session id');
  return path.join(gatewayDataDir(), 'sessions', sessionId);
}

export function sessionViewPath(sessionId: string): string {
  return path.join(sessionDir(sessionId), 'view.git');
}

async function mustGit(dir: string, args: string[], what: string, opts: Parameters<typeof git>[1] = {}): Promise<string> {
  const r = await git(args, { cwd: dir, ...opts });
  if (r.code !== 0) throw new Error(`${what} failed: ${lastLine(r.stderr)}`);
  return r.stdout;
}

function lastLine(s: string): string {
  const lines = s.split('\n').map((l) => l.trim()).filter((l) => l && !/authorization/i.test(l));
  return lines[lines.length - 1] ?? 'no details';
}

async function ensureMirror(dir: string): Promise<void> {
  if (fs.existsSync(path.join(dir, 'HEAD'))) return;
  fs.mkdirSync(path.dirname(dir), { recursive: true, mode: 0o700 });
  const tmp = `${dir}.tmp-${process.pid}-${Date.now()}`;
  await mustGit(path.dirname(dir), ['init', '--bare', '--quiet', tmp], 'creating the repository mirror');
  for (const [k, v] of [['gc.auto', '0'], ['receive.fsckObjects', 'true']] as const) await mustGit(tmp, ['config', k, v], `setting ${k}`);
  fs.chmodSync(tmp, 0o700);
  fs.renameSync(tmp, dir);
}

export interface RealMirror {
  dir: string;
  /** The default branch as the provider named it ("refs/heads/main"). */
  defaultRef: string;
  /** Where the default branch points. */
  defaultTip: string;
}

/**
 * Brings the real mirror up to date with the provider (every branch and tag; refs the provider no longer has are removed) and says
 * where its default branch is. One at a time per repository.
 */
export async function refreshRealMirror(repositoryId: string, upstreamUrl: string, authHeader: string): Promise<RealMirror> {
  const dir = realMirrorPath(repositoryId);
  return withMirrorLock(dir, async () => {
    await ensureMirror(dir);
    const auth = ['-c', `http.extraHeader=${authHeader}`, '-c', 'credential.helper='];
    const listed = await git([...auth, 'ls-remote', '--symref', upstreamUrl, 'HEAD', 'refs/heads/*', 'refs/tags/*'], { cwd: dir });
    if (listed.code !== 0) throw new UpstreamError(`Could not read the repository: ${lastLine(listed.stderr)}`);

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
      wanted.set(m[2], m[1]);
    }
    if (wanted.size === 0) throw new UpstreamError('The repository has no branches yet, so there is nothing to give a session.');

    const refspecs = [...wanted.keys()].map((r) => `+${r}:${r}`).join('\n') + '\n';
    const fetched = await git([...auth, 'fetch', '--quiet', '--no-tags', '--no-write-fetch-head', '--stdin', upstreamUrl], { cwd: dir, input: refspecs });
    if (fetched.code !== 0) throw new UpstreamError(`Could not fetch the repository: ${lastLine(fetched.stderr)}`);

    const local = await git(['for-each-ref', '--format=%(refname)', 'refs/heads', 'refs/tags'], { cwd: dir });
    const stale = local.stdout.split('\n').filter((r) => r && !wanted.has(r));
    if (stale.length > 0) await mustGit(dir, ['update-ref', '--stdin'], 'removing old refs', { input: stale.map((r) => `delete ${r}\n`).join('') });

    if (!headTarget || !wanted.has(headTarget)) throw new UpstreamError('The repository has no default branch to check the base commit against.');
    await mustGit(dir, ['symbolic-ref', 'HEAD', headTarget], 'pointing HEAD at the default branch');
    return { dir, defaultRef: headTarget, defaultTip: wanted.get(headTarget)! };
  });
}

/** Deletes a session's working files: its view repository and anything else the gateway kept for it. */
export function removeSessionFiles(sessionId: string): void {
  fs.rmSync(sessionDir(sessionId), { recursive: true, force: true });
}
