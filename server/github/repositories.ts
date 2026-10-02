import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import JSZip from 'jszip';
import { gh, GitHubConfig, GitHubError, withInstallationToken } from './app';
import { compareSettings, SettingResult } from './organization';

/**
 * "Claim it": creates a project's private repositories in the creator's organization, locks them, and reads
 * every setting back from GitHub. Each repository's result records what GitHub reported, including features
 * GitHub refused (for example branch rules on a private repository of a free organization).
 */

export const RULESET_NAME = 'Custody Core lock';

export function rulesetFor(appId: string) {
  return {
    name: RULESET_NAME,
    target: 'branch',
    enforcement: 'active',
    conditions: { ref_name: { include: ['~ALL'], exclude: [] } },
    rules: [
      { type: 'deletion' }, // branches cannot be deleted
      { type: 'non_fast_forward' }, // no force-push
      { type: 'update', parameters: { update_allows_fetch_and_merge: false } } // nobody may push...
    ],
    // ...except the Custody Core app itself.
    bypass_actors: [{ actor_id: Number(appId), actor_type: 'Integration', bypass_mode: 'always' }]
  };
}

export interface RulesetResult {
  applied: boolean;
  /** GitHub's refusal, when it refused */
  refused: { status: number; message: string; needs_paid_plan: boolean } | null;
  /** What GitHub reports for the ruleset after creating it */
  reported: { id: number; enforcement: string; rules: string[]; bypass_actors: Array<{ actor_type: string; actor_id: number | null; bypass_mode: string }> } | null;
}

export interface RepositoryResult {
  role: 'main' | 'core';
  full_name: string;
  github_repo_id: number;
  html_url: string;
  default_branch: string;
  settings: SettingResult[];
  ruleset: RulesetResult;
  initial_commit: {
    pushed: boolean;
    files_uploaded: number;
    pushed_sha: string;
    /** GitHub's commit on the branch, and the number of files GitHub reports in it */
    reported_sha: string | null;
    reported_files: number | null;
    matches: boolean;
    error: string | null;
  } | null;
  /** Set when the repository was created but a later step could not be completed */
  incomplete?: string;
}

/** A repository name GitHub accepts, from a project name. */
export function repositoryName(projectName: string): string {
  const slug = projectName
    .normalize('NFKD')
    .replace(/[^\x00-\x7F]/g, '')
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, '-')
    .replace(/^[-.]+|[-.]+$/g, '')
    .slice(0, 80);
  return slug || 'project';
}

const MAX_FILES = 5000;
const MAX_TOTAL_BYTES = 100 * 1024 * 1024;

export class BadUpload extends Error {}

const printable = (name: string) => JSON.stringify(name.slice(0, 200));

/**
 * Unpacks one file, stopping as soon as it would pass `limit` bytes, so a small "zip bomb" cannot fill the
 * server's memory (the sizes a zip declares for its files are not trusted).
 */
function unpackWithLimit(entry: JSZip.JSZipObject, limit: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    let done = false;
    const stream = (entry as any).internalStream('uint8array');
    stream
      .on('data', (chunk: Uint8Array) => {
        if (done) return;
        size += chunk.length;
        if (size > limit) {
          done = true;
          stream.pause();
          reject(new BadUpload('The unpacked files are larger than 100 MB.'));
          return;
        }
        chunks.push(Buffer.from(chunk));
      })
      .on('error', (err: Error) => {
        if (!done) {
          done = true;
          reject(new BadUpload(`The zip file could not be read: ${String(err.message).slice(0, 200)}`));
        }
      })
      .on('end', () => {
        if (!done) {
          done = true;
          resolve(Buffer.concat(chunks));
        }
      })
      .resume();
  });
}

/** Reads an uploaded zip safely: no paths outside the folder, no links, no .git, size and count limits. */
export async function readZip(zipBytes: Buffer): Promise<Array<{ path: string; data: Buffer; executable: boolean }>> {
  let zip: JSZip;
  try {
    zip = await JSZip.loadAsync(zipBytes);
  } catch {
    throw new BadUpload('The upload is not a readable zip file.');
  }
  // JSZip quietly rewrites names like "../x" to "x"; judge the names as they are written in the zip file.
  const original = (f: JSZip.JSZipObject) => ((f as any).unsafeOriginalName ?? f.name).replace(/\\/g, '/') as string;
  const entries = Object.values(zip.files).filter((f) => !f.dir && !original(f).startsWith('__MACOSX/'));
  if (entries.length === 0) throw new BadUpload('The zip file has no files in it.');
  if (entries.length > MAX_FILES) throw new BadUpload(`The zip file has more than ${MAX_FILES} files.`);

  const names = entries.map(original);
  // Check every name as stored, before anything else touches it.
  for (const n of names) {
    const parts = n.split('/');
    if (!n || n.startsWith('/') || /^[A-Za-z]:/.test(n) || parts.some((p) => p === '..' || p === '' || p === '.')) {
      throw new BadUpload(`The zip file contains a path that is not allowed: ${printable(n)}`);
    }
    // Names git or the file system would refuse, so that every check happens before anything is created.
    if (/[\x00-\x1f\x7f]/.test(n)) throw new BadUpload(`The zip file contains a file name with control characters: ${printable(n)}`);
    if (Buffer.byteLength(n) > 1024 || parts.some((p) => Buffer.byteLength(p) > 255)) throw new BadUpload(`The zip file contains a file name that is too long: ${printable(n)}`);
    // git's own names for its folder, including the spellings Windows treats as the same folder.
    if (parts.some((p) => /^\.git[. ]*$/i.test(p) || /^git~\d+$/i.test(p))) throw new BadUpload('The zip file contains a .git folder; upload the files only.');
  }
  // Every path once, and nothing that is both a file and a folder.
  const seen = new Set<string>();
  for (const n of names) {
    const key = n.normalize('NFC').toLowerCase();
    if (seen.has(key)) throw new BadUpload(`The zip file contains the same file twice: ${printable(n)}`);
    seen.add(key);
  }
  for (const n of names) {
    const parts = n.normalize('NFC').toLowerCase().split('/');
    for (let i = 1; i < parts.length; i++) {
      if (seen.has(parts.slice(0, i).join('/'))) throw new BadUpload(`The zip file contains a file that is also a folder: ${printable(parts.slice(0, i).join('/'))}`);
    }
  }
  // A zip made by "compress folder" puts everything under one top folder; that folder is not part of the code.
  const tops = new Set(names.map((n) => n.split('/')[0]));
  const strip = tops.size === 1 && names.every((n) => n.includes('/')) ? `${[...tops][0]}/` : '';

  const files: Array<{ path: string; data: Buffer; executable: boolean }> = [];
  let total = 0;
  for (const [i, entry] of entries.entries()) {
    const name = names[i].slice(strip.length);
    const parts = name.split('/');
    if (!name || name.startsWith('/') || /^[A-Za-z]:/.test(name) || parts.some((p) => p === '..' || p === '' || p === '.')) {
      throw new BadUpload(`The zip file contains a path that is not allowed: ${printable(names[i])}`);
    }
    if (parts[parts.length - 1] === '.DS_Store') continue;
    const mode = (entry.unixPermissions as number | null) ?? 0;
    if ((mode & 0o170000) === 0o120000) throw new BadUpload(`The zip file contains a link, which is not allowed: ${name.slice(0, 200)}`);
    const data = await unpackWithLimit(entry, MAX_TOTAL_BYTES - total);
    total += data.length;
    files.push({ path: name, data, executable: (mode & 0o111) !== 0 });
  }
  if (files.length === 0) throw new BadUpload('The zip file has no files in it.');
  return files;
}

function run(cmd: string, args: string[], cwd: string, env: NodeJS.ProcessEnv): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, { cwd, env, stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '';
    let err = '';
    child.stdout.on('data', (c) => (out += c));
    child.stderr.on('data', (c) => (err += c));
    child.on('error', reject);
    // Name the git command itself (skipping "-c key=value" settings), for a readable error.
    const verb = args.find((a, i) => !a.startsWith('-') && args[i - 1] !== '-c') ?? args[0];
    child.on('close', (code) => (code === 0 ? resolve(out.trim()) : reject(new Error(`git ${verb} failed (${code}): ${err.slice(-500)}`))));
  });
}

export interface PreparedCommit {
  sha: string;
  /** files in the commit, as git lists them */
  committed: number;
  push(config: GitHubConfig, token: string, fullName: string): Promise<void>;
  cleanup(): void;
}

/**
 * Makes the first commit locally, BEFORE anything is created on GitHub, so that any problem with the files is
 * found while nothing exists yet. git takes no settings from the uploaded files or from this machine: a
 * .gitconfig in the upload could otherwise run commands or send the push (and its token) elsewhere. So it gets
 * an empty home of its own, no global or system configuration, and no template (so no hooks).
 */
export async function prepareInitialCommit(files: Awaited<ReturnType<typeof readZip>>, branch: string): Promise<PreparedCommit> {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'custody-push-'));
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'custody-git-home-'));
  const cleanup = () => {
    fs.rmSync(dir, { recursive: true, force: true });
    fs.rmSync(home, { recursive: true, force: true });
  };
  const env: NodeJS.ProcessEnv = {
    PATH: process.env.PATH,
    HOME: home,
    XDG_CONFIG_HOME: home,
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_CONFIG_SYSTEM: os.devNull,
    GIT_CONFIG_GLOBAL: os.devNull,
    GIT_TERMINAL_PROMPT: '0',
    GIT_AUTHOR_NAME: 'Custody Core',
    GIT_AUTHOR_EMAIL: 'custody-core@users.noreply.github.com',
    GIT_COMMITTER_NAME: 'Custody Core',
    GIT_COMMITTER_EMAIL: 'custody-core@users.noreply.github.com'
  };
  for (const k of ['HTTPS_PROXY', 'HTTP_PROXY', 'NO_PROXY', 'https_proxy', 'http_proxy', 'no_proxy', 'SSL_CERT_FILE', 'GIT_SSL_CAINFO']) {
    if (process.env[k]) env[k] = process.env[k];
  }
  try {
    for (const f of files) {
      const target = path.join(dir, f.path);
      if (!target.startsWith(dir + path.sep)) throw new BadUpload('A path in the zip file is not allowed.');
      fs.mkdirSync(path.dirname(target), { recursive: true });
      fs.writeFileSync(target, f.data, { mode: f.executable ? 0o755 : 0o644, flag: 'wx' });
    }
    await run('git', ['init', '-q', '--template=', '-b', branch], dir, env);
    // --force: every uploaded file is committed, even if a .gitignore in the upload lists it.
    await run('git', ['add', '-A', '--force'], dir, env);
    await run('git', ['commit', '-q', '-m', 'Initial code, uploaded to Custody Core'], dir, env);
    const sha = await run('git', ['rev-parse', 'HEAD'], dir, env);
    const listed = await run('git', ['ls-files', '-z'], dir, env);
    const committed = listed.split('\0').filter(Boolean).length;
    if (committed !== files.length) throw new BadUpload(`Only ${committed} of the ${files.length} uploaded files could be committed.`);
    return {
      sha,
      committed,
      cleanup,
      // The token goes to git in its environment only (never on the command line or in a file), for this push.
      async push(config, token, fullName) {
        const withToken = {
          ...env,
          GIT_CONFIG_COUNT: '1',
          GIT_CONFIG_KEY_0: 'http.extraHeader',
          GIT_CONFIG_VALUE_0: `Authorization: Basic ${Buffer.from(`x-access-token:${token}`).toString('base64')}`
        };
        await run('git', ['-c', 'credential.helper=', 'push', '-q', `${config.webUrl}/${fullName}.git`, `HEAD:refs/heads/${branch}`], dir, withToken);
      }
    };
  } catch (err: any) {
    cleanup();
    if (err instanceof BadUpload) throw err;
    // git or the file system refused the files: the creator's upload, not a server fault.
    throw new BadUpload(`These files cannot be committed: ${String(err?.message ?? err).replace(/\s+/g, ' ').slice(0, 300)}`);
  }
}

/** Creates one private repository, pushes the upload if any, locks it, and reads it all back. */
export async function createLockedRepository(
  config: GitHubConfig,
  installationId: number,
  org: string,
  name: string,
  role: 'main' | 'core',
  description: string,
  prepared: PreparedCommit | null,
  uploadedFiles = 0
): Promise<RepositoryResult> {
  // 1. Create it. The repository does not exist yet, so this token cannot be narrowed to it.
  const created = await withInstallationToken(config, installationId, { permissions: { administration: 'write' } }, (token) =>
    gh(config, { kind: 'token', token }, 'POST', `/orgs/${encodeURIComponent(org)}/repos`, {
      name,
      description: description.slice(0, 350),
      private: true,
      visibility: 'private',
      auto_init: false,
      has_wiki: false,
      has_projects: false
    })
  );
  const fullName: string = created.full_name;
  const branch: string = created.default_branch || 'main';

  // From here on the repository exists on GitHub: whatever happens is recorded as a result, never as
  // "not created".
  try {
    return await finishRepository(config, installationId, name, role, fullName, branch, prepared, uploadedFiles);
  } catch (err: any) {
    return {
      role,
      full_name: fullName,
      github_repo_id: Number(created.id),
      html_url: String(created.html_url),
      default_branch: branch,
      settings: [],
      ruleset: { applied: false, refused: null, reported: null },
      initial_commit: null,
      incomplete: err instanceof GitHubError ? `GitHub answered ${err.status}: ${String(err.body?.message ?? err.message)}` : 'no answer from GitHub'
    };
  }
}

async function finishRepository(
  config: GitHubConfig,
  installationId: number,
  name: string,
  role: 'main' | 'core',
  fullName: string,
  branch: string,
  prepared: PreparedCommit | null,
  uploadedFiles: number
): Promise<RepositoryResult> {
  // 2. Existing code, as the first commit (a token for this repository only, contents only).
  let initialCommit: RepositoryResult['initial_commit'] = null;
  if (prepared) {
    initialCommit = { pushed: false, files_uploaded: uploadedFiles, pushed_sha: prepared.sha, reported_sha: null, reported_files: null, matches: false, error: null };
    try {
      await withInstallationToken(config, installationId, { repositories: [name], permissions: { contents: 'write' } }, (token) => prepared.push(config, token, fullName));
      initialCommit.pushed = true;
    } catch (err: any) {
      initialCommit.error = String(err?.message ?? err).replace(/x-access-token:[^@\s]*/g, 'x-access-token:***').slice(0, 300);
    }
  }

  // 3. Lock it and read everything back (a token for this repository only).
  return withInstallationToken(config, installationId, { repositories: [name], permissions: { administration: 'write', contents: 'read' } }, async (token) => {
    const auth = { kind: 'token' as const, token };
    const repoPath = `/repos/${fullName.split('/').map(encodeURIComponent).join('/')}`;

    let forkingError: string | null = null;
    try {
      await gh(config, auth, 'PATCH', repoPath, { allow_forking: false });
    } catch (err) {
      if (!(err instanceof GitHubError)) throw err;
      forkingError = String(err.body?.message ?? err.message);
    }

    const ruleset: RulesetResult = { applied: false, refused: null, reported: null };
    try {
      const made = await gh(config, auth, 'POST', `${repoPath}/rulesets`, rulesetFor(config.appId));
      const back = await gh(config, auth, 'GET', `${repoPath}/rulesets/${Number(made.id)}`);
      ruleset.reported = {
        id: Number(back.id),
        enforcement: String(back.enforcement),
        rules: (back.rules ?? []).map((r: any) => String(r.type)).sort(),
        bypass_actors: (back.bypass_actors ?? []).map((b: any) => ({ actor_type: String(b.actor_type), actor_id: b.actor_id ?? null, bypass_mode: String(b.bypass_mode) }))
      };
      ruleset.applied =
        ruleset.reported.enforcement === 'active' &&
        ['deletion', 'non_fast_forward', 'update'].every((t) => ruleset.reported!.rules.includes(t)) &&
        ruleset.reported.bypass_actors.some((b) => b.actor_type === 'Integration' && String(b.actor_id) === config.appId);
    } catch (err) {
      if (!(err instanceof GitHubError)) throw err;
      const message = String(err.body?.message ?? err.message);
      ruleset.refused = { status: err.status, message, needs_paid_plan: err.status === 403 && /upgrade/i.test(message) };
    }

    const repo = await gh(config, auth, 'GET', repoPath);
    const settings = compareSettings({ private: true, visibility: 'private', allow_forking: false }, repo);
    if (forkingError) settings.push({ setting: 'allow_forking (change refused)', requested: false, reported: forkingError, applied: false });

    if (initialCommit) {
      // What GitHub holds: the branch's commit, and how many files are in it.
      const head = await gh(config, auth, 'GET', `${repoPath}/commits/${encodeURIComponent(branch)}`).catch(() => null);
      initialCommit.reported_sha = typeof head?.sha === 'string' ? head.sha : null;
      if (initialCommit.reported_sha) {
        const tree = await gh(config, auth, 'GET', `${repoPath}/git/trees/${initialCommit.reported_sha}?recursive=1`).catch(() => null);
        initialCommit.reported_files = Array.isArray(tree?.tree) && !tree.truncated ? tree.tree.filter((t: any) => t.type === 'blob').length : null;
      }
      initialCommit.matches = initialCommit.reported_sha === initialCommit.pushed_sha && initialCommit.reported_files === initialCommit.files_uploaded;
    }

    return {
      role,
      full_name: repo.full_name,
      github_repo_id: Number(repo.id),
      html_url: String(repo.html_url),
      default_branch: String(repo.default_branch || branch),
      settings,
      ruleset,
      initial_commit: initialCommit
    };
  });
}
