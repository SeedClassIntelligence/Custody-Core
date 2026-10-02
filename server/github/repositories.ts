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
  initial_commit: { pushed: boolean; files: number; pushed_sha: string; reported_sha: string | null; matches: boolean } | null;
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
      throw new BadUpload(`The zip file contains a path that is not allowed: ${n.slice(0, 200)}`);
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
      throw new BadUpload(`The zip file contains a path that is not allowed: ${names[i].slice(0, 200)}`);
    }
    if (parts.some((p) => p === '.git')) throw new BadUpload('The zip file contains a .git folder; upload the files only.');
    if (parts[parts.length - 1] === '.DS_Store') continue;
    const mode = (entry.unixPermissions as number | null) ?? 0;
    if ((mode & 0o170000) === 0o120000) throw new BadUpload(`The zip file contains a link, which is not allowed: ${name.slice(0, 200)}`);
    const data = await entry.async('nodebuffer');
    total += data.length;
    if (total > MAX_TOTAL_BYTES) throw new BadUpload('The unpacked files are larger than 100 MB.');
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
    child.on('close', (code) => (code === 0 ? resolve(out.trim()) : reject(new Error(`git ${args[0]} failed (${code}): ${err.slice(-500)}`))));
  });
}

/**
 * Pushes the files as the repository's first commit, with a token narrowed to this one repository. The token
 * is handed to git in its environment (never on the command line, never in a file), and git is told not to
 * remember it.
 */
async function pushInitialCommit(config: GitHubConfig, token: string, fullName: string, branch: string, files: Awaited<ReturnType<typeof readZip>>): Promise<string> {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'custody-push-'));
  try {
    for (const f of files) {
      const target = path.join(dir, f.path);
      if (!target.startsWith(dir + path.sep)) throw new BadUpload('A path in the zip file is not allowed.');
      fs.mkdirSync(path.dirname(target), { recursive: true });
      fs.writeFileSync(target, f.data, { mode: f.executable ? 0o755 : 0o644 });
    }
    const env: NodeJS.ProcessEnv = {
      PATH: process.env.PATH,
      HOME: dir, // no personal git settings or credential helpers
      GIT_CONFIG_NOSYSTEM: '1',
      GIT_TERMINAL_PROMPT: '0',
      GIT_AUTHOR_NAME: 'Custody Core',
      GIT_AUTHOR_EMAIL: 'custody-core@users.noreply.github.com',
      GIT_COMMITTER_NAME: 'Custody Core',
      GIT_COMMITTER_EMAIL: 'custody-core@users.noreply.github.com',
      GIT_CONFIG_COUNT: '1',
      GIT_CONFIG_KEY_0: 'http.extraHeader',
      GIT_CONFIG_VALUE_0: `Authorization: Basic ${Buffer.from(`x-access-token:${token}`).toString('base64')}`
    };
    for (const k of ['HTTPS_PROXY', 'HTTP_PROXY', 'NO_PROXY', 'https_proxy', 'http_proxy', 'no_proxy', 'SSL_CERT_FILE', 'GIT_SSL_CAINFO']) {
      if (process.env[k]) env[k] = process.env[k];
    }
    await run('git', ['init', '-q', '-b', branch], dir, env);
    await run('git', ['add', '-A'], dir, env);
    await run('git', ['commit', '-q', '-m', 'Initial code, uploaded to Custody Core'], dir, env);
    const sha = await run('git', ['rev-parse', 'HEAD'], dir, env);
    await run('git', ['-c', 'credential.helper=', 'push', '-q', `${config.webUrl}/${fullName}.git`, `HEAD:refs/heads/${branch}`], dir, env);
    return sha;
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
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
  files: Awaited<ReturnType<typeof readZip>> | null
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

  // 2. Existing code, as the first commit (a token for this repository only, contents only).
  let initialCommit: RepositoryResult['initial_commit'] = null;
  if (files) {
    const pushedSha = await withInstallationToken(config, installationId, { repositories: [name], permissions: { contents: 'write' } }, (token) =>
      pushInitialCommit(config, token, fullName, branch, files)
    );
    initialCommit = { pushed: true, files: files.length, pushed_sha: pushedSha, reported_sha: null, matches: false };
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
      const head = await gh(config, auth, 'GET', `${repoPath}/commits/${encodeURIComponent(branch)}`).catch(() => null);
      initialCommit.reported_sha = typeof head?.sha === 'string' ? head.sha : null;
      initialCommit.matches = initialCommit.reported_sha === initialCommit.pushed_sha;
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
