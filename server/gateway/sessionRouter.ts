import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import express from 'express';
import { getDbPool, insertEvent } from '../db';
import { ProviderError, ProviderNotConfigured, githubRef, providerFor } from '../repositoryProvider';
import '../githubProvider';
import { SESSION_TOKEN_PREFIX, hashSessionToken } from '../sessionCredentials';
import { findScanner } from './scanner';
import { gitEnv, withMirrorLock } from './mirror';
import { realMirrorPath, sessionDir, sessionViewPath } from './realMirror';

/**
 * The gateway for automated sessions: a session's git remote (docs/integration/PHASE5_DESIGN.md, 4.5).
 *
 *   <app>/git/sessions/<session id>/<owner>/<repo>.git
 *
 * A different route from the door gateway (a door's address starts with the door's id, a session's with "sessions"), a different
 * credential table and a different token prefix (ccs_). Every request is checked against the database: credential not revoked,
 * session active and not expired, the repository is the session's own. Closing a session ends access on the next request.
 *
 * Fetch and clone are served from the session's VIEW repository only. The real repository is never reachable from here: a push goes
 * through the view's pre-receive hook (pre-receive-session.ts), which is the only thing that ever writes to the real history.
 */

const here = path.dirname(fileURLToPath(import.meta.url));
const HOOK_SCRIPT = path.join(here, 'pre-receive-session.ts');
const ROUTE = /^\/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\/([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+?)(?:\.git)?\/(info\/refs|git-upload-pack|git-receive-pack)$/;

export const PUSH_LIMIT_DEFAULTS = { maxCommits: 200, maxPathsPerCommit: 5000, maxFileBytes: 25 * 1024 * 1024, maxPushBytes: 100 * 1024 * 1024 };

/** Limits from the environment (digits only: no "1e3", no signs). A bad value stops the push with a clear message instead of being guessed at. */
export function pushLimits(e: NodeJS.ProcessEnv = process.env) {
  const read = (name: string, fallback: number) => {
    const raw = e[name];
    if (raw === undefined || raw === '') return fallback;
    const n = /^[0-9]+$/.test(raw.trim()) ? Number(raw) : NaN;
    if (!Number.isSafeInteger(n) || n < 1) throw new Error(`${name} must be a positive whole number.`);
    return n;
  };
  return {
    maxCommits: read('SESSION_PUSH_MAX_COMMITS', PUSH_LIMIT_DEFAULTS.maxCommits),
    maxPathsPerCommit: read('SESSION_PUSH_MAX_PATHS', PUSH_LIMIT_DEFAULTS.maxPathsPerCommit),
    maxFileBytes: read('SESSION_PUSH_MAX_FILE_BYTES', PUSH_LIMIT_DEFAULTS.maxFileBytes),
    maxPushBytes: read('SESSION_PUSH_MAX_BYTES', PUSH_LIMIT_DEFAULTS.maxPushBytes)
  };
}

/** The loader that lets node run the hook (TypeScript) as its own process. Found next to this project's dependencies. */
function findTsxLoader(): string | null {
  let dir = here;
  for (let i = 0; i < 8; i++) {
    const candidate = path.join(dir, 'node_modules', 'tsx', 'dist', 'esm', 'index.mjs');
    if (fs.existsSync(candidate)) return pathToFileURL(candidate).href;
    const up = path.dirname(dir);
    if (up === dir) break;
    dir = up;
  }
  return null;
}

const HOOK = `#!/bin/sh
# Custody Core gateway (written by the server before every push). Refuses everything unless the server set it up for this push.
if [ -z "$CUSTODY_GATEWAY_HOOK" ] || [ -z "$CUSTODY_NODE" ] || [ -z "$CUSTODY_TSX" ]; then
  echo "Custody Core: pushes are only accepted through the gateway." >&2
  exit 1
fi
exec "$CUSTODY_NODE" --import "$CUSTODY_TSX" "$CUSTODY_GATEWAY_HOOK"
`;

function deny(res: express.Response, status: number, message: string) {
  if (status === 401) res.setHeader('WWW-Authenticate', 'Basic realm="Custody Core session gateway", charset="UTF-8"');
  res.status(status).type('text/plain').send(`${message}\n`);
}

function credentialFrom(req: express.Request): string | null {
  const m = /^Basic\s+([A-Za-z0-9+/=]+)\s*$/i.exec(req.headers.authorization ?? '');
  if (!m) return null;
  const decoded = Buffer.from(m[1], 'base64').toString('utf8');
  const i = decoded.indexOf(':');
  const user = i >= 0 ? decoded.slice(0, i) : decoded;
  const pass = i >= 0 ? decoded.slice(i + 1) : '';
  const token = pass.startsWith(SESSION_TOKEN_PREFIX) ? pass : user.startsWith(SESSION_TOKEN_PREFIX) ? user : '';
  return token && token.length < 200 ? token : null;
}

interface SessionAccess {
  credentialId: string;
  sessionId: string;
  projectId: string;
  repositoryId: string;
  fullName: string;
  installationId: number | null;
  provider: 'github';
  readOnly: boolean;
  baseCommit: string;
  rules: { allowedRead: string[]; allowedWrite: string[]; prohibited: string[] };
  author: { name: string; email: string };
}

type Lookup = { ok: true; access: SessionAccess } | { ok: false; status: number; message: string };

/** The name and address a real commit of this session is authored under: from the session's declared executor, never from the push. */
export function authorFor(s: { id: string; executor_type: string; executor_provider: string | null; executor_model: string | null; executor_external_id: string | null; executor_display_name: string | null }) {
  const raw = s.executor_display_name || s.executor_external_id || [s.executor_provider, s.executor_model].filter(Boolean).join(' ') || s.executor_type;
  // eslint-disable-next-line no-control-regex
  const name = raw.replace(/[\u0000-\u001f\u007f<>]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 100) || s.executor_type;
  return { name, email: `session-${s.id}@sessions.custody.invalid` };
}

async function lookup(token: string, sessionId: string, fullName: string): Promise<Lookup> {
  const db = getDbPool();
  if (!db) return { ok: false, status: 503, message: 'The gateway database is not connected.' };
  const r = await db.query(
    `SELECT sc.id AS credential_id, sc.last_used_at, s.id AS session_id, s.project_id, s.status, s.expires_at, s.repository_id, s.repository_access,
            s.base_commit, s.allowed_read_paths, s.allowed_write_paths, s.prohibited_paths,
            s.executor_type, s.executor_provider, s.executor_model, s.executor_external_id, s.executor_display_name,
            r.full_name, r.provider, gi.installation_id, now() AS now
       FROM session_credential sc
       JOIN work_session s ON s.id = sc.work_session_id
       JOIN repository r ON r.id = s.repository_id
       JOIN project p ON p.id = s.project_id
       LEFT JOIN github_installation gi ON gi.creator_id = p.creator_id
      WHERE sc.token_hash = $1 AND sc.revoked_at IS NULL AND s.session_type = 'automated_work_session'`,
    [hashSessionToken(token)]
  );
  if (r.rowCount === 0) return { ok: false, status: 401, message: 'This credential is not valid (wrong, or revoked when the session ended).' };
  const row = r.rows[0];
  if (row.session_id !== sessionId) return { ok: false, status: 403, message: 'This credential is for a different session.' };
  if (row.status !== 'active') return { ok: false, status: 403, message: 'This session is not active.' };
  if (new Date(row.expires_at) <= new Date(row.now)) return { ok: false, status: 403, message: 'This session has expired.' };
  if (String(row.full_name).toLowerCase() !== fullName.toLowerCase()) return { ok: false, status: 404, message: 'This repository is not part of this session.' };
  if (!row.last_used_at || Date.now() - new Date(row.last_used_at).getTime() > 60_000) {
    await db.query('UPDATE session_credential SET last_used_at = now() WHERE id = $1 AND revoked_at IS NULL', [row.credential_id]);
  }
  return {
    ok: true,
    access: {
      credentialId: row.credential_id,
      sessionId,
      projectId: row.project_id,
      repositoryId: row.repository_id,
      fullName: row.full_name,
      installationId: row.installation_id === null ? null : Number(row.installation_id),
      provider: row.provider,
      readOnly: row.repository_access !== 'read_and_push',
      baseCommit: row.base_commit,
      rules: { allowedRead: row.allowed_read_paths, allowedWrite: row.allowed_write_paths, prohibited: row.prohibited_paths },
      author: authorFor({ id: sessionId, ...row })
    }
  };
}

async function record(a: SessionAccess, action: string, payload: Record<string, unknown>) {
  try {
    await insertEvent({
      project_id: a.projectId,
      actor_type: 'gateway',
      actor_id: `session:${a.sessionId}`,
      action,
      subject_type: 'repository',
      subject_id: a.repositoryId,
      payload: { work_session_id: a.sessionId, repository: a.fullName, ...payload }
    });
  } catch (err: any) {
    console.error(`[session-gateway] could not record ${action}:`, err?.message ?? err);
  }
}

/** Same CGI bridge as the door gateway, kept separate so that route stays exactly as it was. */
function httpBackend(req: express.Request, res: express.Response, env: Record<string, string>, beforeEnd?: () => Promise<void>): Promise<void> {
  return new Promise((resolve) => {
    const child = spawn('git', ['http-backend'], { env, stdio: ['pipe', 'pipe', 'pipe'] });
    let head = Buffer.alloc(0);
    let headersSent = false;
    let stderr = '';
    child.stderr.on('data', (c) => (stderr = (stderr + c).slice(-4000)));
    const onData = (chunk: Buffer) => {
      head = Buffer.concat([head, chunk]);
      let end = head.indexOf('\r\n\r\n');
      let sep = 4;
      if (end < 0) {
        end = head.indexOf('\n\n');
        sep = 2;
      }
      if (end < 0) {
        if (head.length > 64 * 1024) child.kill('SIGKILL');
        return;
      }
      let status = 200;
      for (const line of head.subarray(0, end).toString('latin1').split(/\r?\n/)) {
        const i = line.indexOf(':');
        if (i <= 0) continue;
        const name = line.slice(0, i).trim();
        const value = line.slice(i + 1).trim();
        if (name.toLowerCase() === 'status') status = parseInt(value, 10) || 500;
        else res.setHeader(name, value);
      }
      res.status(status);
      headersSent = true;
      child.stdout.off('data', onData);
      const rest = head.subarray(end + sep);
      if (rest.length) res.write(rest);
      child.stdout.pipe(res, { end: false });
    };
    child.stdout.on('data', onData);
    child.on('close', (code) => {
      if (code !== 0 && stderr.trim()) console.error('[session-gateway] git http-backend:', stderr.trim().split('\n').slice(-3).join(' | '));
      const finish = () => {
        if (!headersSent) {
          if (!res.headersSent) res.status(500).type('text/plain').send('The gateway could not serve this request.\n');
        } else {
          res.end();
        }
        resolve();
      };
      if (!beforeEnd) return finish();
      beforeEnd()
        .catch((err) => console.error('[session-gateway] after-request step failed:', err?.message ?? err))
        .finally(finish);
    });
    child.on('error', () => undefined);
    child.stdin.on('error', () => undefined);
    req.pipe(child.stdin);
    res.on('close', () => {
      if (child.exitCode === null) child.kill('SIGTERM');
    });
  });
}

const HEX40 = /^[0-9a-f]{40}$/;

export const sessionGatewayRouter = express.Router();

sessionGatewayRouter.use(async (req, res) => {
  const m = ROUTE.exec(req.path);
  if (!m) return deny(res, 404, 'Not a Custody Core session git address.');
  const [, sessionId, owner, repo, endpoint] = m;

  let service: 'git-upload-pack' | 'git-receive-pack';
  if (endpoint === 'info/refs') {
    if (req.method !== 'GET') return deny(res, 405, 'Method not allowed.');
    const s = req.query.service;
    if (s !== 'git-upload-pack' && s !== 'git-receive-pack') return deny(res, 403, 'Only the smart HTTP git protocol is supported.');
    service = s;
  } else {
    if (req.method !== 'POST') return deny(res, 405, 'Method not allowed.');
    service = endpoint as typeof service;
  }

  const token = credentialFrom(req);
  if (!token) return deny(res, 401, 'Sign in with the credential from your session (any user name; the credential as the password).');

  let result: Lookup;
  try {
    result = await lookup(token, sessionId, `${owner}/${repo}`);
  } catch (err: any) {
    console.error('[session-gateway] lookup failed:', err?.message ?? err);
    return deny(res, 500, 'The gateway could not check this request.');
  }
  if (!result.ok) return deny(res, result.status, result.message);
  const a = result.access;
  if (service === 'git-receive-pack' && a.readOnly) return deny(res, 403, 'This session has read access to this repository, not write access.');

  const viewDir = sessionViewPath(sessionId);
  if (!fs.existsSync(path.join(viewDir, 'HEAD'))) {
    return deny(res, 503, "This session's working copy is not available on the gateway. Anything you already pushed is in the repository; close this session and request a new one to continue.");
  }

  const protocol = String(req.headers['git-protocol'] ?? '');
  const env = gitEnv({
    GIT_PROJECT_ROOT: sessionDir(sessionId),
    GIT_HTTP_EXPORT_ALL: '1',
    PATH_INFO: `/${path.basename(viewDir)}/${endpoint}`,
    REQUEST_METHOD: req.method,
    QUERY_STRING: endpoint === 'info/refs' ? `service=${service}` : '',
    CONTENT_TYPE: String(req.headers['content-type'] ?? ''),
    REMOTE_USER: `session-${sessionId}`,
    REMOTE_ADDR: req.ip ?? '',
    ...(req.headers['content-length'] ? { CONTENT_LENGTH: String(req.headers['content-length']) } : {}),
    ...(req.headers['content-encoding'] ? { HTTP_CONTENT_ENCODING: String(req.headers['content-encoding']) } : {}),
    ...(/^[A-Za-z0-9=:,._-]{1,200}$/.test(protocol) ? { GIT_PROTOCOL: protocol } : {})
  });

  if (endpoint === 'info/refs' && service === 'git-upload-pack') await record(a, 'git.fetch', {});
  if (endpoint !== 'git-receive-pack') return httpBackend(req, res, env);

  // A push. Everything the hook needs is prepared here; it works against the real mirror, which only it ever writes to.
  const scanner = findScanner();
  const tsx = findTsxLoader();
  if (!tsx) return deny(res, 503, 'The gateway cannot run its push check (the runtime loader is missing), so no push can be accepted.');
  let limits;
  try {
    limits = pushLimits();
  } catch (err: any) {
    console.error('[session-gateway]', err?.message ?? err);
    return deny(res, 503, 'The gateway has an invalid push limit setting, so no push can be accepted.');
  }
  if (a.installationId === null) return deny(res, 503, "The project's GitHub connection is missing. Ask the creator to reconnect GitHub.");

  const provider = providerFor(a.provider);
  let remote;
  try {
    remote = await provider.remote(githubRef({ id: a.repositoryId, full_name: a.fullName, installation_id: a.installationId }));
  } catch (err: any) {
    if (err instanceof ProviderNotConfigured) return deny(res, 503, err.publicMessage);
    console.error('[session-gateway] provider credentials:', err?.message ?? err);
    return deny(res, 502, err instanceof ProviderError ? `${provider.label} refused access.` : `${provider.label} could not be reached.`);
  }

  const db = getDbPool()!;
  const view = (await db.query('SELECT view_commit FROM session_view WHERE work_session_id = $1', [sessionId])).rows[0];
  if (!view) return deny(res, 503, 'This session has no recorded view, so no push can be accepted.');

  const real = realMirrorPath(a.repositoryId);
  if (!fs.existsSync(path.join(real, 'HEAD'))) {
    return deny(res, 503, 'The gateway no longer holds the repository this session works on. Close this session and request a new one.');
  }

  const resultDir = fs.mkdtempSync(path.join(os.tmpdir(), 'custody-session-push-'));
  const resultFile = path.join(resultDir, 'result.json');
  const mapFile = path.join(resultDir, 'map.json');

  const recordOutcome = async () => {
    let outcome: any = null;
    try {
      outcome = JSON.parse(fs.readFileSync(resultFile, 'utf8'));
    } catch {
      outcome = null; // the push ended before the hook ran
    }
    if (!outcome) return;
    const refs = (outcome.updates ?? []).map((u: any) => ({ ref: u.ref, old: u.old, new: u.new, ...(u.realNew ? { real_new: u.realNew } : {}) }));
    if (outcome.accepted) {
      const commits = (Array.isArray(outcome.commits) ? outcome.commits : []).filter(
        (c: any) => HEX40.test(c?.view_sha) && HEX40.test(c?.real_sha) && HEX40.test(c?.parent_view_sha) && typeof c?.declared_author === 'string'
      );
      for (const c of commits) {
        await db.query(
          `INSERT INTO session_commit (work_session_id, view_sha, real_sha, parent_view_sha, declared_author)
           VALUES ($1, $2, $3, $4, $5) ON CONFLICT (work_session_id, view_sha) DO NOTHING`,
          [sessionId, c.view_sha, c.real_sha, c.parent_view_sha, c.declared_author.slice(0, 200)]
        );
      }
      await record(a, 'git.push', { updates: refs, commits: commits.map((c: any) => ({ view: c.view_sha, real: c.real_sha })), scanner: outcome.scanner });
    } else {
      await record(a, 'git.push_rejected', {
        reason: outcome.reason,
        updates: refs,
        ...(outcome.findings ? { findings: outcome.findings, finding_count: outcome.finding_count } : {}),
        ...(outcome.paths ? { paths: outcome.paths, path_count: outcome.path_count } : {}),
        ...(outcome.scanner ? { scanner: outcome.scanner } : {}),
        ...(outcome.upstream_detail ? { upstream_detail: outcome.upstream_detail } : {})
      });
    }
  };

  try {
    // One push at a time per session, and per real repository (the real mirror is written by the hook). Always in this order.
    await withMirrorLock(viewDir, () =>
      withMirrorLock(real, async () => {
        // What was already replayed, so the hook starts from there; written fresh for every push.
        const rows = (await db.query('SELECT view_sha, real_sha FROM session_commit WHERE work_session_id = $1', [sessionId])).rows;
        fs.writeFileSync(mapFile, JSON.stringify(Object.fromEntries(rows.map((r) => [r.view_sha, r.real_sha]))));
        // The hook is rewritten before every push, so nothing left in the directory can stand in for it.
        fs.mkdirSync(path.join(viewDir, 'hooks'), { recursive: true });
        fs.writeFileSync(path.join(viewDir, 'hooks', 'pre-receive'), HOOK, { mode: 0o755 });
        await httpBackend(
          req,
          res,
          {
            ...env,
            CUSTODY_GATEWAY_HOOK: HOOK_SCRIPT,
            CUSTODY_NODE: process.execPath,
            CUSTODY_TSX: tsx,
            CUSTODY_REAL_MIRROR: real,
            CUSTODY_UPSTREAM_URL: remote.url,
            CUSTODY_UPSTREAM_AUTH: remote.authHeader,
            CUSTODY_RESULT_FILE: resultFile,
            CUSTODY_COMMIT_MAP: mapFile,
            CUSTODY_SESSION_JSON: JSON.stringify({ sessionId, rules: a.rules, realBase: a.baseCommit, viewBase: view.view_commit, author: a.author, limits }),
            ...(scanner ? { CUSTODY_GITLEAKS: scanner.path, CUSTODY_GITLEAKS_VERSION: scanner.version } : {})
          },
          recordOutcome
        );
      })
    );
  } finally {
    fs.rmSync(resultDir, { recursive: true, force: true });
  }
});
