import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import express from 'express';
import { getDbPool, insertEvent } from '../db';
import { GitHubError, GitHubNotConfigured, gitAuthHeader, installationToken, upstreamGitUrl } from '../github';
import { findScanner } from './scanner';
import { UpstreamError, gitEnv, mirrorPath, refreshMirror, withMirrorLock } from './mirror';

/**
 * The git gateway: a developer's git remote. Smart HTTP only:
 *
 *   <app>/git/<door id>/<owner>/<repo>.git
 *
 * Every request carries the door's credential (HTTP Basic; the password is the credential). Each request is
 * checked against the database (credential not revoked, door open and not expired, repository part of the door,
 * write access for pushes), so closing a door ends access on the very next request. git's own server program
 * (git http-backend) then serves the door's mirror; pushes go through the mirror's pre-receive hook
 * (pre-receive.mjs): branch policy, secret scan, then forwarded to GitHub.
 */

const here = path.dirname(fileURLToPath(import.meta.url));
const HOOK_SCRIPT = path.join(here, 'pre-receive.mjs');
const ROUTE = /^\/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\/([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+?)(?:\.git)?\/(info\/refs|git-upload-pack|git-receive-pack)$/;

export const TOKEN_PREFIX = 'ccg_';

export function newGatewayToken(): { token: string; hash: string } {
  const token = TOKEN_PREFIX + crypto.randomBytes(32).toString('base64url');
  return { token, hash: hashGatewayToken(token) };
}

export function hashGatewayToken(token: string): string {
  return crypto.createHash('sha256').update(token, 'utf8').digest('hex');
}

function credentialFrom(req: express.Request): string | null {
  const header = req.headers.authorization ?? '';
  const m = /^Basic\s+([A-Za-z0-9+/=]+)\s*$/i.exec(header);
  if (!m) return null;
  const decoded = Buffer.from(m[1], 'base64').toString('utf8');
  const i = decoded.indexOf(':');
  const user = i >= 0 ? decoded.slice(0, i) : decoded;
  const pass = i >= 0 ? decoded.slice(i + 1) : '';
  const token = pass.startsWith(TOKEN_PREFIX) ? pass : user.startsWith(TOKEN_PREFIX) ? user : '';
  return token && token.length < 200 ? token : null;
}

function deny(res: express.Response, status: number, message: string) {
  if (status === 401) res.setHeader('WWW-Authenticate', 'Basic realm="Custody Core gateway", charset="UTF-8"');
  res.status(status).type('text/plain').send(`${message}\n`);
}

interface DoorAccess {
  credentialId: string;
  doorId: string;
  projectId: string;
  developerEmail: string;
  installationId: number;
  repositoryId: string;
  fullName: string;
  access: 'read' | 'write';
}

type Lookup = { ok: true; access: DoorAccess } | { ok: false; status: number; message: string };

async function lookup(token: string, doorId: string, fullName: string): Promise<Lookup> {
  const db = getDbPool();
  if (!db) return { ok: false, status: 503, message: 'The gateway database is not connected.' };
  const r = await db.query(
    `SELECT gc.id AS credential_id, gc.last_used_at, d.id AS door_id, d.status, d.expires_at, d.project_id,
            d.developer_email, gi.installation_id, now() AS now
       FROM gateway_credential gc
       JOIN door d ON d.id = gc.door_id
       JOIN project p ON p.id = d.project_id
       LEFT JOIN github_installation gi ON gi.creator_id = p.creator_id
      WHERE gc.token_hash = $1 AND gc.revoked_at IS NULL`,
    [hashGatewayToken(token)]
  );
  if (r.rowCount === 0) return { ok: false, status: 401, message: 'This credential is not valid (wrong, or revoked when the door closed).' };
  const row = r.rows[0];
  if (row.door_id !== doorId) return { ok: false, status: 403, message: 'This credential is for a different door.' };
  if (row.status !== 'open') return { ok: false, status: 403, message: 'This door is not open.' };
  if (row.expires_at && new Date(row.expires_at) <= new Date(row.now)) {
    return { ok: false, status: 403, message: 'This door has expired.' };
  }
  if (!row.installation_id) return { ok: false, status: 503, message: "The project's GitHub connection is missing. Ask the creator to reconnect GitHub." };

  const repo = await db.query(
    `SELECT r.id, r.full_name, dr.access FROM door_repository dr JOIN repository r ON r.id = dr.repository_id
      WHERE dr.door_id = $1 AND lower(r.full_name) = lower($2)`,
    [doorId, fullName]
  );
  if (repo.rowCount === 0) return { ok: false, status: 404, message: 'This repository is not part of this door.' };

  if (!row.last_used_at || Date.now() - new Date(row.last_used_at).getTime() > 60_000) {
    await db.query('UPDATE gateway_credential SET last_used_at = now() WHERE id = $1 AND revoked_at IS NULL', [row.credential_id]);
  }
  return {
    ok: true,
    access: {
      credentialId: row.credential_id,
      doorId,
      projectId: row.project_id,
      developerEmail: row.developer_email ?? '',
      installationId: Number(row.installation_id),
      repositoryId: repo.rows[0].id,
      fullName: repo.rows[0].full_name,
      access: repo.rows[0].access
    }
  };
}

async function record(a: DoorAccess, action: string, payload: Record<string, unknown>) {
  try {
    await insertEvent({
      project_id: a.projectId,
      actor_type: 'gateway',
      actor_id: `door:${a.doorId}`,
      action,
      subject_type: 'repository',
      subject_id: a.repositoryId,
      payload: { door_id: a.doorId, repository: a.fullName, developer_email: a.developerEmail, ...payload }
    });
  } catch (err: any) {
    console.error(`[gateway] could not record ${action}:`, err?.message ?? err);
  }
}

/**
 * Runs `git http-backend` (CGI) for one request and streams its answer back. beforeEnd runs after git has finished
 * and before the response ends, so whatever it records is in place by the time the client's git command returns.
 */
function httpBackend(
  req: express.Request,
  res: express.Response,
  env: Record<string, string>,
  beforeEnd?: () => Promise<void>
): Promise<void> {
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
      if (code !== 0 && stderr.trim()) console.error('[gateway] git http-backend:', stderr.trim().split('\n').slice(-3).join(' | '));
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
        .catch((err) => console.error('[gateway] after-request step failed:', err?.message ?? err))
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

export const gatewayRouter = express.Router();

gatewayRouter.use(async (req, res) => {
  const m = ROUTE.exec(req.path);
  if (!m) return deny(res, 404, 'Not a Custody Core git address.');
  const [, doorId, owner, repo, endpoint] = m;

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
  if (!token) return deny(res, 401, 'Sign in with the credential from your door (any user name; the credential as the password).');

  let result: Lookup;
  try {
    result = await lookup(token, doorId, `${owner}/${repo}`);
  } catch (err: any) {
    console.error('[gateway] lookup failed:', err?.message ?? err);
    return deny(res, 500, 'The gateway could not check this request.');
  }
  if (!result.ok) return deny(res, result.status, result.message);
  const a = result.access;
  if (service === 'git-receive-pack' && a.access !== 'write') return deny(res, 403, 'This door gives read access to this repository, not write access.');

  let authHeader: string;
  try {
    authHeader = gitAuthHeader(await installationToken(a.installationId, a.fullName.split('/')[1]));
  } catch (err: any) {
    if (err instanceof GitHubNotConfigured) return deny(res, 503, 'The GitHub App is not set up on this server.');
    console.error('[gateway] installation token:', err?.message ?? err);
    return deny(res, 502, err instanceof GitHubError ? `GitHub refused access: ${err.message}` : 'GitHub could not be reached.');
  }
  const upstream = upstreamGitUrl(a.fullName);
  const dir = mirrorPath(a.doorId, a.repositoryId);

  if (endpoint === 'info/refs') {
    try {
      await refreshMirror(a.doorId, a.repositoryId, upstream, authHeader);
    } catch (err: any) {
      console.error('[gateway] refresh failed:', err?.message ?? err);
      return deny(res, 502, err instanceof UpstreamError ? err.message : 'The gateway could not read the repository from GitHub.');
    }
    // One fetch event per git fetch or clone (the advertisement starts each one; later requests continue it).
    if (service === 'git-upload-pack') await record(a, 'git.fetch', {});
  }

  const protocol = String(req.headers['git-protocol'] ?? '');
  const env = gitEnv({
    GIT_PROJECT_ROOT: path.dirname(dir),
    GIT_HTTP_EXPORT_ALL: '1',
    PATH_INFO: `/${path.basename(dir)}/${endpoint}`,
    REQUEST_METHOD: req.method,
    QUERY_STRING: endpoint === 'info/refs' ? `service=${service}` : '',
    CONTENT_TYPE: String(req.headers['content-type'] ?? ''),
    REMOTE_USER: `door-${a.doorId}`,
    REMOTE_ADDR: req.ip ?? '',
    ...(req.headers['content-length'] ? { CONTENT_LENGTH: String(req.headers['content-length']) } : {}),
    ...(req.headers['content-encoding'] ? { HTTP_CONTENT_ENCODING: String(req.headers['content-encoding']) } : {}),
    ...(/^[A-Za-z0-9=:,._-]{1,200}$/.test(protocol) ? { GIT_PROTOCOL: protocol } : {})
  });

  if (endpoint !== 'git-receive-pack') return httpBackend(req, res, env);

  // A push: one at a time per mirror, through the pre-receive hook, which reports back through a file.
  const scanner = findScanner();
  const resultDir = fs.mkdtempSync(path.join(os.tmpdir(), 'custody-push-'));
  const resultFile = path.join(resultDir, 'result.json');
  // The push's outcome is recorded before the developer's git sees the end of the response.
  const recordOutcome = async () => {
    let outcome: any = null;
    try {
      outcome = JSON.parse(fs.readFileSync(resultFile, 'utf8'));
    } catch {
      outcome = null; // the push ended before the hook ran (nothing was sent, or git refused it earlier)
    }
    if (!outcome) return;
    const refs = (outcome.updates ?? []).map((u: any) => ({ ref: u.ref, old: u.old, new: u.new }));
    if (outcome.accepted) {
      await record(a, 'git.push', { updates: refs, scanner: outcome.scanner });
    } else {
      await record(a, 'git.push_rejected', {
        reason: outcome.reason,
        updates: refs,
        ...(outcome.findings ? { findings: outcome.findings, finding_count: outcome.finding_count } : {}),
        ...(outcome.scanner ? { scanner: outcome.scanner } : {}),
        ...(outcome.upstream_detail ? { upstream_detail: outcome.upstream_detail } : {})
      });
    }
  };
  try {
    await withMirrorLock(dir, () =>
      httpBackend(
        req,
        res,
        {
          ...env,
          CUSTODY_GATEWAY_HOOK: HOOK_SCRIPT,
          CUSTODY_NODE: process.execPath,
          CUSTODY_DOOR_ID: a.doorId,
          CUSTODY_UPSTREAM_URL: upstream,
          CUSTODY_UPSTREAM_AUTH: authHeader,
          CUSTODY_RESULT_FILE: resultFile,
          ...(scanner ? { CUSTODY_GITLEAKS: scanner.path, CUSTODY_GITLEAKS_VERSION: scanner.version } : {})
        },
        recordOutcome
      )
    );
  } finally {
    fs.rmSync(resultDir, { recursive: true, force: true });
  }
});
