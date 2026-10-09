import crypto from 'node:crypto';
import express from 'express';
import { getDbPool } from './db';
import { creatorOf } from './auth';
import { encryptionKey } from './secretBox';
import {
  GitHubError,
  GitHubNotConfigured,
  exchangeOAuthCode,
  forgetInstallationTokens,
  getInstallation,
  githubConfig,
  installationRepositories,
  userCanAccessInstallation
} from './github';

/**
 * Connecting a creator's GitHub organization.
 *
 * 1. The signed-in creator asks for an install link (POST /api/v1/github/install). The answer sets a short-lived,
 *    signed, HttpOnly cookie naming that creator, and the link carries a random value (state) also in the cookie.
 * 2. They install the App on GitHub. GitHub sends the browser back to /github/callback with the installation id
 *    and a one-time code (the App must have "Request user authorization (OAuth) during installation" on).
 * 3. The server trades the code for the installing person's GitHub token and checks, with GitHub, that this
 *    person really has access to that installation. An installation id alone proves nothing: anyone can type one.
 *    Only then is the installation recorded for the creator named in the cookie.
 */

const COOKIE = 'cc_github_install';
const COOKIE_PATH = '/github';
const FLOW_MINUTES = 15;

function stateKey(): Buffer {
  // A key for this purpose only, derived from the server's secret key (never stored anywhere).
  return Buffer.from(crypto.hkdfSync('sha256', encryptionKey(), Buffer.alloc(0), 'custody-core github install v1', 32));
}

function signFlow(creatorId: string, nonce: string, expiresAt: number): string {
  const body = Buffer.from(JSON.stringify({ c: creatorId, n: nonce, e: expiresAt })).toString('base64url');
  const mac = crypto.createHmac('sha256', stateKey()).update(body).digest('base64url');
  return `${body}.${mac}`;
}

function readFlow(value: string | undefined): { creatorId: string; nonce: string } | null {
  if (!value) return null;
  const [body, mac] = value.split('.');
  if (!body || !mac) return null;
  const expected = crypto.createHmac('sha256', stateKey()).update(body).digest();
  const given = Buffer.from(mac, 'base64url');
  if (given.length !== expected.length || !crypto.timingSafeEqual(given, expected)) return null;
  try {
    const parsed = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    if (typeof parsed.c !== 'string' || typeof parsed.n !== 'string' || typeof parsed.e !== 'number') return null;
    if (parsed.e < Date.now()) return null;
    return { creatorId: parsed.c, nonce: parsed.n };
  } catch {
    return null;
  }
}

function cookieValue(req: express.Request, name: string): string | undefined {
  for (const part of (req.headers.cookie ?? '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0 && part.slice(0, i).trim() === name) return decodeURIComponent(part.slice(i + 1).trim());
  }
  return undefined;
}

function flowCookie(value: string, maxAgeSeconds: number): string {
  const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  return `${COOKIE}=${encodeURIComponent(value)}; Path=${COOKIE_PATH}; Max-Age=${maxAgeSeconds}; HttpOnly; SameSite=Lax${secure}`;
}

export interface CreatorInstallation {
  installation_id: number;
  account_login: string;
  account_type: string;
}

export async function installationOf(creatorId: string): Promise<CreatorInstallation | null> {
  const db = getDbPool();
  if (!db) return null;
  const r = await db.query('SELECT installation_id, account_login, account_type FROM github_installation WHERE creator_id = $1', [creatorId]);
  if (r.rowCount === 0) return null;
  return { ...r.rows[0], installation_id: Number(r.rows[0].installation_id) };
}

function githubFailure(res: express.Response, err: any, what: string) {
  if (err instanceof GitHubNotConfigured) return res.status(503).json({ error: err.message });
  if (err instanceof GitHubError) {
    console.error(`[github] ${what}:`, err.message);
    return res.status(502).json({ error: err.message });
  }
  console.error(`[github] ${what}:`, err?.message ?? err);
  return res.status(500).json({ error: 'Something went wrong on the server.' });
}

/** /api/v1/github: needs a full login (mounted after authenticate). */
export const githubApiRouter = express.Router();

githubApiRouter.get('/', async (_req, res) => {
  const config = githubConfig();
  try {
    const installation = await installationOf(creatorOf(res).id);
    res.json({
      configured: !!config,
      connected: !!installation,
      account_login: installation?.account_login ?? null,
      account_type: installation?.account_type ?? null
    });
  } catch (err) {
    githubFailure(res, err, 'reading the connection');
  }
});

githubApiRouter.post('/install', (_req, res) => {
  const config = githubConfig();
  if (!config) return res.status(503).json({ error: 'The GitHub App is not set up on this server (GITHUB_APP_* settings).' });
  try {
    const nonce = crypto.randomBytes(16).toString('base64url');
    const flow = signFlow(creatorOf(res).id, nonce, Date.now() + FLOW_MINUTES * 60 * 1000);
    res.setHeader('Set-Cookie', flowCookie(flow, FLOW_MINUTES * 60));
    res.json({ url: `${config.webUrl}/apps/${encodeURIComponent(config.slug)}/installations/new?state=${encodeURIComponent(nonce)}` });
  } catch (err) {
    githubFailure(res, err, 'starting an installation');
  }
});

githubApiRouter.get('/repositories', async (_req, res) => {
  try {
    const installation = await installationOf(creatorOf(res).id);
    if (!installation) return res.status(409).json({ error: 'Connect GitHub first.' });
    const repositories = await installationRepositories(installation.installation_id);
    res.json({ repositories });
  } catch (err) {
    githubFailure(res, err, 'listing repositories');
  }
});

/** /github/callback: where GitHub sends the browser after installation. Not under /api: it answers with redirects. */
export const githubCallbackRouter = express.Router();

githubCallbackRouter.get('/callback', async (req, res) => {
  const done = (outcome: string, reason?: string) => {
    res.setHeader('Set-Cookie', flowCookie('', 0));
    const q = new URLSearchParams({ github: outcome, ...(reason ? { reason } : {}) });
    res.redirect(303, `/?${q.toString()}`);
  };

  let flow: { creatorId: string; nonce: string } | null = null;
  try {
    flow = readFlow(cookieValue(req, COOKIE));
  } catch (err) {
    return done('error', 'server_not_configured');
  }
  if (!flow) return done('error', 'start_again'); // no, expired or forged cookie: start from Custody Core
  const state = typeof req.query.state === 'string' ? req.query.state : undefined;
  if (state !== undefined && state !== flow.nonce) return done('error', 'start_again');

  if (req.query.setup_action === 'request') return done('requested'); // an organization owner must approve it
  const installationId = Number(req.query.installation_id);
  const code = typeof req.query.code === 'string' ? req.query.code : '';
  if (!Number.isSafeInteger(installationId) || installationId <= 0) return done('error', 'no_installation');
  if (!code) return done('error', 'no_user_authorization');

  const db = getDbPool();
  if (!db) return done('error', 'database_not_connected');
  try {
    const userToken = await exchangeOAuthCode(code);
    const access = await userCanAccessInstallation(userToken, installationId);
    if (!access.allowed) return done('error', 'not_your_installation');
    const installation = await getInstallation(installationId);
    const creator = await db.query('SELECT identity_id FROM creator WHERE id = $1', [flow.creatorId]);
    if (creator.rowCount === 0) return done('error', 'start_again');

    const client = await db.connect();
    try {
      await client.query('BEGIN');
      await client.query(
        `INSERT INTO github_installation (creator_id, installation_id, account_login, account_type, connected_by_github_login)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (creator_id) DO UPDATE SET installation_id = EXCLUDED.installation_id, account_login = EXCLUDED.account_login,
           account_type = EXCLUDED.account_type, connected_by_github_login = EXCLUDED.connected_by_github_login, updated_at = now()`,
        [flow.creatorId, installationId, installation.account_login, installation.account_type, access.login]
      );
      await client.query(
        `SELECT * FROM append_account_event($1, 'creator', $2, 'account.github_connected', $3::jsonb)`,
        [creator.rows[0].identity_id, flow.creatorId, JSON.stringify({
          installation_id: installationId,
          account_login: installation.account_login,
          account_type: installation.account_type,
          connected_by_github_login: access.login
        })]
      );
      await client.query('COMMIT');
    } catch (err) {
      await client.query('ROLLBACK').catch(() => undefined);
      throw err;
    } finally {
      client.release();
    }
    forgetInstallationTokens(installationId);
    done('connected');
  } catch (err: any) {
    console.error('[github] installation callback failed:', err?.message ?? err);
    done('error', err instanceof GitHubError ? 'github_refused' : 'server_error');
  }
});
