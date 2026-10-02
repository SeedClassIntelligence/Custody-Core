import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import express from 'express';
import { appendAccountEvent, getDbPool } from '../db';
import { creatorOf } from '../auth';
import { gh, githubConfig, GitHubConfig, GitHubError, GitHubNotConfigured } from './app';
import { lockOrganization } from './organization';

/**
 * Connecting a creator's GitHub organization (their "code home").
 *
 *   POST /api/v1/github/connect     (signed in) start: a one-time state, tied to this creator AND this browser
 *   GET  /api/v1/github/setup       GitHub sends the browser here after the app is installed
 *   GET  /api/v1/github/callback    GitHub sends the browser here after "Authorize"; this links the installation
 *   GET  /api/v1/github/connection  (signed in) what is connected, and the organization settings GitHub reported
 *
 * GitHub's redirect after installing carries an installation id that anyone could forge, so it is never
 * trusted by itself (GitHub's own guidance). The installation is linked only after GitHub confirms, with a token
 * for the GitHub user who just authorized, that this user can see that installation and is an owner of the
 * organization it is installed on. That token is used for those two questions and then revoked; only the
 * installation's id is stored.
 */

export const STATE_COOKIE = 'cc_github_connect';
const STATE_MINUTES = 30;
const sha256 = (v: string) => createHash('sha256').update(v).digest('hex');

export const githubPublicRouter = express.Router();
export const githubRouter = express.Router();

function appUrl(): string {
  const raw = (process.env.APP_URL || '').replace(/\/+$/, '');
  if (!/^https?:\/\/[^/]+$/.test(raw)) throw new GitHubNotConfigured('APP_URL must be set to where this app is reached, for example https://custody.example.com');
  return raw;
}

function configOr503(res: express.Response): GitHubConfig | null {
  try {
    appUrl();
    return githubConfig();
  } catch (err) {
    if (err instanceof GitHubNotConfigured) {
      res.status(503).json({ error: err.message, configured: false });
      return null;
    }
    throw err;
  }
}

function readCookie(req: express.Request, name: string): string | null {
  for (const part of (req.get('cookie') || '').split(';')) {
    const [k, ...v] = part.trim().split('=');
    if (k === name) return decodeURIComponent(v.join('='));
  }
  return null;
}

/** The state in the URL must be the one this browser was given, and must be a live one in the database. */
function stateFromRequest(req: express.Request): string | null {
  const fromUrl = typeof req.query.state === 'string' ? req.query.state : '';
  const fromCookie = readCookie(req, STATE_COOKIE) || '';
  if (!/^[A-Za-z0-9_-]{43}$/.test(fromUrl) || fromUrl.length !== fromCookie.length) return null;
  return timingSafeEqual(Buffer.from(fromUrl), Buffer.from(fromCookie)) ? fromUrl : null;
}

/** Back to the app with a fixed, plain outcome code (never anything from the request). */
function backToApp(res: express.Response, outcome: string) {
  res.set('Cache-Control', 'no-store');
  res.clearCookie(STATE_COOKIE, { path: '/api/v1/github' });
  res.redirect(303, `${appUrl()}/?code_home=${encodeURIComponent(outcome)}`);
}

// ------------------------------------------------------------------------------------------------ signed-in routes

// (Mounted after the full login check in server.ts: session, confirmed email and the code step.)

githubRouter.post('/connect', async (_req, res) => {
  const config = configOr503(res);
  if (!config) return;
  const db = getDbPool();
  if (!db) return res.status(503).json({ error: 'Database not connected.' });
  const creator = creatorOf(res);
  try {
    const existing = await db.query(`SELECT account_login FROM github_installation WHERE creator_id = $1 AND status <> 'removed'`, [creator.id]);
    if (existing.rowCount) return res.status(409).json({ error: `Your code home is already connected (${existing.rows[0].account_login}).` });
    const state = randomBytes(32).toString('base64url');
    await db.query(
      `INSERT INTO github_connect_state (state_hash, creator_id, expires_at) VALUES ($1, $2, now() + make_interval(mins => $3))`,
      [sha256(state), creator.id, STATE_MINUTES]
    );
    res.cookie(STATE_COOKIE, state, {
      httpOnly: true,
      sameSite: 'lax', // sent on GitHub's top-level redirect back to us, not on cross-site requests
      secure: appUrl().startsWith('https://'),
      path: '/api/v1/github',
      maxAge: STATE_MINUTES * 60_000
    });
    res.json({
      install_url: `${config.webUrl}/apps/${encodeURIComponent(config.slug)}/installations/new?state=${state}`,
      new_organization_url: `${config.webUrl}/account/organizations/new?plan=free`
    });
  } catch (err: any) {
    console.error('[github] connect failed:', err?.message ?? err);
    res.status(500).json({ error: 'Something went wrong on the server.' });
  }
});

// Re-apply the organization lock and record what GitHub reports now (for example after someone changed a setting).
githubRouter.post('/organization/lock', async (_req, res) => {
  const config = configOr503(res);
  if (!config) return;
  const db = getDbPool();
  if (!db) return res.status(503).json({ error: 'Database not connected.' });
  const creator = creatorOf(res);
  const inst = (await db.query(`SELECT installation_id, account_login FROM github_installation WHERE creator_id = $1 AND status = 'active'`, [creator.id])).rows[0];
  if (!inst) return res.status(409).json({ error: 'Your code home is not connected.' });
  try {
    const lock = await lockOrganization(config, Number(inst.installation_id), inst.account_login);
    await appendAccountEvent(creator.userId, 'creator', creator.id, 'github.organization_locked', { installation_id: Number(inst.installation_id), ...lock });
    res.json(lock);
  } catch (err: any) {
    const error = err instanceof GitHubError ? { status: err.status, message: String(err.body?.message ?? err.message) } : { status: null, message: 'no answer from GitHub' };
    await appendAccountEvent(creator.userId, 'creator', creator.id, 'github.organization_lock_failed', { installation_id: Number(inst.installation_id), organization: inst.account_login, error });
    res.status(502).json({ error: `GitHub did not answer as expected: ${error.message}` });
  }
});

githubRouter.get('/connection', async (_req, res) => {
  const db = getDbPool();
  if (!db) return res.status(503).json({ error: 'Database not connected.' });
  const creator = creatorOf(res);
  let configured = true;
  try {
    githubConfig();
    appUrl();
  } catch {
    configured = false;
  }
  try {
    const inst = (
      await db.query(
        `SELECT installation_id, account_login, status, connected_at, status_changed_at FROM github_installation
          WHERE creator_id = $1 ORDER BY (status <> 'removed') DESC, connected_at DESC LIMIT 1`,
        [creator.id]
      )
    ).rows[0];
    const latest = async (action: string) =>
      (await db.query(`SELECT payload, hashed_timestamp FROM account_event WHERE account_id = $1 AND action = $2 ORDER BY seq DESC LIMIT 1`, [creator.userId, action])).rows[0] ?? null;
    const lock = await latest('github.organization_locked');
    const broken = inst && inst.status !== 'active' ? await latest('github.connection_broken') : null;
    res.json({
      configured,
      installation: inst
        ? {
            installation_id: Number(inst.installation_id),
            organization: inst.account_login,
            status: inst.status,
            connected_at: inst.connected_at,
            status_changed_at: inst.status_changed_at
          }
        : null,
      organization_lock: lock ? { ...lock.payload, recorded_at: lock.hashed_timestamp } : null,
      broken: broken ? { ...broken.payload, recorded_at: broken.hashed_timestamp } : null
    });
  } catch (err: any) {
    console.error('[github] connection status failed:', err?.message ?? err);
    res.status(500).json({ error: 'Something went wrong on the server.' });
  }
});

// ------------------------------------------------------------------------------------------------ browser redirects from GitHub

githubPublicRouter.get('/setup', async (req, res) => {
  let config: GitHubConfig;
  try {
    config = githubConfig();
    appUrl();
  } catch {
    return res.status(503).send('The GitHub App is not configured on this server.');
  }
  const db = getDbPool();
  if (!db) return res.status(503).send('Database not connected.');
  const state = stateFromRequest(req);
  if (!state) return backToApp(res, 'expired');
  const hint = typeof req.query.installation_id === 'string' && /^\d{1,18}$/.test(req.query.installation_id) ? req.query.installation_id : null;
  if (!hint) return backToApp(res, 'not_installed');
  // Remember what GitHub's redirect claimed; it is checked against GitHub itself in /callback.
  const live = await db.query(
    `UPDATE github_connect_state SET installation_hint = $2 WHERE state_hash = $1 AND used_at IS NULL AND expires_at > now() RETURNING 1`,
    [sha256(state), hint]
  );
  if (!live.rowCount) return backToApp(res, 'expired');
  const authorize = new URL(`${config.webUrl}/login/oauth/authorize`);
  authorize.searchParams.set('client_id', config.clientId);
  authorize.searchParams.set('state', state);
  authorize.searchParams.set('redirect_uri', `${appUrl()}/api/v1/github/callback`);
  res.set('Cache-Control', 'no-store');
  res.redirect(303, authorize.toString());
});

githubPublicRouter.get('/callback', async (req, res) => {
  let config: GitHubConfig;
  try {
    config = githubConfig();
    appUrl();
  } catch {
    return res.status(503).send('The GitHub App is not configured on this server.');
  }
  const db = getDbPool();
  if (!db) return res.status(503).send('Database not connected.');
  const state = stateFromRequest(req);
  const code = typeof req.query.code === 'string' && /^[A-Za-z0-9_-]{1,100}$/.test(req.query.code) ? req.query.code : null;
  if (!state || !code) return backToApp(res, 'expired');

  // Use the state once.
  const claimed = (
    await db.query(
      `UPDATE github_connect_state SET used_at = now()
        WHERE state_hash = $1 AND used_at IS NULL AND expires_at > now() AND installation_hint IS NOT NULL
        RETURNING creator_id, installation_hint`,
      [sha256(state)]
    )
  ).rows[0];
  if (!claimed) return backToApp(res, 'expired');
  const installationId = Number(claimed.installation_hint);

  let userToken: string | null = null;
  try {
    userToken = await exchangeCode(config, code);
    const user = { kind: 'token' as const, token: userToken };
    const installation = await findUserInstallation(config, user, installationId);
    if (!installation) return backToApp(res, 'not_yours');
    if (installation.account?.type !== 'Organization') return backToApp(res, 'not_an_organization');
    const org: string = installation.account.login;
    let membership: any = null;
    try {
      membership = await gh(config, user, 'GET', `/user/memberships/orgs/${encodeURIComponent(org)}`);
    } catch (err) {
      if (!(err instanceof GitHubError)) throw err;
      // 403: GitHub would not tell us, because the app lacks Organization > Members: Read-only. Say exactly that,
      // rather than calling the person "not an owner".
      if (err.status === 403) return backToApp(res, 'app_needs_members_permission');
      if (err.status !== 404) throw err;
    }
    if (membership?.state !== 'active' || membership?.role !== 'admin') return backToApp(res, 'not_owner');
    const githubUser: string = membership.user?.login ?? null;

    // Linked. From here on only the app's own installation tokens are used.
    const creator = (await db.query('SELECT id, identity_id FROM creator WHERE id = $1', [claimed.creator_id])).rows[0];
    const client = await db.connect();
    try {
      await client.query('BEGIN');
      // One link attempt per installation at a time, so two creators (two owners of the same organization)
      // finishing at the same moment cannot both be told "connected".
      await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', [`github_installation:${installationId}`]);
      const taken = await client.query(`SELECT creator_id FROM github_installation WHERE installation_id = $1`, [installationId]);
      if (taken.rowCount && taken.rows[0].creator_id !== creator.id) {
        await client.query('ROLLBACK');
        return backToApp(res, 'linked_elsewhere');
      }
      const linked = await client.query(
        `INSERT INTO github_installation (creator_id, installation_id, account_login, account_id, status)
         VALUES ($1, $2, $3, $4, 'active')
         ON CONFLICT (installation_id) DO UPDATE SET status = 'active', account_login = EXCLUDED.account_login, status_changed_at = now()
           WHERE github_installation.creator_id = EXCLUDED.creator_id
         RETURNING id`,
        [creator.id, installationId, org, installation.account.id]
      );
      if (linked.rowCount !== 1) {
        await client.query('ROLLBACK');
        return backToApp(res, 'linked_elsewhere');
      }
      await appendAccountEvent(
        creator.identity_id,
        'creator',
        creator.id,
        'github.connected',
        { organization: org, organization_id: installation.account.id, installation_id: installationId, confirmed_by_github_user: githubUser },
        client
      );
      await client.query('COMMIT');
    } catch (err: any) {
      await client.query('ROLLBACK').catch(() => undefined);
      if (err?.code === '23505') return backToApp(res, 'already_connected');
      throw err;
    } finally {
      client.release();
    }

    // Lock the organization and record what GitHub reports afterwards (or that locking failed).
    try {
      const lock = await lockOrganization(config, installationId, org);
      await appendAccountEvent(creator.identity_id, 'system', 'github-app', 'github.organization_locked', { installation_id: installationId, ...lock });
      return backToApp(res, lock.all_applied ? 'connected' : 'connected_not_all_locked');
    } catch (err: any) {
      await appendAccountEvent(creator.identity_id, 'system', 'github-app', 'github.organization_lock_failed', {
        installation_id: installationId,
        organization: org,
        error: err instanceof GitHubError ? { status: err.status, message: String(err.body?.message ?? err.message) } : { status: null, message: 'no answer from GitHub' }
      });
      return backToApp(res, 'connected_lock_failed');
    }
  } catch (err: any) {
    console.error('[github] callback failed:', err instanceof GitHubError ? `${err.status} ${err.message}` : err?.message ?? err);
    return backToApp(res, 'github_error');
  } finally {
    if (userToken) await revokeUserToken(config, userToken);
    userToken = null;
  }
});

async function exchangeCode(config: GitHubConfig, code: string): Promise<string> {
  const res = await fetch(`${config.webUrl}/login/oauth/access_token`, {
    method: 'POST',
    headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
    body: JSON.stringify({ client_id: config.clientId, client_secret: config.clientSecret, code, redirect_uri: `${appUrl()}/api/v1/github/callback` }),
    signal: AbortSignal.timeout(20_000)
  });
  const body: any = await res.json().catch(() => ({}));
  if (!res.ok || typeof body.access_token !== 'string') {
    throw new GitHubError(`GitHub did not accept the authorization code (${body.error ?? res.status})`, res.status, { message: body.error });
  }
  return body.access_token;
}

async function findUserInstallation(config: GitHubConfig, user: { kind: 'token'; token: string }, installationId: number) {
  for (let page = 1; page <= 10; page++) {
    const list = await gh(config, user, 'GET', `/user/installations?per_page=100&page=${page}`);
    const match = (list?.installations ?? []).find((i: any) => i?.id === installationId && String(i?.app_id) === config.appId);
    if (match) return match;
    if (!list?.installations?.length || list.installations.length < 100) return null;
  }
  return null;
}

/** The user token answered two questions; revoke it so it cannot be used again. */
async function revokeUserToken(config: GitHubConfig, token: string) {
  try {
    const res = await fetch(`${config.apiUrl}/applications/${encodeURIComponent(config.clientId)}/token`, {
      method: 'DELETE',
      headers: {
        Accept: 'application/vnd.github+json',
        Authorization: `Basic ${Buffer.from(`${config.clientId}:${config.clientSecret}`).toString('base64')}`,
        'Content-Type': 'application/json',
        'User-Agent': `custody-core-${config.slug}`
      },
      body: JSON.stringify({ access_token: token }),
      signal: AbortSignal.timeout(20_000)
    });
    if (res.status !== 204) console.warn('[github] revoking the user token answered', res.status);
  } catch (err: any) {
    console.warn('[github] could not revoke the user token:', err?.message ?? err);
  }
}
