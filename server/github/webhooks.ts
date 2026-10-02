import { createHmac, timingSafeEqual } from 'node:crypto';
import type { Request, Response } from 'express';
import { appendAccountEvent, getDbPool, insertEvent } from '../db';
import { appJwt, gh, githubConfig, GitHubConfig, GitHubError, GitHubNotConfigured, withInstallationToken } from './app';

/**
 * POST /api/v1/github/webhook
 *
 * GitHub signs each delivery with HMAC-SHA256 over the exact body bytes, keyed with the app's webhook secret,
 * and sends it as `X-Hub-Signature-256: sha256=<hex>`. A delivery whose signature does not match is refused
 * (401) and nothing in it is used. Each delivery id is processed once.
 */

export function signatureFor(secret: string, body: Buffer): string {
  return `sha256=${createHmac('sha256', secret).update(body).digest('hex')}`;
}

export function signatureIsValid(secret: string, body: Buffer, header: string | undefined): boolean {
  if (!header || !/^sha256=[0-9a-f]{64}$/.test(header)) return false;
  const expected = Buffer.from(signatureFor(secret, body), 'utf8');
  const given = Buffer.from(header, 'utf8');
  return expected.length === given.length && timingSafeEqual(expected, given);
}

export async function githubWebhook(req: Request, res: Response) {
  let config: GitHubConfig;
  let secret: string;
  try {
    config = githubConfig();
    secret = config.webhookSecret;
  } catch (err) {
    if (err instanceof GitHubNotConfigured) return res.status(503).json({ error: 'The GitHub App is not configured on this server.' });
    throw err;
  }
  const body = Buffer.isBuffer(req.body) ? req.body : Buffer.alloc(0);
  if (!signatureIsValid(secret, body, req.get('x-hub-signature-256'))) {
    console.warn('[github] refused a webhook with a missing or wrong signature');
    return res.status(401).json({ error: 'Signature does not match.' });
  }

  const deliveryId = req.get('x-github-delivery') || '';
  const event = req.get('x-github-event') || '';
  if (!deliveryId || !event || deliveryId.length > 100 || event.length > 100) {
    return res.status(400).json({ error: 'Missing delivery id or event name.' });
  }
  let payload: any;
  try {
    payload = JSON.parse(body.toString('utf8'));
  } catch {
    return res.status(400).json({ error: 'Body is not JSON.' });
  }

  const db = getDbPool();
  if (!db) return res.status(503).json({ error: 'Database not connected.' });
  const installationId = Number.isSafeInteger(payload?.installation?.id) ? payload.installation.id : null;
  const action = typeof payload?.action === 'string' ? payload.action.slice(0, 100) : null;

  try {
    // A delivery already handled is answered at once, before GitHub is asked anything.
    if ((await db.query('SELECT 1 FROM github_webhook_delivery WHERE delivery_id = $1', [deliveryId])).rowCount) {
      return res.status(200).json({ ok: true, duplicate: true });
    }
    // 1. Decide what (if anything) this delivery could change, from our own record. Short queries only.
    const plan = await planFor(db, event, action, installationId, payload);
    // The moment GitHub is asked (database clock), so an older answer never overwrites a newer one.
    const askedAt: Date = (await db.query('SELECT clock_timestamp() AS t')).rows[0].t;
    // 2. Ask GitHub what is true now, holding no database connection while GitHub answers.
    const githubNow = plan.kind === 'installation' ? await installationNow(config, installationId!) : plan.kind === 'repository' ? await repositoryNow(config, installationId!, plan.repoId) : null;
    // 3. One short transaction: handle each delivery id once, compare with what is stored, record real changes.
    const client = await db.connect();
    try {
      await client.query('BEGIN');
      await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', [`github_delivery:${deliveryId}`]);
      const seen = await client.query('SELECT 1 FROM github_webhook_delivery WHERE delivery_id = $1', [deliveryId]);
      if (seen.rowCount) {
        await client.query('ROLLBACK');
        return res.status(200).json({ ok: true, duplicate: true });
      }
      const outcome =
        plan.kind === 'installation'
          ? await applyInstallation(client, installationId!, githubNow as Installation, askedAt, event, action, payload)
          : plan.kind === 'repository'
            ? await applyRepository(client, installationId!, plan.repoId, githubNow as RepoNow, askedAt, payload)
            : plan.outcome;
      await client.query('INSERT INTO github_webhook_delivery (delivery_id, event, action, installation_id, outcome) VALUES ($1, $2, $3, $4, $5)', [
        deliveryId,
        event,
        action,
        installationId,
        outcome
      ]);
      await client.query('COMMIT');
      console.log(`[github] webhook ${event}${action ? `.${action}` : ''}: ${outcome}`);
      res.status(200).json({ ok: true, outcome });
    } catch (err) {
      await client.query('ROLLBACK').catch(() => undefined);
      throw err;
    } finally {
      client.release();
    }
  } catch (err: any) {
    console.error('[github] webhook handling failed:', err?.message ?? err);
    // 500 makes GitHub mark the delivery failed, so it can be redelivered.
    res.status(500).json({ error: 'Could not process this delivery.' });
  }
}

type Installation = { state: 'active' | 'suspended' | 'removed'; login: string | null };
type RepoNow = { exists: true; full_name: string; private: boolean; archived: boolean } | { exists: false };
type Plan = { kind: 'installation' } | { kind: 'repository'; repoId: number } | { kind: 'none'; outcome: string };

/** What this delivery could change, judged from its (signed) body and our own record; nothing is changed here. */
async function planFor(db: import('pg').Pool, event: string, action: string | null, installationId: number | null, payload: any): Promise<Plan> {
  if (installationId === null) return { kind: 'none', outcome: 'no installation' };
  // The event name is a header GitHub does not sign, so the signed body must look like that event.
  const shapeOk =
    event === 'installation'
      ? typeof payload?.installation?.account?.login === 'string' && payload?.repository === undefined
      : event === 'repository'
        ? typeof payload?.repository?.id === 'number'
        : event === 'organization'
          ? typeof payload?.organization?.login === 'string'
          : true;
  if (!shapeOk) return { kind: 'none', outcome: `ignored: body does not match the ${event} event` };
  const isInstallation = event === 'installation' || (event === 'organization' && action === 'renamed');
  const isRepository = event === 'repository' && !!action && ['deleted', 'renamed', 'transferred', 'publicized', 'privatized', 'archived', 'unarchived', 'edited'].includes(action);
  if (!isInstallation && !isRepository) return { kind: 'none', outcome: 'received, not acted on' };
  const known = (await db.query('SELECT account_id FROM github_installation WHERE installation_id = $1', [installationId])).rows[0];
  if (!known) return { kind: 'none', outcome: 'installation not linked to a creator' };
  // (Compared by GitHub's account id, which survives an organization being renamed.)
  if (event === 'installation' && Number(payload.installation.account.id) !== Number(known.account_id)) {
    return { kind: 'none', outcome: 'ignored: installation account does not match' };
  }
  if (isInstallation) return { kind: 'installation' };
  const repoId = Number(payload.repository.id);
  const ours = await db.query('SELECT 1 FROM repository WHERE github_repo_id = $1 AND installation_id = $2', [String(repoId), installationId]);
  return ours.rowCount ? { kind: 'repository', repoId } : { kind: 'none', outcome: 'not one of our repositories' };
}

/** What GitHub reports about an installation right now (asked with the app's own login, not from a webhook). */
async function installationNow(config: GitHubConfig, installationId: number): Promise<Installation> {
  try {
    const inst = await gh(config, { kind: 'app', token: appJwt(config) }, 'GET', `/app/installations/${installationId}`);
    return { state: inst?.suspended_at ? 'suspended' : 'active', login: typeof inst?.account?.login === 'string' ? inst.account.login : null };
  } catch (err) {
    if (err instanceof GitHubError && err.status === 404) return { state: 'removed', login: null };
    throw err;
  }
}

/** What GitHub reports about one repository right now, with a token for that repository only. */
async function repositoryNow(config: GitHubConfig, installationId: number, repoId: number): Promise<RepoNow> {
  try {
    const repo = await withInstallationToken(config, installationId, { repositoryIds: [repoId], permissions: { metadata: 'read' } }, (token) =>
      gh(config, { kind: 'token', token }, 'GET', `/repositories/${repoId}`)
    );
    return { exists: true, full_name: String(repo.full_name), private: repo.private === true, archived: repo.archived === true };
  } catch (err) {
    // 404 from the read, or 422 when a token cannot even be narrowed to it: GitHub no longer shows it to the app.
    if (err instanceof GitHubError && (err.status === 404 || err.status === 422)) return { exists: false };
    throw err;
  }
}

async function applyInstallation(
  client: import('pg').PoolClient,
  installationId: number,
  now: Installation,
  askedAt: Date,
  event: string,
  action: string | null,
  payload: any
): Promise<string> {
  const known = (
    await client.query('SELECT id, creator_id, account_login, status, status_asked_at FROM github_installation WHERE installation_id = $1 FOR UPDATE', [installationId])
  ).rows[0];
  if (!known) return 'installation not linked to a creator';
  if (new Date(known.status_asked_at) > askedAt) return 'ignored: a newer answer from GitHub is already recorded';
  await client.query('UPDATE github_installation SET status_asked_at = $2 WHERE id = $1', [known.id, askedAt]);
  const identity = (await client.query('SELECT identity_id FROM creator WHERE id = $1', [known.creator_id])).rows[0]?.identity_id as string;
  const sender = typeof payload?.sender?.login === 'string' ? payload.sender.login : null;
  const changes: string[] = [];
  if (now.state !== known.status) {
    await client.query('UPDATE github_installation SET status = $2, status_changed_at = now() WHERE id = $1', [known.id, now.state]);
    await appendAccountEvent(
      identity,
      'system',
      'github-webhook',
      now.state === 'active' ? 'github.connection_restored' : 'github.connection_broken',
      {
        installation_id: installationId,
        organization: now.login ?? known.account_login,
        reason:
          now.state === 'removed'
            ? 'GitHub reports the app is no longer installed'
            : now.state === 'suspended'
              ? 'GitHub reports the app is suspended'
              : 'GitHub reports the app is installed and working again',
        github_reports: now.state,
        webhook_said: `${event}.${action ?? ''}`,
        webhook_sender_unconfirmed: sender
      },
      client
    );
    changes.push(`connection ${now.state}`);
  }
  if (now.login && now.login !== known.account_login) {
    await client.query('UPDATE github_installation SET account_login = $2 WHERE id = $1', [known.id, now.login]);
    await appendAccountEvent(identity, 'system', 'github-webhook', 'github.organization_renamed', { installation_id: installationId, from: known.account_login, to: now.login }, client);
    changes.push(`organization renamed to ${now.login}`);
  }
  return changes.length ? changes.join(', ') : `no change (GitHub reports ${now.state})`;
}

/**
 * What GitHub reports now, compared with what was last recorded. Only a real difference is recorded, so the same
 * webhook sent again (or an old one) adds nothing. The webhook's own words are not used as facts.
 */
async function applyRepository(client: import('pg').PoolClient, installationId: number, repoId: number, now: RepoNow, askedAt: Date, payload: any): Promise<string> {
  const ours = (
    await client.query(
      'SELECT id, project_id, full_name, github_state, github_state_asked_at FROM repository WHERE github_repo_id = $1 AND installation_id = $2 FOR UPDATE',
      [String(repoId), installationId]
    )
  ).rows[0];
  if (!ours) return 'not one of our repositories';
  if (ours.github_state_asked_at && new Date(ours.github_state_asked_at) > askedAt) return 'ignored: a newer answer from GitHub is already recorded';
  await client.query('UPDATE repository SET github_state_asked_at = $2 WHERE id = $1', [ours.id, askedAt]);
  const sender = typeof payload?.sender?.login === 'string' ? payload.sender.login : null;
  const before = ours.github_state ?? { exists: true, full_name: ours.full_name, private: true, archived: false };
  const changes: string[] = [];
  if (!now.exists) {
    if (before.exists !== false) changes.push('no_longer_visible');
  } else {
    if (before.exists === false) changes.push('visible_again');
    if (now.full_name !== before.full_name) {
      changes.push(String(now.full_name).split('/')[0] !== String(before.full_name).split('/')[0] ? 'transferred' : 'renamed');
    }
    if (before.private !== undefined && now.private !== before.private) changes.push(now.private ? 'privatized' : 'publicized');
    if (before.archived !== undefined && now.archived !== before.archived) changes.push(now.archived ? 'archived' : 'unarchived');
  }
  if (!changes.length) return 'no change (GitHub reports the same as last recorded)';
  for (const change of changes) {
    await insertEvent(
      {
        project_id: ours.project_id,
        actor_type: 'system',
        actor_id: 'github-webhook',
        action: `repository.${change}_on_github`,
        subject_type: 'repository',
        subject_id: ours.id,
        payload: { before, github_reports: now, webhook_sender_unconfirmed: sender }
      },
      client
    );
  }
  await client.query('UPDATE repository SET github_state = $2::jsonb, full_name = COALESCE($3, full_name), updated_at = now() WHERE id = $1', [
    ours.id,
    JSON.stringify(now),
    now.exists ? now.full_name : null
  ]);
  return `recorded ${changes.join(', ')}`;
}
