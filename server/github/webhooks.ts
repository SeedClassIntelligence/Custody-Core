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

  const client = await db.connect();
  try {
    await client.query('BEGIN');
    // One at a time per delivery id, so a delivery GitHub sends twice is handled once.
    await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', [`github_delivery:${deliveryId}`]);
    const seen = await client.query('SELECT 1 FROM github_webhook_delivery WHERE delivery_id = $1', [deliveryId]);
    if (seen.rowCount) {
      await client.query('ROLLBACK');
      return res.status(200).json({ ok: true, duplicate: true });
    }
    const outcome = await handle(config, client, event, action, installationId, payload);
    await client.query(
      'INSERT INTO github_webhook_delivery (delivery_id, event, action, installation_id, outcome) VALUES ($1, $2, $3, $4, $5)',
      [deliveryId, event, action, installationId, outcome]
    );
    await client.query('COMMIT');
    console.log(`[github] webhook ${event}${action ? `.${action}` : ''}: ${outcome}`);
    res.status(200).json({ ok: true, outcome });
  } catch (err: any) {
    await client.query('ROLLBACK').catch(() => undefined);
    console.error('[github] webhook handling failed:', err?.message ?? err);
    // 500 makes GitHub mark the delivery failed, so it can be redelivered.
    res.status(500).json({ error: 'Could not process this delivery.' });
  } finally {
    client.release();
  }
}

type Installation = { state: 'active' | 'suspended' | 'removed'; login: string | null };

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

/**
 * A webhook only says something happened; anyone holding an old signed delivery could send it again. So nothing
 * is changed or recorded from the body alone: each change is confirmed by asking GitHub what is true now, and
 * what GitHub reports is what gets recorded.
 */
async function handle(
  config: GitHubConfig,
  client: import('pg').PoolClient,
  event: string,
  action: string | null,
  installationId: number | null,
  payload: any
): Promise<string> {
  if (installationId === null) return 'no installation';
  const known = (await client.query('SELECT id, creator_id, account_login, account_id, status FROM github_installation WHERE installation_id = $1 FOR UPDATE', [installationId])).rows[0];
  if (!known) return 'installation not linked to a creator';
  const identity = (await client.query('SELECT identity_id FROM creator WHERE id = $1', [known.creator_id])).rows[0]?.identity_id as string;
  const sender = typeof payload?.sender?.login === 'string' ? payload.sender.login : null;

  // The event name is a header GitHub does not sign, so the signed body must look like that event.
  const shapeOk =
    event === 'installation'
      ? typeof payload?.installation?.account?.login === 'string' && payload?.repository === undefined
      : event === 'repository'
        ? typeof payload?.repository?.id === 'number'
        : event === 'organization'
          ? typeof payload?.organization?.login === 'string'
          : true;
  if (!shapeOk) return `ignored: body does not match the ${event} event`;
  // (Compared by GitHub's account id, which survives an organization being renamed.)
  if (event === 'installation' && Number(payload.installation.account.id) !== Number(known.account_id)) {
    return 'ignored: installation account does not match';
  }

  if (event === 'installation' || (event === 'organization' && action === 'renamed')) {
    const now = await installationNow(config, installationId);
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

  if (event === 'repository' && action && ['deleted', 'renamed', 'transferred', 'publicized', 'privatized', 'archived', 'unarchived', 'edited'].includes(action)) {
    const repoId = Number(payload.repository.id);
    const ours = (
      await client.query('SELECT id, project_id, full_name, github_state FROM repository WHERE github_repo_id = $1 AND installation_id = $2 FOR UPDATE', [
        String(repoId),
        installationId
      ])
    ).rows[0];
    if (!ours) return 'not one of our repositories';

    let repo: any = null;
    try {
      repo = await withInstallationToken(config, installationId, { permissions: { metadata: 'read' } }, (token) =>
        gh(config, { kind: 'token', token }, 'GET', `/repositories/${repoId}`).catch((err) => {
          if (err instanceof GitHubError && err.status === 404) return null;
          throw err;
        })
      );
    } catch (err) {
      if (err instanceof GitHubError) return `could not check with GitHub (${err.status}); nothing changed`;
      throw err;
    }
    // What GitHub reports now, compared with what was last recorded. Only a real difference is recorded, so the
    // same webhook sent again (or an old one) adds nothing. The webhook's own words are not used as facts.
    const before = ours.github_state ?? { exists: true, full_name: ours.full_name, private: true, archived: false };
    const now = repo ? { exists: true, full_name: String(repo.full_name), private: repo.private === true, archived: repo.archived === true } : { exists: false };
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
      now.exists ? (now as any).full_name : null
    ]);
    return `recorded ${changes.join(', ')}`;
  }

  return 'received, not acted on';
}

