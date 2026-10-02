import { createHmac, timingSafeEqual } from 'node:crypto';
import type { Request, Response } from 'express';
import { appendAccountEvent, getDbPool, insertEvent } from '../db';
import { githubConfig, GitHubNotConfigured } from './app';

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
  let secret: string;
  try {
    secret = githubConfig().webhookSecret;
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
    const outcome = await handle(client, event, action, installationId, payload);
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

async function handle(client: import('pg').PoolClient, event: string, action: string | null, installationId: number | null, payload: any): Promise<string> {
  if (installationId === null) return 'no installation';
  const known = (await client.query('SELECT id, creator_id, account_login, status FROM github_installation WHERE installation_id = $1 FOR UPDATE', [installationId])).rows[0];
  if (!known) return 'installation not linked to a creator';
  const identity = (await client.query('SELECT identity_id FROM creator WHERE id = $1', [known.creator_id])).rows[0]?.identity_id as string;
  const sender = typeof payload?.sender?.login === 'string' ? payload.sender.login : null;

  if (event === 'installation' && (action === 'deleted' || action === 'suspend' || action === 'unsuspend')) {
    const status = action === 'deleted' ? 'removed' : action === 'suspend' ? 'suspended' : 'active';
    if (known.status === status) return `already ${status}`;
    await client.query('UPDATE github_installation SET status = $2, status_changed_at = now() WHERE id = $1', [known.id, status]);
    await appendAccountEvent(
      identity,
      'system',
      'github-webhook',
      action === 'unsuspend' ? 'github.connection_restored' : 'github.connection_broken',
      {
        installation_id: installationId,
        organization: known.account_login,
        reason: action === 'deleted' ? 'the app was uninstalled on GitHub' : action === 'suspend' ? 'the app was suspended on GitHub' : 'the app was unsuspended on GitHub',
        by: sender
      },
      client
    );
    return `connection ${status}`;
  }

  if (event === 'repository' && action && ['deleted', 'renamed', 'transferred', 'publicized', 'privatized', 'archived', 'unarchived'].includes(action)) {
    const repoId = String(payload?.repository?.id ?? '');
    const ours = (await client.query('SELECT id, project_id, full_name FROM repository WHERE github_repo_id = $1 AND installation_id = $2', [repoId, installationId])).rows[0];
    if (!ours) return 'not one of our repositories';
    await insertEvent(
      {
        project_id: ours.project_id,
        actor_type: 'system',
        actor_id: 'github-webhook',
        action: `repository.${action}_on_github`,
        subject_type: 'repository',
        subject_id: ours.id,
        payload: {
          full_name_before: ours.full_name,
          full_name_now: typeof payload?.repository?.full_name === 'string' ? payload.repository.full_name : null,
          private_now: typeof payload?.repository?.private === 'boolean' ? payload.repository.private : null,
          by: sender
        }
      },
      client
    );
    if (action === 'renamed' && typeof payload?.repository?.full_name === 'string') {
      await client.query('UPDATE repository SET full_name = $2, updated_at = now() WHERE id = $1', [ours.id, payload.repository.full_name]);
    }
    return `recorded repository ${action}`;
  }

  return 'recorded';
}
