import type { Response } from 'express';
import { appendAccountEvent, getDbPool } from '../db';
import { creatorOf } from '../auth';
import { appJwt, gh, GitHubConfig, GitHubError, withInstallationToken } from './app';

/**
 * The creator's code home, checked with GitHub before any change is made there:
 *   - the app is still installed on the organization and not suspended (asked of GitHub, not our own record);
 *   - a renamed organization is followed;
 *   - the GitHub user who connected it is still an owner of it (by GitHub user id, which survives renames).
 * Uses short, separate database queries only: no connection is held while GitHub is being asked.
 * Answers with an error and returns null when the creator may not act.
 */
export interface CodeHome {
  installationId: number;
  org: string;
}

export async function codeHomeFor(config: GitHubConfig, res: Response): Promise<CodeHome | null> {
  const db = getDbPool()!;
  const creator = creatorOf(res);
  const row = (
    await db.query(
      `SELECT id, installation_id, account_login, owner_login, owner_id, status FROM github_installation WHERE creator_id = $1 AND status <> 'removed'`,
      [creator.id]
    )
  ).rows[0];
  if (!row) {
    res.status(409).json({ error: 'Connect your code home first.' });
    return null;
  }
  const installationId = Number(row.installation_id);

  let inst: any;
  try {
    inst = await gh(config, { kind: 'app', token: appJwt(config) }, 'GET', `/app/installations/${installationId}`);
  } catch (err) {
    if (err instanceof GitHubError && err.status === 404) {
      const changed = await db.query(
        `UPDATE github_installation SET status = 'removed', status_changed_at = now(), status_asked_at = clock_timestamp()
          WHERE id = $1 AND status <> 'removed' RETURNING id`,
        [row.id]
      );
      if (changed.rowCount) {
        await appendAccountEvent(creator.userId, 'system', 'github-app', 'github.connection_broken', {
          installation_id: installationId,
          organization: row.account_login,
          reason: 'GitHub reports the app is no longer installed',
          github_reports: 'removed'
        });
      }
      res.status(409).json({ error: 'Your code home connection is broken: the app is no longer installed on GitHub.' });
      return null;
    }
    throw err;
  }
  if (inst.suspended_at) {
    res.status(409).json({ error: 'Your code home connection is not working: the app is suspended on GitHub.' });
    return null;
  }

  let org: string = row.account_login;
  if (typeof inst.account?.login === 'string' && inst.account.login !== org) {
    await db.query('UPDATE github_installation SET account_login = $2 WHERE id = $1', [row.id, inst.account.login]);
    await appendAccountEvent(creator.userId, 'system', 'github-app', 'github.organization_renamed', { installation_id: installationId, from: org, to: inst.account.login });
    org = inst.account.login;
  }

  // Fail closed: without a confirmed owner there is nothing to check against, so nothing is done.
  if (!row.owner_id) {
    res.status(403).json({ error: 'This code home has no confirmed owner. Connect it again.' });
    return null;
  }
  const owner = await withInstallationToken(config, installationId, { permissions: { members: 'read' } }, async (token) => {
    const auth = { kind: 'token' as const, token };
    // The owner's current login, from their permanent GitHub user id (a login can be renamed or re-registered).
    const user = await gh(config, auth, 'GET', `/user/${Number(row.owner_id)}`).catch((err) => {
      if (err instanceof GitHubError && err.status === 404) return null;
      throw err;
    });
    if (!user?.login) return null;
    const membership = await gh(config, auth, 'GET', `/orgs/${encodeURIComponent(org)}/memberships/${encodeURIComponent(user.login)}`).catch((err) => {
      if (err instanceof GitHubError && err.status === 404) return null;
      throw err;
    });
    return membership?.state === 'active' && membership?.role === 'admin' && Number(membership?.user?.id) === Number(row.owner_id) ? String(user.login) : null;
  });
  if (!owner) {
    res.status(403).json({ error: `The GitHub account that connected this code home (${row.owner_login}) is no longer an owner of ${org}.` });
    return null;
  }
  if (owner !== row.owner_login) await db.query('UPDATE github_installation SET owner_login = $2 WHERE id = $1', [row.id, owner]);
  return { installationId, org };
}
