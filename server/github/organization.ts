import { gh, GitHubConfig, GitHubError, withInstallationToken } from './app';

/**
 * Locks a creator's GitHub organization, then reads every setting back from GitHub. What is recorded is what
 * GitHub reports afterwards, not what was asked for.
 */

export const ORG_LOCK: Record<string, unknown> = {
  // Members see no repository unless given access to it.
  default_repository_permission: 'none',
  // Members cannot create repositories (of any visibility).
  members_can_create_repositories: false,
  members_can_create_public_repositories: false,
  members_can_create_private_repositories: false,
  // Private repositories cannot be forked.
  members_can_fork_private_repositories: false
};

export interface SettingResult {
  setting: string;
  requested: unknown;
  /** GitHub's value after the change; null when GitHub did not report the field */
  reported: unknown;
  applied: boolean;
}

export interface OrgLockResult {
  organization: string;
  /** GitHub's plan name for the organization (free, team, ...), when GitHub reports it */
  plan: string | null;
  /** GitHub's answer to the change itself, if it refused it */
  change_error: { status: number; message: string } | null;
  settings: SettingResult[];
  all_applied: boolean;
}

export function compareSettings(requested: Record<string, unknown>, reported: any): SettingResult[] {
  return Object.entries(requested).map(([setting, want]) => {
    const got = reported && Object.prototype.hasOwnProperty.call(reported, setting) ? reported[setting] : null;
    return { setting, requested: want, reported: got, applied: got === want };
  });
}

export async function lockOrganization(config: GitHubConfig, installationId: number, org: string): Promise<OrgLockResult> {
  return withInstallationToken(config, installationId, { permissions: { organization_administration: 'write' } }, async (token) => {
    const auth = { kind: 'token' as const, token };
    let changeError: OrgLockResult['change_error'] = null;
    try {
      await gh(config, auth, 'PATCH', `/orgs/${encodeURIComponent(org)}`, ORG_LOCK);
    } catch (err) {
      if (!(err instanceof GitHubError)) throw err;
      changeError = { status: err.status, message: String(err.body?.message ?? err.message) };
    }
    // Always read back, whether or not the change was accepted.
    const reported = await gh(config, auth, 'GET', `/orgs/${encodeURIComponent(org)}`);
    const settings = compareSettings(ORG_LOCK, reported);
    return {
      organization: org,
      plan: typeof reported?.plan?.name === 'string' ? reported.plan.name : null,
      change_error: changeError,
      settings,
      all_applied: settings.every((s) => s.applied)
    };
  });
}
