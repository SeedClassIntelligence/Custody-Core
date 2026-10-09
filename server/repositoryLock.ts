import { GitHubError, githubApi, githubAppId, installationToken } from './github';

/**
 * Locks a repository on GitHub, then reads the lock back and checks it.
 *
 * The lock is a repository ruleset named "Custody Core lock" on the default branch with two rules: the branch
 * cannot be deleted, and cannot be force-pushed. Only the Custody Core GitHub App may bypass it. Forking is
 * turned off where GitHub allows it (private repositories of an organization). Organization owners can still
 * remove a ruleset on GitHub; every check reads it back, so that is noticed and recorded.
 *
 * Needs the App permission "Administration: Read and write". Rulesets on private repositories need a paid GitHub
 * plan (Pro, Team or Enterprise); on the free plan GitHub refuses, and the repository stays unlocked with that reason.
 */

export const LOCK_NAME = 'Custody Core lock';
const RULES = ['deletion', 'non_fast_forward'];

export interface LockResult {
  locked: boolean;
  ruleset_id: number | null;
  /** false when forking is off; null when GitHub has no setting for this repository (public, or personal account) */
  allow_forking: boolean | null;
  /** In words, for the creator, when not locked. */
  error: string | null;
  /** What was found before this check: used to record a lock that was removed or changed on GitHub. */
  previous: 'none' | 'intact' | 'changed';
}

function lockBody(appId: number) {
  return {
    name: LOCK_NAME,
    target: 'branch',
    enforcement: 'active',
    bypass_actors: [{ actor_id: appId, actor_type: 'Integration', bypass_mode: 'always' }],
    conditions: { ref_name: { include: ['~DEFAULT_BRANCH'], exclude: [] } },
    rules: RULES.map((type) => ({ type }))
  };
}

/** True when a ruleset read back from GitHub is exactly the lock: active, default branch, both rules, only the App bypasses. */
export function isIntactLock(ruleset: any, appId: number): boolean {
  if (!ruleset || ruleset.enforcement !== 'active' || ruleset.target !== 'branch') return false;
  const include: string[] = ruleset.conditions?.ref_name?.include ?? [];
  const exclude: string[] = ruleset.conditions?.ref_name?.exclude ?? [];
  if (!include.includes('~DEFAULT_BRANCH') || exclude.length > 0) return false;
  const types = new Set((ruleset.rules ?? []).map((r: any) => r.type));
  if (!RULES.every((t) => types.has(t))) return false;
  const bypass = ruleset.bypass_actors ?? [];
  return bypass.every((b: any) => b.actor_type === 'Integration' && Number(b.actor_id) === appId);
}

function explain(err: unknown): string {
  if (err instanceof GitHubError) {
    const m = err.message;
    if (/upgrade to github pro|make this repository public|not available for this repository/i.test(m)) {
      return [
        'Not locked on GitHub: GitHub only allows this lock on private repositories with a paid plan (Pro, Team or Enterprise).',
        'Developers you give a door still cannot reach this code on GitHub: they get no GitHub access, only a gateway credential,',
        'and the gateway only accepts their pushes to their own door branches.',
        'The GitHub lock is an extra layer against changes made directly on GitHub by people who do have GitHub access',
        '(organization members and outside collaborators): without it, they can delete or force-push the default branch there.',
        'To add it, upgrade the organization\'s plan, then press lock.'
      ].join(' ');
    }
    if (/not granted to this installation|resource not accessible by integration/i.test(m) || err.status === 403) {
      return 'The GitHub App does not have the "Administration: Read and write" permission on this repository. Accept the updated permissions on GitHub (organization settings > GitHub Apps), then check the lock again.';
    }
    if (err.status === 404) return 'GitHub says the repository does not exist or the App cannot see it.';
    return `GitHub refused: ${m}`;
  }
  return 'GitHub could not be reached.';
}

export async function lockRepository(installationId: number, fullName: string): Promise<LockResult> {
  const appId = githubAppId();
  const repoPath = `/repos/${fullName.split('/').map(encodeURIComponent).join('/')}`;
  let previous: LockResult['previous'] = 'none';
  try {
    const token = await installationToken(installationId, fullName.split('/')[1], { administration: 'write', metadata: 'read' });

    // 1. The ruleset: update ours if it is there (whatever someone did to it), else create it.
    const existing = ((await githubApi('GET', `${repoPath}/rulesets?includes_parents=false&per_page=100`, token)) ?? [])
      .filter((r: any) => r.name === LOCK_NAME && (r.source_type ?? 'Repository') === 'Repository');
    let rulesetId: number;
    if (existing.length > 0) {
      rulesetId = Number(existing[0].id);
      const current = await githubApi('GET', `${repoPath}/rulesets/${rulesetId}`, token);
      previous = isIntactLock(current, appId) ? 'intact' : 'changed';
      if (previous === 'changed') await githubApi('PUT', `${repoPath}/rulesets/${rulesetId}`, token, lockBody(appId));
    } else {
      rulesetId = Number((await githubApi('POST', `${repoPath}/rulesets`, token, lockBody(appId))).id);
    }

    // 2. Forking off, where the repository has the setting.
    let repo = await githubApi('GET', repoPath, token);
    if (repo.private && typeof repo.allow_forking === 'boolean' && repo.allow_forking) {
      try {
        repo = await githubApi('PATCH', repoPath, token, { allow_forking: false });
      } catch (err) {
        // An organization that does not allow forking private repositories at all has nothing to turn off.
        if (!(err instanceof GitHubError && err.status === 422)) throw err;
      }
      repo = await githubApi('GET', repoPath, token);
    }

    // 3. Read back. Only what GitHub reports now counts.
    const readBack = await githubApi('GET', `${repoPath}/rulesets/${rulesetId}`, token);
    if (!isIntactLock(readBack, appId)) {
      return { locked: false, ruleset_id: rulesetId, allow_forking: null, error: 'GitHub did not keep the ruleset as set. Check the lock again.', previous };
    }
    const allowForking = repo.private && typeof repo.allow_forking === 'boolean' ? repo.allow_forking : null;
    return { locked: true, ruleset_id: rulesetId, allow_forking: allowForking, error: null, previous };
  } catch (err) {
    return { locked: false, ruleset_id: null, allow_forking: null, error: explain(err), previous };
  }
}
