import { GitHubError, GitHubNotConfigured, appJwt, githubAppApi, githubConfig, installationRepositories, installationToken } from './github';

/**
 * Is the GitHub App still in place? (docs/GITHUB_APP_SETUP.md)
 *
 * Asks GitHub, as the App itself, whether the App this server is configured with exists and accepts its key, whether it asks for the permissions
 * Custody Core needs, and, for every organization that installed it, whether the installation is active, has those permissions (an organization has to
 * accept a permission added later) and can actually mint a working token. Never prints or returns a secret.
 * It cannot see the App's callback URL, its "request user authorization" switch or whether the client secret is still valid: GitHub does not
 * expose them to the App, so those are listed as things to look at on the App's settings page.
 */

export type Level = 'pass' | 'warn' | 'fail';
export interface Finding {
  level: Level;
  what: string;
  detail?: string;
}

/** What Custody Core needs the App to be allowed to do, and why. */
export const REQUIRED_PERMISSIONS: Array<{ name: string; level: 'read' | 'write'; why: string }> = [
  { name: 'contents', level: 'write', why: 'to fetch repositories, and to push session and door branches and promoted commits' },
  { name: 'metadata', level: 'read', why: 'GitHub always requires it' },
  { name: 'administration', level: 'write', why: 'to put the lock (a ruleset) on each repository and turn off forking' }
];

const RANK: Record<string, number> = { read: 1, write: 2, admin: 3 };
const enough = (have: unknown, need: 'read' | 'write') => typeof have === 'string' && (RANK[have] ?? 0) >= RANK[need];

const ENV_NAMES = ['GITHUB_APP_ID', 'GITHUB_APP_SLUG', 'GITHUB_APP_PRIVATE_KEY', 'GITHUB_APP_CLIENT_ID', 'GITHUB_APP_CLIENT_SECRET'];

function words(err: unknown): string {
  if (err instanceof GitHubError) return err.message; // GitHub's own words, never ours with a secret in them
  return 'an unexpected error';
}

export async function checkGitHubApp(): Promise<Finding[]> {
  const out: Finding[] = [];
  const add = (level: Level, what: string, detail?: string) => out.push({ level, what, ...(detail ? { detail } : {}) });

  // 1. the settings are there, and the key can sign
  const missing = ENV_NAMES.filter((n) => !process.env[n]?.trim());
  if (missing.length > 0) {
    add('fail', 'The server is not configured with the GitHub App', `Missing: ${missing.join(', ')}. Set them where the server runs (see docs/GITHUB_APP_SETUP.md, section 2).`);
    return out;
  }
  let config;
  try {
    config = githubConfig();
    if (!config) throw new GitHubNotConfigured('missing');
    appJwt(config); // signs with the private key
  } catch {
    add('fail', 'The private key cannot be used', 'GITHUB_APP_PRIVATE_KEY is not a readable RSA private key (PEM text with literal \\n for line breaks, or a path to the .pem file). Generate a new key on the App\'s settings page and set it again.');
    return out;
  }
  add('pass', 'All five GITHUB_APP_* settings are present and the private key can sign');

  // 2. the App exists and accepts this key
  let app: any;
  try {
    app = await githubAppApi('/app');
  } catch (err) {
    if (err instanceof GitHubError && (err.status === 401 || err.status === 404)) {
      add('fail', 'GitHub does not accept this App ID with this private key', `${words(err)} The key may have been deleted on the App's settings page, belong to another App, or the App ID is wrong. Generate a new private key and set GITHUB_APP_PRIVATE_KEY again.`);
    } else {
      add('fail', 'GitHub could not be asked', `${words(err)} Check the server's network, then run this again.`);
    }
    return out;
  }
  add('pass', `The App exists and accepts its key: "${app.name}" (id ${app.id}, ${app.slug})`);
  if (String(app.id) !== config.appId) add('warn', 'GITHUB_APP_ID is not the App\'s id', `GitHub says ${app.id}; the server has ${config.appId}.`);
  if (String(app.slug) !== config.slug) add('warn', 'GITHUB_APP_SLUG is not the App\'s name in its address', `GitHub says "${app.slug}"; the server has "${config.slug}". The Connect GitHub button sends people to the wrong address.`);

  // 3. what the App asks for
  let appOk = true;
  for (const p of REQUIRED_PERMISSIONS) {
    if (!enough(app.permissions?.[p.name], p.level)) {
      appOk = false;
      add('fail', `The App does not ask for "${p.name}: ${p.level}"`, `It is needed ${p.why}. On the App's settings page, under Permissions, set ${p.name} to ${p.level === 'write' ? 'Read and write' : 'Read-only'}; each organization that installed the App is then asked to accept it.`);
    }
  }
  if (appOk) add('pass', 'The App asks for the permissions Custody Core needs (contents write, metadata read, administration write)');

  // 4. the installations
  let installs: any[] = [];
  try {
    for (let page = 1; page <= 10; page++) {
      const batch = await githubAppApi(`/app/installations?per_page=100&page=${page}`);
      installs = installs.concat(batch);
      if (batch.length < 100) break;
    }
  } catch (err) {
    add('fail', 'The installations could not be listed', words(err));
    return out;
  }
  if (installs.length === 0) {
    add('warn', 'No organization has installed the App yet', 'That is normal before the first creator presses Connect GitHub in Custody Core.');
  }
  for (const i of installs) {
    const who = `${i.account?.login ?? 'unknown'} (installation ${i.id})`;
    if (i.suspended_at) {
      add('warn', `Installation ${who} is suspended`, 'GitHub is not letting the App act there. The organization\'s owner can unsuspend it in the organization\'s settings, under GitHub Apps.');
      continue;
    }
    const short = REQUIRED_PERMISSIONS.filter((p) => enough(app.permissions?.[p.name], p.level) && !enough(i.permissions?.[p.name], p.level));
    if (short.length > 0) {
      add('warn', `Installation ${who} has not accepted: ${short.map((p) => `${p.name} ${p.level}`).join(', ')}`, 'The permission was added to the App after the organization installed it. An owner accepts it in the organization\'s settings, under GitHub Apps, Custody Core, review request. Until then, locking repositories (and anything else that needs it) is refused there.');
    }
    try {
      const token = await installationToken(Number(i.id));
      const repos = await installationRepositories(Number(i.id));
      void token;
      add('pass', `Installation ${who} works: a token can be made and it can see ${repos.length} repositor${repos.length === 1 ? 'y' : 'ies'} (${i.repository_selection === 'all' ? 'all of them' : 'the ones chosen'})`);
    } catch (err) {
      add('fail', `Installation ${who} cannot be used`, `${words(err)} The organization may have removed the App or its access.`);
    }
  }

  // 5. what GitHub does not tell the App
  add('warn', 'Not checkable from here: look at these on the App\'s settings page', 'Callback URL = your address + /github/callback; "Request user authorization (OAuth) during installation" = on; Webhook active = off; the client secret is the current one.');
  return out;
}
