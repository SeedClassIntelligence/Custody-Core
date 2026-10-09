import crypto from 'node:crypto';
import fs from 'node:fs';

/**
 * Custody Core's GitHub App. The creator installs it on their organization once; after that the server acts
 * for them with short-lived installation tokens, and developers never receive any GitHub credential.
 *
 * Settings (server only):
 *   GITHUB_APP_ID, GITHUB_APP_SLUG             from the App's settings page
 *   GITHUB_APP_PRIVATE_KEY                     the App's private key (PEM text, or a path to the .pem file)
 *   GITHUB_APP_CLIENT_ID, GITHUB_APP_CLIENT_SECRET   used once per installation to prove who installed it
 * GITHUB_API_URL, GITHUB_WEB_URL and GITHUB_GIT_URL default to github.com; tests point them at a local stand-in.
 */
export interface GitHubConfig {
  appId: string;
  slug: string;
  privateKey: string;
  clientId: string;
  clientSecret: string;
  apiUrl: string;
  webUrl: string;
  gitUrl: string;
}

export class GitHubNotConfigured extends Error {}
export class GitHubError extends Error {
  constructor(message: string, readonly status: number) {
    super(message);
  }
}

const trimSlash = (s: string) => s.replace(/\/+$/, '');

export function githubConfig(): GitHubConfig | null {
  const env = process.env;
  const appId = env.GITHUB_APP_ID?.trim();
  const slug = env.GITHUB_APP_SLUG?.trim();
  let privateKey = env.GITHUB_APP_PRIVATE_KEY?.trim();
  const clientId = env.GITHUB_APP_CLIENT_ID?.trim();
  const clientSecret = env.GITHUB_APP_CLIENT_SECRET?.trim();
  if (!appId || !slug || !privateKey || !clientId || !clientSecret) return null;
  if (!privateKey.includes('-----BEGIN')) privateKey = fs.readFileSync(privateKey, 'utf8');
  // Hosts that cannot hold multi-line values often store the key with literal "\n".
  privateKey = privateKey.replace(/\\n/g, '\n');
  return {
    appId,
    slug,
    privateKey,
    clientId,
    clientSecret,
    apiUrl: trimSlash(env.GITHUB_API_URL || 'https://api.github.com'),
    webUrl: trimSlash(env.GITHUB_WEB_URL || 'https://github.com'),
    gitUrl: trimSlash(env.GITHUB_GIT_URL || 'https://github.com')
  };
}

function requireConfig(): GitHubConfig {
  const config = githubConfig();
  if (!config) throw new GitHubNotConfigured('The GitHub App is not set up on this server (GITHUB_APP_* settings).');
  return config;
}

/** The App's own identity: a JWT signed with its private key, valid for 9 minutes (GitHub allows 10). */
export function appJwt(config = requireConfig(), now = Date.now()): string {
  const iat = Math.floor(now / 1000) - 60; // allow for clock drift
  const enc = (o: object) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const unsigned = `${enc({ alg: 'RS256', typ: 'JWT' })}.${enc({ iat, exp: iat + 600 - 60, iss: config.appId })}`;
  const signature = crypto.createSign('RSA-SHA256').update(unsigned).sign(config.privateKey).toString('base64url');
  return `${unsigned}.${signature}`;
}

async function call(url: string, init: RequestInit & { token?: string; bearer?: string } = {}): Promise<any> {
  const headers = new Headers(init.headers);
  headers.set('Accept', 'application/vnd.github+json');
  headers.set('X-GitHub-Api-Version', '2022-11-28');
  headers.set('User-Agent', 'custody-core');
  if (init.bearer) headers.set('Authorization', `Bearer ${init.bearer}`);
  if (init.body && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json');
  let res: Response;
  try {
    res = await fetch(url, { ...init, headers, signal: AbortSignal.timeout(15000) });
  } catch (err: any) {
    throw new GitHubError(`GitHub could not be reached (${err?.message ?? err}).`, 502);
  }
  const text = await res.text();
  let body: any = null;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    body = null;
  }
  if (!res.ok) {
    throw new GitHubError(`GitHub answered ${res.status}${body?.message ? `: ${body.message}` : ''}.`, res.status);
  }
  return body;
}

export interface Installation {
  id: number;
  account_login: string;
  account_type: string;
}

export async function getInstallation(installationId: number): Promise<Installation> {
  const config = requireConfig();
  const body = await call(`${config.apiUrl}/app/installations/${installationId}`, { bearer: appJwt(config) });
  return { id: Number(body.id), account_login: String(body.account?.login ?? ''), account_type: String(body.account?.type ?? '') };
}

// Installation tokens last an hour; one is kept per installation and repository until 5 minutes before expiry.
const tokenCache = new Map<string, { token: string; expiresAt: number }>();

/**
 * A token for one installation, limited to one repository (or to every repository the installation can see
 * when repo is omitted), with only the permissions asked for.
 */
export async function installationToken(
  installationId: number,
  repo?: string,
  permissions: Record<string, 'read' | 'write'> = { contents: 'write', metadata: 'read' }
): Promise<string> {
  const key = `${installationId}|${repo ?? '*'}|${JSON.stringify(permissions)}`;
  const cached = tokenCache.get(key);
  if (cached && cached.expiresAt - Date.now() > 5 * 60 * 1000) return cached.token;
  const config = requireConfig();
  const body = await call(`${config.apiUrl}/app/installations/${installationId}/access_tokens`, {
    method: 'POST',
    bearer: appJwt(config),
    body: JSON.stringify({ ...(repo ? { repositories: [repo] } : {}), permissions })
  });
  const token = String(body.token);
  tokenCache.set(key, { token, expiresAt: Date.parse(body.expires_at) || Date.now() + 50 * 60 * 1000 });
  return token;
}

/** Forgets cached installation tokens (for an installation, or all). */
export function forgetInstallationTokens(installationId?: number) {
  for (const key of tokenCache.keys()) if (installationId === undefined || key.startsWith(`${installationId}|`)) tokenCache.delete(key);
}

export interface GitHubRepository {
  id: number;
  full_name: string;
  default_branch: string;
  private: boolean;
}

/** Repositories the installation can see (up to 1,000). */
export async function installationRepositories(installationId: number): Promise<GitHubRepository[]> {
  const config = requireConfig();
  const token = await installationToken(installationId, undefined, { metadata: 'read' });
  const out: GitHubRepository[] = [];
  for (let page = 1; page <= 10; page++) {
    const body = await call(`${config.apiUrl}/installation/repositories?per_page=100&page=${page}`, { bearer: token });
    const repos = Array.isArray(body?.repositories) ? body.repositories : [];
    for (const r of repos) {
      out.push({ id: Number(r.id), full_name: String(r.full_name), default_branch: String(r.default_branch || 'main'), private: !!r.private });
    }
    if (repos.length < 100) break;
  }
  return out;
}

/** Turns the one-time code GitHub sends after installation into the installing user's token. */
export async function exchangeOAuthCode(code: string): Promise<string> {
  const config = requireConfig();
  const body = await call(`${config.webUrl}/login/oauth/access_token`, {
    method: 'POST',
    headers: { Accept: 'application/json' },
    body: JSON.stringify({ client_id: config.clientId, client_secret: config.clientSecret, code })
  });
  if (!body?.access_token) {
    throw new GitHubError(`GitHub did not accept the sign-in code${body?.error_description ? `: ${body.error_description}` : ''}.`, 400);
  }
  return String(body.access_token);
}

/** The GitHub user behind a user token, and whether that user can access the installation. */
export async function userCanAccessInstallation(userToken: string, installationId: number): Promise<{ login: string; allowed: boolean }> {
  const config = requireConfig();
  const user = await call(`${config.apiUrl}/user`, { bearer: userToken });
  for (let page = 1; page <= 10; page++) {
    const body = await call(`${config.apiUrl}/user/installations?per_page=100&page=${page}`, { bearer: userToken });
    const list = Array.isArray(body?.installations) ? body.installations : [];
    if (list.some((i: any) => Number(i.id) === installationId)) return { login: String(user.login), allowed: true };
    if (list.length < 100) break;
  }
  return { login: String(user.login), allowed: false };
}

/** The https git address of a repository, without any credential in it. */
export function upstreamGitUrl(fullName: string): string {
  return `${requireConfig().gitUrl}/${fullName}.git`;
}

/** The HTTP header git sends to GitHub with an installation token (kept out of URLs and config files). */
export function gitAuthHeader(token: string): string {
  return `Authorization: Basic ${Buffer.from(`x-access-token:${token}`).toString('base64')}`;
}

/** A REST call to GitHub's API with an installation token. Throws GitHubError on any non-2xx answer. */
export async function githubApi(method: string, apiPath: string, token: string, body?: unknown): Promise<any> {
  const config = requireConfig();
  return call(`${config.apiUrl}${apiPath}`, {
    method,
    bearer: token,
    ...(body !== undefined ? { body: JSON.stringify(body) } : {})
  });
}

/** The App's numeric id (what a ruleset names as the actor allowed to bypass it). */
export function githubAppId(): number {
  return Number(requireConfig().appId);
}
