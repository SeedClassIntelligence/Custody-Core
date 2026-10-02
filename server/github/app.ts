import { createPrivateKey, createSign, KeyObject } from 'node:crypto';

/**
 * The GitHub App, server side only.
 *
 *   GITHUB_APP_ID            numeric app id (App settings > General > "App ID")
 *   GITHUB_APP_SLUG          the app's URL name (github.com/apps/<slug>)
 *   GITHUB_APP_CLIENT_ID     for the one-time "who installed it" check after installation
 *   GITHUB_APP_CLIENT_SECRET
 *   GITHUB_APP_PRIVATE_KEY   the .pem file's contents (newlines may be written as \n)
 *   GITHUB_WEBHOOK_SECRET    checks that webhooks really come from GitHub
 *
 * None of these may have a VITE_ prefix; tests/bundle.test.ts proves they are not in the browser bundle.
 *
 * Tokens: the app's own login (a JWT, 9 minutes) is made per request. Installation tokens are requested per
 * operation, narrowed to the repositories and permissions that operation needs, used, and revoked. Neither is
 * ever stored or logged.
 */

export class GitHubNotConfigured extends Error {}

export interface GitHubConfig {
  appId: string;
  slug: string;
  clientId: string;
  clientSecret: string;
  privateKey: KeyObject;
  webhookSecret: string;
  /** https://api.github.com, or a loopback stand-in in tests */
  apiUrl: string;
  /** https://github.com (OAuth, install pages, git), or a loopback stand-in in tests */
  webUrl: string;
}

const LOOPBACK = /^http:\/\/(127\.0\.0\.1|localhost):\d+$/;

/** The GitHub endpoints. Anything other than GitHub itself is only accepted on this machine (tests). */
function endpoint(name: string, real: string): string {
  const value = (process.env[name] || real).replace(/\/+$/, '');
  if (value !== real && !LOOPBACK.test(value)) {
    throw new GitHubNotConfigured(`${name} must be ${real} (or a local test address).`);
  }
  return value;
}

export function githubConfig(): GitHubConfig {
  const missing = ['GITHUB_APP_ID', 'GITHUB_APP_SLUG', 'GITHUB_APP_CLIENT_ID', 'GITHUB_APP_CLIENT_SECRET', 'GITHUB_APP_PRIVATE_KEY', 'GITHUB_WEBHOOK_SECRET'].filter(
    (k) => !process.env[k]
  );
  if (missing.length) throw new GitHubNotConfigured(`The GitHub App is not configured on the server (missing ${missing.join(', ')}).`);
  if (!/^\d+$/.test(process.env.GITHUB_APP_ID!)) throw new GitHubNotConfigured('GITHUB_APP_ID must be the numeric App ID.');
  let privateKey: KeyObject;
  try {
    privateKey = createPrivateKey(process.env.GITHUB_APP_PRIVATE_KEY!.replace(/\\n/g, '\n'));
  } catch {
    throw new GitHubNotConfigured('GITHUB_APP_PRIVATE_KEY is not a valid private key (paste the whole .pem file).');
  }
  return {
    appId: process.env.GITHUB_APP_ID!,
    slug: process.env.GITHUB_APP_SLUG!,
    clientId: process.env.GITHUB_APP_CLIENT_ID!,
    clientSecret: process.env.GITHUB_APP_CLIENT_SECRET!,
    privateKey,
    webhookSecret: process.env.GITHUB_WEBHOOK_SECRET!,
    apiUrl: endpoint('GITHUB_API_URL', 'https://api.github.com'),
    webUrl: endpoint('GITHUB_WEB_URL', 'https://github.com')
  };
}

export function isGitHubConfigured(): boolean {
  try {
    githubConfig();
    return true;
  } catch {
    return false;
  }
}

const b64url = (v: Buffer | string) => Buffer.from(v).toString('base64url');

/** The app's own short login (RS256 JWT), as GitHub specifies: issued 60 s in the past, valid for 9 minutes. */
export function appJwt(config: GitHubConfig, nowMs = Date.now()): string {
  const now = Math.floor(nowMs / 1000);
  const header = b64url(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
  const payload = b64url(JSON.stringify({ iat: now - 60, exp: now + 9 * 60, iss: config.appId }));
  const signer = createSign('RSA-SHA256');
  signer.update(`${header}.${payload}`);
  return `${header}.${payload}.${b64url(signer.sign(config.privateKey))}`;
}

export class GitHubError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly body: any
  ) {
    super(message);
  }
}

/** Calls the GitHub REST API. `auth` is a token string, or null. Throws GitHubError on any non-2xx answer. */
export async function gh(config: GitHubConfig, auth: { kind: 'app' | 'token'; token: string } | null, method: string, path: string, body?: unknown): Promise<any> {
  const headers: Record<string, string> = {
    Accept: 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
    'User-Agent': `custody-core-${config.slug}`
  };
  if (auth) headers.Authorization = `Bearer ${auth.token}`;
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  const res = await fetch(`${config.apiUrl}${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
    signal: AbortSignal.timeout(20_000)
  });
  const text = await res.text();
  let parsed: any = null;
  try {
    parsed = text ? JSON.parse(text) : null;
  } catch {
    parsed = { message: text.slice(0, 500) };
  }
  if (!res.ok) {
    // The message is GitHub's own; it never contains our tokens.
    throw new GitHubError(`GitHub answered ${res.status} to ${method} ${path.split('?')[0]}: ${parsed?.message ?? 'no message'}`, res.status, parsed);
  }
  return parsed;
}

export type Permissions = Partial<Record<'administration' | 'contents' | 'pull_requests' | 'metadata' | 'organization_administration', 'read' | 'write'>>;

/**
 * A short-lived installation token for one operation, narrowed to `repositories` (names in the installation's
 * account) and `permissions`. Use it inside `work` only; it is never returned, stored or logged, and it is
 * revoked as soon as `work` finishes.
 */
export async function withInstallationToken<T>(
  config: GitHubConfig,
  installationId: number | string,
  scope: { repositories?: string[]; permissions: Permissions },
  work: (token: string) => Promise<T>
): Promise<T> {
  const body: Record<string, unknown> = { permissions: scope.permissions };
  if (scope.repositories) body.repositories = scope.repositories;
  const issued = await gh(config, { kind: 'app', token: appJwt(config) }, 'POST', `/app/installations/${Number(installationId)}/access_tokens`, body);
  try {
    return await work(issued.token);
  } finally {
    // Revoke it now rather than letting it live out its hour. A failure here is logged without the token.
    await gh(config, { kind: 'token', token: issued.token }, 'DELETE', '/installation/token').catch((err: any) =>
      console.warn('[github] could not revoke an installation token:', err?.status ?? err?.message)
    );
  }
}
