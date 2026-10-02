import http from 'node:http';
import { spawn, spawnSync } from 'node:child_process';
import { createPublicKey, createVerify, generateKeyPairSync, randomBytes } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

/**
 * A local stand-in for the parts of GitHub that Custody Core calls, for unit and integration tests ONLY.
 * The end-to-end run (scripts/github-e2e.ts) uses real GitHub.
 *
 * It is strict where mistakes would matter: the app's JWT is verified with the app's public key; installation
 * tokens carry exactly the repositories and permissions requested and every call is checked against them;
 * tokens can be revoked; a free organization refuses rulesets on private repositories with GitHub's message;
 * and git pushes go to real bare repositories through `git http-backend`.
 */

type Perm = 'read' | 'write';
interface IssuedToken {
  token: string;
  installationId: number;
  repositories: string[] | null;
  permissions: Record<string, Perm>;
  revoked: boolean;
}
interface Org {
  login: string;
  id: number;
  plan: 'free' | 'team';
  settings: Record<string, unknown>;
  owners: Set<string>;
  members: Set<string>;
  /** When set, PATCH /orgs answers this instead of applying (to test honest recording). */
  refusePatch?: { status: number; message: string };
}
interface Repo {
  id: number;
  org: string;
  name: string;
  private: boolean;
  allow_forking: boolean;
  default_branch: string;
  rulesets: any[];
  bare: string;
  description: string;
  created_at: string;
}

export interface StandIn {
  url: string;
  appId: string;
  slug: string;
  clientId: string;
  clientSecret: string;
  privateKeyPem: string;
  orgs: Map<string, Org>;
  repos: Map<string, Repo>;
  installations: Map<number, { org: string; appId: string; suspendedAt?: string | null }>;
  tokens: IssuedToken[];
  userTokens: Map<string, { login: string; revoked: boolean }>;
  calls: Array<{ method: string; path: string; auth: string }>;
  addOrg(login: string, opts?: { plan?: 'free' | 'team'; owners?: string[]; members?: string[] }): Org;
  install(org: string, opts?: { appId?: string }): number;
  /** What GitHub does when a user clicks Authorize: a one-time code for that user. */
  authorizeCode(login: string): string;
  /**
   * For a browser test: who is "signed in to GitHub", which organization they install on, and where the app's
   * setup URL points. The install page and the authorize page then behave like GitHub's (redirecting back).
   */
  browser: { login: string; org: string; setupUrl: string } | null;
  /** The permissions the app was registered with (docs/GITHUB_APP_SETUP.md). Tokens can never exceed these. */
  appPermissions: Record<string, 'read' | 'write'>;
  /** Refuse every git push (to test a failure after a repository was created). */
  refusePushes: boolean;
  /** Answer 500 to reading a repository (to test a GitHub failure after creating one). */
  failRepoRead: boolean;
  /** Answer 500 to reading an organization (to test a failed organization lock). */
  failOrgRead: boolean;
  /** Report file trees as truncated, as GitHub does for very large trees. */
  truncateTrees: boolean;
  /** Create the repository but lose GitHub's answer (502), as when a response times out. */
  loseCreateAnswer: boolean;
  /** Uninstall / suspend / unsuspend the app on an organization, as an owner would on GitHub. */
  uninstall(id: number): void;
  suspend(id: number, suspended: boolean): void;
  /** Rename an organization, as an owner would on GitHub (its id stays the same). */
  renameOrg(from: string, to: string): void;
  stop(): Promise<void>;
}

const LIKE_GITHUB_FREE_PRIVATE_RULESETS = 'Upgrade to GitHub Team or make this repository public to enable this feature.';

export async function startGitHubStandIn(): Promise<StandIn> {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const pub = createPublicKey(publicKey.export({ type: 'spki', format: 'pem' }));
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gh-standin-'));
  const s = {
    appId: String(100000 + Math.floor(Math.random() * 800000)),
    slug: 'custody-core-test',
    clientId: `Iv1.${randomBytes(8).toString('hex')}`,
    clientSecret: randomBytes(20).toString('hex'),
    privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    orgs: new Map<string, Org>(),
    repos: new Map<string, Repo>(),
    installations: new Map<number, { org: string; appId: string; suspendedAt?: string | null }>(),
    tokens: [] as IssuedToken[],
    userTokens: new Map<string, { login: string; revoked: boolean }>(),
    codes: new Map<string, string>(),
    calls: [] as Array<{ method: string; path: string; auth: string }>
  };
  let nextId = 5000;

  const send = (res: http.ServerResponse, status: number, body?: unknown) => {
    res.writeHead(status, { 'Content-Type': 'application/json' });
    res.end(body === undefined ? '' : JSON.stringify(body));
  };
  const readBody = (req: http.IncomingMessage) =>
    new Promise<Buffer>((resolve) => {
      const chunks: Buffer[] = [];
      req.on('data', (c) => chunks.push(c));
      req.on('end', () => resolve(Buffer.concat(chunks)));
    });

  function verifyAppJwt(token: string): boolean {
    const [h, p, sig] = token.split('.');
    if (!h || !p || !sig) return false;
    const v = createVerify('RSA-SHA256');
    v.update(`${h}.${p}`);
    if (!v.verify(pub, Buffer.from(sig, 'base64url'))) return false;
    const claims = JSON.parse(Buffer.from(p, 'base64url').toString());
    const now = Math.floor(Date.now() / 1000);
    return claims.iss === s.appId && claims.exp > now && claims.iat <= now && claims.exp - claims.iat <= 600;
  }

  const bearer = (req: http.IncomingMessage) => /^Bearer (.+)$/.exec(req.headers.authorization || '')?.[1] ?? '';
  const instToken = (req: http.IncomingMessage) => s.tokens.find((t) => t.token === bearer(req) && !t.revoked) ?? null;
  const can = (t: IssuedToken, perm: string, level: Perm) => t.permissions[perm] === 'write' || t.permissions[perm] === level;
  const coversRepo = (t: IssuedToken, org: string, name: string) =>
    s.installations.get(t.installationId)?.org === org && (t.repositories === null || t.repositories.includes(name));
  const repoView = (r: Repo) => ({
    id: r.id,
    name: r.name,
    full_name: `${r.org}/${r.name}`,
    private: r.private,
    visibility: r.private ? 'private' : 'public',
    allow_forking: r.allow_forking,
    default_branch: r.default_branch,
    html_url: `${url}/${r.org}/${r.name}`,
    description: r.description,
    created_at: r.created_at,
    // GitHub reports 0 for a repository with no commits yet
    size: spawnSync('git', ['-C', r.bare, 'rev-parse', '--verify', '-q', 'HEAD']).status === 0 ? 1 : 0
  });

  async function api(req: http.IncomingMessage, res: http.ServerResponse, p: string, body: any) {
    const m = req.method!;
    let match: RegExpExecArray | null;

    if (m === 'POST' && (match = /^\/app\/installations\/(\d+)\/access_tokens$/.exec(p))) {
      if (!verifyAppJwt(bearer(req))) return send(res, 401, { message: 'A JSON web token could not be decoded' });
      const inst = s.installations.get(Number(match[1]));
      if (!inst || inst.appId !== s.appId) return send(res, 404, { message: 'Not Found' });
      if (inst.suspendedAt) return send(res, 403, { message: 'This installation has been suspended' });
      const known = ['administration', 'contents', 'pull_requests', 'metadata', 'organization_administration', 'members'];
      const asked = Object.keys(body?.permissions ?? {});
      if (asked.some((k) => !known.includes(k))) return send(res, 422, { message: 'The permissions requested are not granted to this installation.' });
      // An installation token can never carry more than the app was granted.
      if (asked.some((k) => !handle.appPermissions[k] || (body.permissions[k] === 'write' && handle.appPermissions[k] !== 'write'))) {
        return send(res, 422, { message: 'The permissions requested are not granted to this installation.' });
      }
      const repositories: string[] | null = Array.isArray(body?.repositories) ? body.repositories : null;
      if (repositories && repositories.some((n) => !s.repos.has(`${inst.org}/${n}`))) return send(res, 422, { message: 'There is at least one repository that does not exist or is not accessible to the parent installation.' });
      const t: IssuedToken = { token: `ghs_${randomBytes(18).toString('hex')}`, installationId: Number(match[1]), repositories, permissions: body?.permissions ?? {}, revoked: false };
      s.tokens.push(t);
      return send(res, 201, { token: t.token, expires_at: new Date(Date.now() + 3600_000).toISOString(), permissions: t.permissions, repository_selection: repositories ? 'selected' : 'all' });
    }
    if (m === 'GET' && (match = /^\/app\/installations\/(\d+)$/.exec(p))) {
      if (!verifyAppJwt(bearer(req))) return send(res, 401, { message: 'A JSON web token could not be decoded' });
      const inst = s.installations.get(Number(match[1]));
      if (!inst || inst.appId !== s.appId) return send(res, 404, { message: 'Not Found' });
      const org = s.orgs.get(inst.org)!;
      return send(res, 200, { id: Number(match[1]), app_id: Number(inst.appId), suspended_at: inst.suspendedAt ?? null, account: { login: org.login, id: org.id, type: 'Organization' } });
    }
    if (m === 'GET' && p === '/installation/repositories') {
      const t = instToken(req);
      if (!t) return send(res, 401, { message: 'Bad credentials' });
      const org = s.installations.get(t.installationId)!.org;
      const list = [...s.repos.values()].filter((r) => r.org === org && (t.repositories === null || t.repositories.includes(r.name)));
      return send(res, 200, { total_count: list.length, repositories: list.map(repoView) });
    }
    if (m === 'DELETE' && p === '/installation/token') {
      const t = instToken(req);
      if (!t) return send(res, 401, { message: 'Bad credentials' });
      t.revoked = true;
      return send(res, 204);
    }
    if ((match = /^\/orgs\/([^/]+)$/.exec(p)) && (m === 'GET' || m === 'PATCH')) {
      const t = instToken(req);
      const org = s.orgs.get(decodeURIComponent(match[1]));
      if (!t || !org || s.installations.get(t.installationId)?.org !== org.login) return send(res, 404, { message: 'Not Found' });
      if (m === 'PATCH') {
        if (!can(t, 'organization_administration', 'write')) return send(res, 403, { message: 'Resource not accessible by integration' });
        if (org.refusePatch) return send(res, org.refusePatch.status, { message: org.refusePatch.message });
        Object.assign(org.settings, body);
      }
      if (handle.failOrgRead) return send(res, 500, { message: 'Server Error' });
      const visible = can(t, 'organization_administration', 'read') ? { ...org.settings, plan: { name: org.plan } } : {};
      return send(res, 200, { login: org.login, id: org.id, type: 'Organization', ...visible });
    }
    if (m === 'POST' && (match = /^\/orgs\/([^/]+)\/repos$/.exec(p))) {
      const t = instToken(req);
      const org = s.orgs.get(decodeURIComponent(match[1]));
      if (!t || !org || s.installations.get(t.installationId)?.org !== org.login) return send(res, 404, { message: 'Not Found' });
      if (!can(t, 'administration', 'write')) return send(res, 403, { message: 'Resource not accessible by integration' });
      const key = `${org.login}/${body.name}`;
      if (s.repos.has(key)) return send(res, 422, { message: 'Repository creation failed.', errors: [{ message: 'name already exists on this account' }] });
      const bare = path.join(root, org.login, `${body.name}.git`);
      fs.mkdirSync(path.dirname(bare), { recursive: true });
      spawnSync('git', ['init', '-q', '--bare', '-b', 'main', bare]);
      spawnSync('git', ['-C', bare, 'config', 'http.receivepack', 'true']);
      // GitHub checks every pushed object and refuses broken or dangerous ones.
      spawnSync('git', ['-C', bare, 'config', 'receive.fsckObjects', 'true']);
      const repo: Repo = {
        id: nextId++,
        org: org.login,
        name: body.name,
        private: body.private !== false,
        allow_forking: !!org.settings.members_can_fork_private_repositories,
        default_branch: 'main',
        rulesets: [],
        bare,
        description: String(body.description ?? ''),
        created_at: new Date().toISOString()
      };
      s.repos.set(key, repo);
      if (handle.loseCreateAnswer) return send(res, 502, { message: 'Server Error' });
      return send(res, 201, repoView(repo));
    }
    if (m === 'GET' && (match = /^\/repositories\/(\d+)$/.exec(p))) {
      const t = instToken(req);
      if (!t) return send(res, 401, { message: 'Bad credentials' });
      const repo = [...s.repos.values()].find((r) => r.id === Number(match![1]));
      if (!repo || !coversRepo(t, repo.org, repo.name)) return send(res, 404, { message: 'Not Found' });
      return send(res, 200, repoView(repo));
    }
    if (m === 'GET' && (match = /^\/orgs\/([^/]+)\/memberships\/([^/]+)$/.exec(p))) {
      const t = instToken(req);
      const org = s.orgs.get(decodeURIComponent(match[1]));
      if (!t || !org || s.installations.get(t.installationId)?.org !== org.login) return send(res, 404, { message: 'Not Found' });
      if (!can(t, 'members', 'read')) return send(res, 403, { message: 'Resource not accessible by integration' });
      const login = decodeURIComponent(match[2]);
      if (!org.owners.has(login) && !org.members.has(login)) return send(res, 404, { message: 'Not Found' });
      return send(res, 200, { state: 'active', role: org.owners.has(login) ? 'admin' : 'member', user: { login } });
    }
    if ((match = /^\/repos\/([^/]+)\/([^/]+)(\/.*)?$/.exec(p))) {
      const [o, n, rest = ''] = [decodeURIComponent(match[1]), decodeURIComponent(match[2]), match[3]];
      const repo = s.repos.get(`${o}/${n}`);
      const t = instToken(req);
      if (!t || !repo || !coversRepo(t, o, n)) return send(res, 404, { message: 'Not Found' });
      if (rest === '' && m === 'GET') return handle.failRepoRead ? send(res, 500, { message: 'Server Error' }) : send(res, 200, repoView(repo));
      if (rest === '' && m === 'DELETE') {
        if (!can(t, 'administration', 'write')) return send(res, 403, { message: 'Resource not accessible by integration' });
        s.repos.delete(`${o}/${n}`);
        return send(res, 204);
      }
      if (rest === '/rulesets' && m === 'GET') {
        if (!can(t, 'administration', 'read')) return send(res, 403, { message: 'Resource not accessible by integration' });
        return send(res, 200, repo.rulesets.map((r) => ({ id: r.id, name: r.name, enforcement: r.enforcement })));
      }
      if (rest === '' && m === 'PATCH') {
        if (!can(t, 'administration', 'write')) return send(res, 403, { message: 'Resource not accessible by integration' });
        if (typeof body.allow_forking === 'boolean') repo.allow_forking = body.allow_forking;
        return send(res, 200, repoView(repo));
      }
      if (rest === '/rulesets' && m === 'POST') {
        if (!can(t, 'administration', 'write')) return send(res, 403, { message: 'Resource not accessible by integration' });
        if (repo.private && s.orgs.get(o)!.plan === 'free') return send(res, 403, { message: LIKE_GITHUB_FREE_PRIVATE_RULESETS });
        const rs = { id: nextId++, ...body };
        repo.rulesets.push(rs);
        return send(res, 201, rs);
      }
      if ((match = /^\/rulesets\/(\d+)$/.exec(rest)) && m === 'GET') {
        if (!can(t, 'administration', 'read')) return send(res, 403, { message: 'Resource not accessible by integration' });
        const rs = repo.rulesets.find((r) => r.id === Number(match![1]));
        return rs ? send(res, 200, rs) : send(res, 404, { message: 'Not Found' });
      }
      if ((match = /^\/git\/trees\/([0-9a-f]{40})$/.exec(rest)) && m === 'GET') {
        if (!can(t, 'contents', 'read')) return send(res, 403, { message: 'Resource not accessible by integration' });
        const r = spawnSync('git', ['-C', repo.bare, 'ls-tree', '-r', '-z', match[1]], { encoding: 'utf8' });
        if (r.status !== 0) return send(res, 404, { message: 'Not Found' });
        const tree = r.stdout.split('\0').filter(Boolean).map((line) => {
          const [meta, p2] = line.split('\t');
          const [mode, type, sha] = meta.split(' ');
          return { path: p2, mode, type, sha };
        });
        return send(res, 200, { sha: match[1], tree: handle.truncateTrees ? tree.slice(0, 1) : tree, truncated: handle.truncateTrees });
      }
      if ((match = /^\/commits\/([^/]+)$/.exec(rest)) && m === 'GET') {
        if (!can(t, 'contents', 'read')) return send(res, 403, { message: 'Resource not accessible by integration' });
        const r = spawnSync('git', ['-C', repo.bare, 'rev-parse', '--verify', `refs/heads/${decodeURIComponent(match[1])}`], { encoding: 'utf8' });
        return r.status === 0 ? send(res, 200, { sha: r.stdout.trim() }) : send(res, 409, { message: 'Git Repository is empty.' });
      }
      return send(res, 404, { message: 'Not Found' });
    }
    // ---- user-to-server (the person who installed)
    const user = s.userTokens.get(bearer(req));
    if (m === 'GET' && p.startsWith('/user/installations')) {
      if (!user || user.revoked) return send(res, 401, { message: 'Bad credentials' });
      const list = [...s.installations.entries()]
        .filter(([, i]) => {
          const org = s.orgs.get(i.org)!;
          return i.appId === s.appId && (org.owners.has(user.login) || org.members.has(user.login));
        })
        .map(([id, i]) => ({ id, app_id: Number(i.appId), account: { login: i.org, id: s.orgs.get(i.org)!.id, type: 'Organization' } }));
      return send(res, 200, { total_count: list.length, installations: list });
    }
    if (m === 'GET' && (match = /^\/user\/memberships\/orgs\/([^/]+)$/.exec(p))) {
      if (!user || user.revoked) return send(res, 401, { message: 'Bad credentials' });
      const org = s.orgs.get(decodeURIComponent(match[1]));
      if (!org || !(org.owners.has(user.login) || org.members.has(user.login))) return send(res, 404, { message: 'Not Found' });
      if (!handle.appPermissions.members) return send(res, 403, { message: 'Resource not accessible by integration' });
      return send(res, 200, { state: 'active', role: org.owners.has(user.login) ? 'admin' : 'member', user: { login: user.login } });
    }
    if (m === 'DELETE' && (match = /^\/applications\/([^/]+)\/token$/.exec(p))) {
      const basic = Buffer.from((req.headers.authorization || '').replace(/^Basic /, ''), 'base64').toString();
      if (basic !== `${s.clientId}:${s.clientSecret}` || decodeURIComponent(match[1]) !== s.clientId) return send(res, 401, { message: 'Bad credentials' });
      const u = s.userTokens.get(body?.access_token);
      if (!u) return send(res, 404, { message: 'Not Found' });
      u.revoked = true;
      return send(res, 204);
    }
    return send(res, 404, { message: 'Not Found' });
  }

  function gitHttp(req: http.IncomingMessage, res: http.ServerResponse, p: string, query: string) {
    const match = /^\/([^/]+)\/([^/]+)\.git(\/.*)$/.exec(p)!;
    const [o, n, rest] = [match[1], match[2], match[3]];
    const repo = s.repos.get(`${o}/${n}`);
    const basic = Buffer.from((req.headers.authorization || '').replace(/^Basic /, ''), 'base64').toString();
    const t = basic.startsWith('x-access-token:') ? s.tokens.find((x) => x.token === basic.slice(15) && !x.revoked) : undefined;
    const pushing = rest === '/git-receive-pack' || /service=git-receive-pack/.test(query);
    if (pushing && handle.refusePushes) {
      res.writeHead(403, { 'Content-Type': 'text/plain' });
      return res.end('Push refused (test)');
    }
    if (!repo || !t || !coversRepo(t, o, n) || !can(t, 'contents', pushing ? 'write' : 'read')) {
      res.writeHead(401, { 'WWW-Authenticate': 'Basic realm="GitHub"' });
      return res.end('Unauthorized');
    }
    const cgi = spawn('git', ['http-backend'], {
      env: {
        PATH: process.env.PATH,
        GIT_PROJECT_ROOT: root,
        GIT_HTTP_EXPORT_ALL: '1',
        PATH_INFO: `/${o}/${n}.git${rest}`,
        QUERY_STRING: query,
        REQUEST_METHOD: req.method,
        CONTENT_TYPE: req.headers['content-type'] || '',
        REMOTE_USER: 'x-access-token',
        HTTP_CONTENT_ENCODING: (req.headers['content-encoding'] as string) || ''
      }
    });
    req.pipe(cgi.stdin);
    let head = Buffer.alloc(0);
    let headersDone = false;
    cgi.stdout.on('data', (chunk: Buffer) => {
      if (headersDone) return void res.write(chunk);
      head = Buffer.concat([head, chunk]);
      const end = head.indexOf('\r\n\r\n');
      if (end < 0) return;
      headersDone = true;
      let status = 200;
      for (const line of head.subarray(0, end).toString().split('\r\n')) {
        const i = line.indexOf(':');
        const k = line.slice(0, i).trim();
        const v = line.slice(i + 1).trim();
        if (k.toLowerCase() === 'status') status = Number(v.split(' ')[0]);
        else res.setHeader(k, v);
      }
      res.statusCode = status;
      res.write(head.subarray(end + 4));
    });
    cgi.stdout.on('end', () => res.end());
  }

  const server = http.createServer(async (req, res) => {
    const u = new URL(req.url!, 'http://x');
    const p = u.pathname;
    const auth = (req.headers.authorization || '').split(' ')[0] || 'none';
    s.calls.push({ method: req.method!, path: p, auth });
    try {
      if (/^\/[^/]+\/[^/]+\.git\//.test(p)) return gitHttp(req, res, p, u.search.slice(1));
      const raw = await readBody(req);
      let body: any = {};
      if (raw.length) body = JSON.parse(raw.toString());
      if (req.method === 'GET' && /^\/apps\/[^/]+\/installations\/new$/.test(p)) {
        const b = handle.browser;
        if (!b) return send(res, 404, { message: 'Not Found' });
        const existing = [...s.installations.entries()].find(([, i]) => i.org === b.org && i.appId === s.appId);
        const id = existing ? existing[0] : handle.install(b.org);
        const back = new URL(b.setupUrl);
        back.searchParams.set('installation_id', String(id));
        back.searchParams.set('setup_action', 'install');
        back.searchParams.set('state', u.searchParams.get('state') || '');
        res.writeHead(302, { Location: back.toString() });
        return res.end();
      }
      if (req.method === 'GET' && p === '/login/oauth/authorize') {
        const b = handle.browser;
        if (!b || u.searchParams.get('client_id') !== s.clientId) return send(res, 404, { message: 'Not Found' });
        const back = new URL(u.searchParams.get('redirect_uri')!);
        back.searchParams.set('code', handle.authorizeCode(b.login));
        back.searchParams.set('state', u.searchParams.get('state') || '');
        res.writeHead(302, { Location: back.toString() });
        return res.end();
      }
      if (req.method === 'GET' && p === '/account/organizations/new') {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        return res.end('<h1>Create an organization (GitHub stand-in)</h1>');
      }
      if (req.method === 'POST' && p === '/login/oauth/access_token') {
        const login = s.codes.get(body.code);
        if (!login || body.client_id !== s.clientId || body.client_secret !== s.clientSecret) return send(res, 200, { error: 'bad_verification_code' });
        s.codes.delete(body.code);
        const token = `ghu_${randomBytes(18).toString('hex')}`;
        s.userTokens.set(token, { login, revoked: false });
        return send(res, 200, { access_token: token, token_type: 'bearer' });
      }
      return await api(req, res, p, body);
    } catch (err: any) {
      send(res, 500, { message: String(err?.message ?? err) });
    }
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  const url = `http://127.0.0.1:${(server.address() as any).port}`;

  const handle: StandIn = {
    url,
    browser: null,
    refusePushes: false,
    loseCreateAnswer: false,
    failRepoRead: false,
    failOrgRead: false,
    truncateTrees: false,
    appPermissions: {
      administration: 'write',
      contents: 'write',
      pull_requests: 'write',
      metadata: 'read',
      organization_administration: 'write',
      members: 'read'
    },
    appId: s.appId,
    slug: s.slug,
    clientId: s.clientId,
    clientSecret: s.clientSecret,
    privateKeyPem: s.privateKeyPem,
    orgs: s.orgs,
    repos: s.repos,
    installations: s.installations,
    tokens: s.tokens,
    userTokens: s.userTokens,
    calls: s.calls,
    addOrg(login, opts = {}) {
      const org: Org = {
        login,
        id: nextId++,
        plan: opts.plan ?? 'free',
        // GitHub's defaults for a new organization
        settings: {
          default_repository_permission: 'read',
          members_can_create_repositories: true,
          members_can_create_public_repositories: true,
          members_can_create_private_repositories: true,
          members_can_fork_private_repositories: false
        },
        owners: new Set(opts.owners ?? []),
        members: new Set(opts.members ?? [])
      };
      s.orgs.set(login, org);
      return org;
    },
    uninstall(id) {
      s.installations.delete(id);
    },
    suspend(id, suspended) {
      const i = s.installations.get(id);
      if (i) i.suspendedAt = suspended ? new Date().toISOString() : null;
    },
    renameOrg(from, to) {
      const org = s.orgs.get(from)!;
      s.orgs.delete(from);
      org.login = to;
      s.orgs.set(to, org);
      for (const i of s.installations.values()) if (i.org === from) i.org = to;
      for (const [k, r] of [...s.repos.entries()]) {
        if (r.org !== from) continue;
        s.repos.delete(k);
        r.org = to;
        s.repos.set(`${to}/${r.name}`, r);
      }
    },
    install(org, opts = {}) {
      const id = nextId++;
      s.installations.set(id, { org, appId: opts.appId ?? s.appId });
      return id;
    },
    authorizeCode(login) {
      const code = randomBytes(10).toString('hex');
      s.codes.set(code, login);
      return code;
    },
    stop: () =>
      new Promise<void>((r) => {
        server.close(() => {
          fs.rmSync(root, { recursive: true, force: true });
          r();
        });
        server.closeAllConnections();
      })
  };
  return handle;
}
