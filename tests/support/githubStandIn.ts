import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { spawn, execFileSync } from 'node:child_process';
import express from 'express';

/**
 * A local stand-in for the parts of GitHub the gateway uses, so tests never touch github.com:
 *
 *  - the REST endpoints for a GitHub App (installation tokens, installation lookup, repositories, the OAuth code
 *    exchange, the user's installations). It checks the App's JWT with the App's public key, like GitHub does,
 *    so a wrongly signed or expired JWT fails here too;
 *  - real git repositories served over smart HTTP (git http-backend) that accept only an installation token
 *    issued here, for a repository that token covers (Authorization: Basic x-access-token:<token>).
 *
 * What it does not prove: GitHub's exact JSON beyond the fields the gateway reads, and GitHub's own rules
 * (rulesets, branch protection). Those need the live check in docs/GITHUB_APP_SETUP.md.
 */

export interface StandIn {
  url: string;
  env: Record<string, string>;
  addInstallation(id: number, login: string, repos: string[]): void;
  createRepo(fullName: string): string;
  issueUserCode(login: string, installationIds: number[]): string;
  upstreamDir(fullName: string): string;
  tokensIssued(): number;
  /** Repository settings as GitHub would hold them (rulesets need a paid plan on private repositories). */
  repoState(fullName: string): RepoState;
  /** Permissions the installation has granted (default: contents write, metadata read, administration write). */
  setInstallationPermissions(id: number, permissions: Record<string, 'read' | 'write'>): void;
  stop(): Promise<void>;
}

export interface RepoState {
  private: boolean;
  allow_forking: boolean;
  rulesets_allowed: boolean;
  rulesets: Map<number, any>;
}

function verifyJwt(token: string, publicKey: crypto.KeyObject, appId: string): boolean {
  const [h, p, s] = token.split('.');
  if (!h || !p || !s) return false;
  const header = JSON.parse(Buffer.from(h, 'base64url').toString());
  if (header.alg !== 'RS256') return false;
  const ok = crypto.createVerify('RSA-SHA256').update(`${h}.${p}`).verify(publicKey, Buffer.from(s, 'base64url'));
  if (!ok) return false;
  const claims = JSON.parse(Buffer.from(p, 'base64url').toString());
  const now = Math.floor(Date.now() / 1000);
  return String(claims.iss) === appId && claims.exp > now && claims.iat <= now + 60 && claims.exp - claims.iat <= 600;
}

export async function startGitHubStandIn(): Promise<StandIn> {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const appId = String(100000 + Math.floor(Math.random() * 900000));
  const clientId = `Iv1.${crypto.randomBytes(8).toString('hex')}`;
  const clientSecret = crypto.randomBytes(20).toString('hex');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'custody-github-standin-'));

  const installations = new Map<number, { login: string; repos: Set<string>; permissions: Record<string, string> }>();
  const tokens = new Map<string, { installation: number; repos: Set<string> | null; expires: number; permissions: Record<string, string> }>();
  const repoStates = new Map<string, RepoState>();
  let nextRulesetId = 7000;
  const stateOf = (full: string): RepoState => {
    const key = full.toLowerCase();
    if (!repoStates.has(key)) repoStates.set(key, { private: true, allow_forking: true, rulesets_allowed: true, rulesets: new Map() });
    return repoStates.get(key)!;
  };
  const userCodes = new Map<string, { login: string; installations: number[] }>();
  const userTokens = new Map<string, { login: string; installations: number[] }>();
  let issued = 0;

  const app = express();
  app.use(express.json());

  const appAuth = (req: express.Request, res: express.Response) => {
    const m = /^Bearer (.+)$/.exec(req.headers.authorization ?? '');
    if (!m || !verifyJwt(m[1], publicKey, appId)) {
      res.status(401).json({ message: 'A JSON web token could not be decoded' });
      return false;
    }
    return true;
  };

  app.post('/app/installations/:id/access_tokens', (req, res) => {
    if (!appAuth(req, res)) return;
    const inst = installations.get(Number(req.params.id));
    if (!inst) return res.status(404).json({ message: 'Not Found' });
    let repos: Set<string> | null = null;
    if (Array.isArray(req.body?.repositories)) {
      repos = new Set();
      for (const name of req.body.repositories) {
        const full = `${inst.login}/${name}`.toLowerCase();
        if (!inst.repos.has(full)) return res.status(422).json({ message: `There is at least one repository that does not exist or is not accessible to the parent installation.` });
        repos.add(full);
      }
    }
    const requested: Record<string, string> = req.body?.permissions ?? inst.permissions;
    for (const [perm, level] of Object.entries(requested)) {
      const granted = inst.permissions[perm];
      if (!granted || (level === 'write' && granted !== 'write')) {
        return res.status(422).json({ message: 'The permissions requested are not granted to this installation.' });
      }
    }
    const token = `ghs_${crypto.randomBytes(18).toString('base64url')}`;
    const expires = Date.now() + 3600_000;
    tokens.set(token, { installation: Number(req.params.id), repos, expires, permissions: requested });
    issued++;
    res.status(201).json({ token, expires_at: new Date(expires).toISOString() });
  });

  app.get('/app/installations/:id', (req, res) => {
    if (!appAuth(req, res)) return;
    const inst = installations.get(Number(req.params.id));
    if (!inst) return res.status(404).json({ message: 'Not Found' });
    res.json({ id: Number(req.params.id), account: { login: inst.login, type: 'Organization' } });
  });

  app.get('/installation/repositories', (req, res) => {
    const t = tokens.get(/^Bearer (.+)$/.exec(req.headers.authorization ?? '')?.[1] ?? '');
    if (!t || t.expires < Date.now()) return res.status(401).json({ message: 'Bad credentials' });
    const inst = installations.get(t.installation)!;
    const page = Number(req.query.page ?? 1);
    const all = [...inst.repos].sort();
    const slice = all.slice((page - 1) * 100, page * 100);
    res.json({
      total_count: all.length,
      repositories: slice.map((full, i) => ({ id: 1000 + i, full_name: full, default_branch: 'main', private: true }))
    });
  });

  app.post('/login/oauth/access_token', (req, res) => {
    const { client_id, client_secret, code } = req.body ?? {};
    if (client_id !== clientId || client_secret !== clientSecret) return res.json({ error: 'incorrect_client_credentials' });
    const user = userCodes.get(code);
    if (!user) return res.json({ error: 'bad_verification_code', error_description: 'The code passed is incorrect or expired.' });
    userCodes.delete(code);
    const token = `ghu_${crypto.randomBytes(18).toString('base64url')}`;
    userTokens.set(token, user);
    res.json({ access_token: token, token_type: 'bearer' });
  });

  const userOf = (req: express.Request) => userTokens.get(/^Bearer (.+)$/.exec(req.headers.authorization ?? '')?.[1] ?? '');
  app.get('/user', (req, res) => {
    const u = userOf(req);
    if (!u) return res.status(401).json({ message: 'Bad credentials' });
    res.json({ login: u.login });
  });
  app.get('/user/installations', (req, res) => {
    const u = userOf(req);
    if (!u) return res.status(401).json({ message: 'Bad credentials' });
    res.json({ total_count: u.installations.length, installations: u.installations.map((id) => ({ id })) });
  });

  // Repository settings and rulesets (installation tokens only, limited to the token's repositories and permissions).
  const repoAccess = (req: express.Request, res: express.Response, need?: 'administration') => {
    const t = tokens.get(/^Bearer (.+)$/.exec(req.headers.authorization ?? '')?.[1] ?? '');
    if (!t || t.expires < Date.now()) {
      res.status(401).json({ message: 'Bad credentials' });
      return null;
    }
    const full = `${req.params.owner}/${req.params.repo}`.toLowerCase();
    const inst = installations.get(t.installation)!;
    if (!inst.repos.has(full) || (t.repos && !t.repos.has(full))) {
      res.status(404).json({ message: 'Not Found' });
      return null;
    }
    if (need && t.permissions[need] !== 'write') {
      res.status(403).json({ message: 'Resource not accessible by integration' });
      return null;
    }
    return { full, state: stateOf(full) };
  };
  const repoJson = (full: string, st: RepoState) => ({ id: 1, full_name: full, private: st.private, allow_forking: st.allow_forking, default_branch: 'main' });

  app.get('/repos/:owner/:repo', (req, res) => {
    const a = repoAccess(req, res);
    if (a) res.json(repoJson(a.full, a.state));
  });
  app.patch('/repos/:owner/:repo', (req, res) => {
    const a = repoAccess(req, res, 'administration');
    if (!a) return;
    if (typeof req.body?.allow_forking === 'boolean') a.state.allow_forking = req.body.allow_forking;
    res.json(repoJson(a.full, a.state));
  });
  app.get('/repos/:owner/:repo/rulesets', (req, res) => {
    const a = repoAccess(req, res);
    if (!a) return;
    res.json([...a.state.rulesets.values()].map((r) => ({ id: r.id, name: r.name, target: r.target, source_type: 'Repository', source: a.full, enforcement: r.enforcement })));
  });
  const validRuleset = (b: any) =>
    b && typeof b.name === 'string' && ['branch', 'tag', 'push'].includes(b.target) && ['active', 'disabled', 'evaluate'].includes(b.enforcement) &&
    Array.isArray(b.rules) && b.rules.every((r: any) => typeof r.type === 'string') &&
    Array.isArray(b.bypass_actors ?? []) && Array.isArray(b.conditions?.ref_name?.include);
  app.post('/repos/:owner/:repo/rulesets', (req, res) => {
    const a = repoAccess(req, res, 'administration');
    if (!a) return;
    if (a.state.private && !a.state.rulesets_allowed) {
      return res.status(403).json({ message: 'Upgrade to GitHub Pro or make this repository public to enable this feature.' });
    }
    if (!validRuleset(req.body)) return res.status(422).json({ message: 'Invalid request.' });
    const id = nextRulesetId++;
    const ruleset = { id, source_type: 'Repository', source: a.full, ...req.body };
    a.state.rulesets.set(id, ruleset);
    res.status(201).json(ruleset);
  });
  app.get('/repos/:owner/:repo/rulesets/:id', (req, res) => {
    const a = repoAccess(req, res);
    if (!a) return;
    const r = a.state.rulesets.get(Number(req.params.id));
    if (!r) return res.status(404).json({ message: 'Not Found' });
    res.json(r);
  });
  app.put('/repos/:owner/:repo/rulesets/:id', (req, res) => {
    const a = repoAccess(req, res, 'administration');
    if (!a) return;
    const id = Number(req.params.id);
    if (!a.state.rulesets.has(id)) return res.status(404).json({ message: 'Not Found' });
    if (!validRuleset(req.body)) return res.status(422).json({ message: 'Invalid request.' });
    const ruleset = { id, source_type: 'Repository', source: a.full, ...req.body };
    a.state.rulesets.set(id, ruleset);
    res.json(ruleset);
  });

  // Real git over smart HTTP, for installation tokens only.
  app.use((req, res, next) => {
    const m = /^\/([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)\.git\/(info\/refs|git-upload-pack|git-receive-pack)$/.exec(req.path);
    if (!m) return next();
    const full = `${m[1]}/${m[2]}`.toLowerCase();
    const basic = /^Basic (.+)$/.exec(req.headers.authorization ?? '');
    const [user, pass] = basic ? Buffer.from(basic[1], 'base64').toString().split(':') : [];
    const t = tokens.get(pass ?? '');
    if (user !== 'x-access-token' || !t || t.expires < Date.now()) {
      res.setHeader('WWW-Authenticate', 'Basic realm="GitHub"');
      return res.status(401).send('Invalid username or token.');
    }
    const inst = installations.get(t.installation)!;
    if (!inst.repos.has(full) || (t.repos && !t.repos.has(full))) return res.status(404).send('Repository not found.');

    const child = spawn('git', ['http-backend'], {
      env: {
        PATH: process.env.PATH ?? '',
        GIT_PROJECT_ROOT: root,
        GIT_HTTP_EXPORT_ALL: '1',
        PATH_INFO: `/${full}.git/${m[3]}`,
        REQUEST_METHOD: req.method,
        QUERY_STRING: new URL(req.url, 'http://x').search.slice(1),
        CONTENT_TYPE: String(req.headers['content-type'] ?? ''),
        REMOTE_USER: 'x-access-token',
        GIT_CONFIG_NOSYSTEM: '1',
        GIT_CONFIG_GLOBAL: '/dev/null',
        ...(req.headers['content-encoding'] ? { HTTP_CONTENT_ENCODING: String(req.headers['content-encoding']) } : {}),
        ...(req.headers['git-protocol'] ? { GIT_PROTOCOL: String(req.headers['git-protocol']) } : {})
      }
    });
    let head = Buffer.alloc(0);
    let started = false;
    child.stdout.on('data', (chunk: Buffer) => {
      if (started) return void res.write(chunk);
      head = Buffer.concat([head, chunk]);
      const end = head.indexOf('\r\n\r\n');
      if (end < 0) return;
      for (const line of head.subarray(0, end).toString().split('\r\n')) {
        const i = line.indexOf(':');
        if (line.slice(0, i).toLowerCase() === 'status') res.status(parseInt(line.slice(i + 1), 10));
        else res.setHeader(line.slice(0, i), line.slice(i + 1).trim());
      }
      started = true;
      res.write(head.subarray(end + 4));
    });
    child.on('close', () => res.end());
    req.pipe(child.stdin);
  });

  const server = http.createServer(app);
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  const port = (server.address() as any).port;
  const url = `http://127.0.0.1:${port}`;

  const upstreamDir = (fullName: string) => path.join(root, `${fullName.toLowerCase()}.git`);

  return {
    url,
    env: {
      GITHUB_APP_ID: appId,
      GITHUB_APP_SLUG: 'custody-core-test',
      GITHUB_APP_PRIVATE_KEY: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
      GITHUB_APP_CLIENT_ID: clientId,
      GITHUB_APP_CLIENT_SECRET: clientSecret,
      GITHUB_API_URL: url,
      GITHUB_WEB_URL: url,
      GITHUB_GIT_URL: url
    },
    addInstallation(id, login, repos) {
      installations.set(id, {
        login,
        repos: new Set(repos.map((r) => r.toLowerCase())),
        permissions: { contents: 'write', metadata: 'read', administration: 'write' }
      });
    },
    setInstallationPermissions(id, permissions) {
      installations.get(id)!.permissions = permissions;
    },
    repoState: stateOf,
    createRepo(fullName) {
      // A repository with a main branch, as GitHub has after "Initialize with a README".
      const dir = upstreamDir(fullName);
      const work = fs.mkdtempSync(path.join(os.tmpdir(), 'custody-seed-'));
      const g = (args: string[], cwd = work) =>
        execFileSync('git', args, { cwd, env: { ...process.env, GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_NOSYSTEM: '1' }, stdio: 'pipe' });
      fs.mkdirSync(path.dirname(dir), { recursive: true });
      g(['init', '--bare', '--quiet', '--initial-branch=main', dir]);
      g(['config', 'http.receivepack', 'true'], dir);
      g(['init', '--quiet', '--initial-branch=main']);
      fs.writeFileSync(path.join(work, 'README.md'), `# ${fullName}\n`);
      g(['add', '.']);
      g(['-c', 'user.name=Creator', '-c', 'user.email=creator@example.com', 'commit', '--quiet', '-m', 'Initial commit']);
      g(['push', '--quiet', dir, 'main:main']);
      fs.rmSync(work, { recursive: true, force: true });
      return dir;
    },
    issueUserCode(login, installationIds) {
      const code = crypto.randomBytes(10).toString('hex');
      userCodes.set(code, { login, installations: installationIds });
      return code;
    },
    upstreamDir,
    tokensIssued: () => issued,
    stop: async () => {
      await new Promise<void>((r) => server.close(() => r()));
      fs.rmSync(root, { recursive: true, force: true });
    }
  };
}
