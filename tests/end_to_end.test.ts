import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import crypto from 'node:crypto';
import fs from 'node:fs';
import https from 'node:https';
import os from 'node:os';
import path from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { getAdminPool, getDbPool, getProjectEvents, insertEvent, runMigrations, verifyServerProjectEvents } from '../server/db';
import { configureWebhookRuntime, deliverDueWebhooks, resetWebhookRuntime } from '../server/webhooks';
import { forgetInstallationTokens } from '../server/github';
import { assertPoolTargetsTestDb } from './support/safety';
import { startHarness, Harness } from './support/apiHarness';
import { startApp, RunningApp } from './support/api';
import { startGitHubStandIn, StandIn } from './support/githubStandIn';
import { installGitleaks } from '../scripts/install-gitleaks';
import { newKey, TestKey, sign } from './support/principalKeys';
import {
  CustodyCoreClient, CustodyCoreError, attestationSigningInput, payloadSha256, signText, verifyWebhookSignature
} from '../sdk/typescript/custody-core';

/**
 * The whole external flow (Phase 12), the way an outside platform and an owner would really do it, and then the record checked by someone who has none of our code:
 *
 *   an operator registers the platform as a principal (the command-line tool) -> the owner registers a webhook and a signing authority -> the platform asks for a
 *   session and the owner approves it -> the platform works with ordinary git through the gateway (and is refused where it should be) -> a CI principal signs evidence,
 *   a signing authority attests -> a release principal asks to promote, the owner approves, the default branch moves -> the platform closes -> signed webhooks
 *   arrived at a real HTTPS receiver -> and `scripts/verify-chain.mjs`, which imports nothing from this project, verifies the project's record from the exported
 *   events and from the deliveries, and catches every way of tampering with them.
 */
const GIT_ENV = { ...process.env, GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_NOSYSTEM: '1', GIT_TERMINAL_PROMPT: '0' };
const run = (cmd: string, args: string[], cwd?: string) => new Promise<{ code: number; out: string }>((resolve) => {
  const child = spawn(cmd, args, { cwd, env: GIT_ENV });
  let out = '';
  child.stdout.on('data', (c) => (out += c));
  child.stderr.on('data', (c) => (out += c));
  child.on('close', (code) => resolve({ code: code ?? 1, out }));
});
const gitc = (args: string[], cwd?: string) => run('git', args, cwd);
function gl(args: string[], cwd?: string) {
  const r = spawnSync('git', args, { cwd, env: GIT_ENV, encoding: 'utf8' });
  expect(r.status, `${args.join(' ')}: ${r.stderr}`).toBe(0);
  return r.stdout.trim();
}
function write(dir: string, file: string, content: string) {
  fs.mkdirSync(path.dirname(path.join(dir, file)), { recursive: true });
  fs.writeFileSync(path.join(dir, file), content);
}
const CREATOR_ID = ['-c', 'user.name=Alice Creator', '-c', 'user.email=alice.creator@example.com'];
const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');
const VERIFY = path.join(root, 'scripts', 'verify-chain.mjs');
const TSX = path.join(root, 'node_modules', '.bin', 'tsx');

describe('The whole external flow, and the record verified without our code', () => {
  const db = getDbPool()!;
  const admin = getAdminPool()!;
  let standIn: StandIn;
  let h: Harness;
  let app: RunningApp;
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'custody-e2e-'));
  const savedEnv = { ...process.env };
  const ORG = `org${Date.now()}`;
  const APP = `${ORG}/app`;
  const INSTALLATION = 9000 + Math.floor(Math.random() * 900);
  let creator: any;
  let projectId = '', repoId = '', base = '';
  const upstream = () => standIn.upstreamDir(APP);
  const sha = (s: string) => crypto.createHash('sha256').update(s).digest('hex');

  // the real HTTPS receiver for webhooks
  const certDir = path.join(work, 'cert');
  let receiver: https.Server;
  let receiverPort = 0;
  const received: Array<{ headers: Record<string, any>; body: string }> = [];

  // principals, made by the command-line tool
  interface Platform { id: string; keyId: string; client: CustodyCoreClient; jwk: any; key: TestKey | null }
  const cli = async (args: string[]) => run(TSX, ['scripts/principal.ts', ...args], root);
  async function provision(name: string, scopes: string[], alg: 'Ed25519' | 'ES256' = 'Ed25519'): Promise<Platform> {
    const keys = path.join(work, 'keys');
    expect((await cli(['keygen', '--alg', alg, '--name', name, '--out', keys])).code).toBe(0);
    const created = await cli(['create', '--creator', creator.id, '--name', name, '--platform', 'agent', '--env', 'development', '--scopes', scopes.join(',')]);
    expect(created.code, created.out).toBe(0);
    const id = /Created principal ([0-9a-f-]{36})/.exec(created.out)![1];
    const added = await cli(['add-key', '--principal', id, '--public-key', path.join(keys, `${name}.public.jwk.json`)]);
    expect(added.code, added.out).toBe(0);
    const keyId = /kid \(put this in the assertion header\): ([0-9a-f-]{36})/.exec(added.out)![1];
    const jwk = JSON.parse(fs.readFileSync(path.join(keys, `${name}.private.jwk.json`), 'utf8'));
    return { id, keyId, jwk, key: null, client: new CustodyCoreClient({ baseUrl: app.base, principalId: id, keyId, privateKey: jwk, algorithm: alg }) };
  }
  let agent: Platform, ci: Platform, release: Platform;

  const events = async () => (await db.query('SELECT * FROM event WHERE project_id = $1 ORDER BY seq', [projectId])).rows;
  const names = async () => (await events()).map((e) => e.action as string);
  const subsequence = (all: string[], want: string[]) => { let i = 0; for (const a of all) if (a === want[i]) i++; return i === want.length; };

  beforeAll(async () => {
    await assertPoolTargetsTestDb(admin);
    expect((await runMigrations()).success).toBe(true);
    await installGitleaks();
    standIn = await startGitHubStandIn();
    Object.assign(process.env, standIn.env, { GATEWAY_DATA_DIR: path.join(work, 'gateway'), APP_URL: '' });
    forgetInstallationTokens();
    standIn.addInstallation(INSTALLATION, ORG, [APP]);
    standIn.createRepo(APP);
    const seed = path.join(work, 'seed');
    fs.mkdirSync(seed, { recursive: true });
    gl(['init', '--quiet', '--initial-branch=main'], seed);
    write(seed, 'README.md', '# app\n');
    write(seed, 'src/a.ts', 'export const a = 1;\n');
    write(seed, 'src/lib/b.ts', 'export const b = 1;\n');
    write(seed, '.env', 'API_KEY=hunter2-not-for-agents\n');
    gl(['add', '-A'], seed);
    gl([...CREATOR_ID, 'commit', '--quiet', '-m', 'Initial state'], seed);
    base = gl(['rev-parse', 'HEAD'], seed);
    gl(['push', '--quiet', '--force', upstream(), 'main:main'], seed);

    fs.mkdirSync(certDir, { recursive: true });
    const r = spawnSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-keyout', path.join(certDir, 'k.pem'), '-out', path.join(certDir, 'c.pem'), '-days', '2', '-subj', '/CN=hooks.example.test', '-addext', 'subjectAltName=DNS:hooks.example.test'], { encoding: 'utf8' });
    expect(r.status, r.stderr).toBe(0);
    receiver = https.createServer({ key: fs.readFileSync(path.join(certDir, 'k.pem')), cert: fs.readFileSync(path.join(certDir, 'c.pem')) }, (req, res) => {
      let body = '';
      req.on('data', (c) => (body += c));
      req.on('end', () => {
        received.push({ headers: req.headers, body });
        res.writeHead(200);
        res.end('ok');
      });
    });
    await new Promise<void>((ok) => receiver.listen(0, '127.0.0.1', () => ok()));
    receiverPort = (receiver.address() as any).port;

    h = await startHarness();
    app = await startApp();
    creator = await h.newCreator('owner');
    await db.query(`INSERT INTO github_installation (creator_id, installation_id, account_login, account_type, connected_by_github_login) VALUES ($1, $2, $3, 'Organization', 'octo')`, [creator.id, INSTALLATION, ORG]);
    projectId = (await db.query(`INSERT INTO project (creator_id, name, purpose, status) VALUES ($1, 'End to end', 'The whole flow', 'active') RETURNING id`, [creator.id])).rows[0].id;
    repoId = (await db.query(`INSERT INTO repository (project_id, github_repo_id, full_name) VALUES ($1, '1', $2) RETURNING id`, [projectId, APP])).rows[0].id;
    await insertEvent({ project_id: projectId, actor_type: 'creator', actor_id: creator.id, action: 'project.claimed', subject_type: 'project', subject_id: projectId, payload: {} });
  }, 240_000);
  afterAll(async () => {
    resetWebhookRuntime();
    await new Promise<void>((ok) => receiver?.close(() => ok()));
    await app?.stop();
    await h?.stop();
    await standIn?.stop();
    for (const k of Object.keys(process.env)) if (!(k in savedEnv)) delete process.env[k];
    Object.assign(process.env, savedEnv);
    forgetInstallationTokens();
    fs.rmSync(work, { recursive: true, force: true });
  });

  let sessionId = '';
  let secretWebhook = '';
  let authority: { id: string; key: TestKey } | null = null;
  let commit = '';
  const PEM = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ type: 'pkcs1', format: 'pem' }).toString();

  it('1. an operator registers the platform with the command-line tool; keys are never shared and duties are kept apart', async () => {
    agent = await provision('agent', ['work-sessions:request', 'work-sessions:read', 'work-sessions:close-own', 'repositories:push-session']);
    ci = await provision('ci-runner', ['evidence:submit'], 'ES256');
    release = await provision('release-bot', ['repositories:promote', 'work-sessions:read']);
    const me = await agent.client.whoami();
    expect(me.principal).toMatchObject({ id: agent.id, scopes: expect.arrayContaining(['work-sessions:request']) });
    // an agent that could both do the work and release it is refused at registration, by the tool and by the database
    const both = await cli(['create', '--creator', creator.id, '--name', 'too-powerful', '--platform', 'agent', '--env', 'development', '--scopes', 'work-sessions:request,repositories:promote']);
    expect(both.code).toBe(1);
    expect(both.out).toMatch(/Refused/);
  }, 240_000);

  it('2. the owner registers a webhook (to a real HTTPS receiver) and a signing authority', async () => {
    configureWebhookRuntime({ resolve: async () => [{ address: '127.0.0.1', family: 4 }], allowPrivate: true, ca: fs.readFileSync(path.join(certDir, 'c.pem'), 'utf8') });
    const hook = await h.api(creator, 'POST', '/webhook-endpoints', { name: 'Everything', url: `https://hooks.example.test:${receiverPort}/custody`, events: ['*'], project_ids: [projectId] });
    expect(hook.status, JSON.stringify(hook.body)).toBe(201);
    secretWebhook = hook.body.secret;
    const key = newKey('ES256');
    const reg = await h.api(creator, 'POST', '/attestation-authorities', { name: 'Release notary', public_key: key.publicJwk });
    expect(reg.status).toBe(201);
    authority = { id: reg.body.authority.id, key };
  });

  it('3. the platform asks for a session; nothing happens until the owner approves', async () => {
    const requested = await agent.client.requestWorkSession({
      project_id: projectId, repository_id: repoId, executor: { type: 'ai_assistant', provider: 'example-ai', model: 'model-1', external_id: 'agent_99', display_name: 'Refactor Engine' },
      sponsor: { type: 'creator', id: creator.id }, objective: 'Improve the library', base_commit: base,
      access: { repository: 'read_and_push', allowed_read_paths: ['src/**', 'README.md'], allowed_write_paths: ['src/lib/**'], prohibited_paths: ['.env*'] },
      evidence_requirements: [{ type: 'tests', issuer_principal_id: ci.id, specification_hash: sha('spec v1'), max_age_seconds: 3600 }],
      external_context: { namespace: 'com.example.orchestrator', context: { workcell: 'cell_09' } }
    });
    sessionId = requested.session_id;
    expect(requested).toMatchObject({ status: 'requested', requires_approval: true });
    const early = await agent.client.issueSessionCredential(sessionId).then(() => null, (e) => e);
    expect(early).toBeInstanceOf(CustodyCoreError);
    expect(early.status).toBe(409);
    expect((await h.api(creator, 'POST', `/projects/${projectId}/work-sessions/${sessionId}/approve`, {})).status).toBe(200);
  });

  it('4. the platform works with ordinary git; the gateway refuses what the rules forbid, and records each refusal', async () => {
    const grant = await agent.client.issueSessionCredential(sessionId);
    const url = grant.git_url.replace('http://', `http://x:${grant.credential.token}@`);
    const dir = path.join(work, 'clone');
    expect((await gitc(['clone', '--quiet', url, dir])).code).toBe(0);
    expect(fs.existsSync(path.join(dir, '.env'))).toBe(false); // the view holds only what may be read
    expect(gl(['rev-list', '--count', 'HEAD'], dir)).toBe('1');
    const branch = `refs/heads/${grant.branch_prefix}work`;

    write(dir, 'src/a.ts', 'export const a = 2;\n'); // outside the write paths
    gl(['add', '-A'], dir);
    gl([...CREATOR_ID, 'commit', '--quiet', '-m', 'sneaky'], dir);
    const outside = await gitc(['push', 'origin', `HEAD:${branch}`], dir);
    expect(outside.code).not.toBe(0);
    expect(outside.out).toMatch(/not_writable/);
    gl(['reset', '--quiet', '--hard', 'HEAD~1'], dir);

    write(dir, 'src/lib/deploy.txt', PEM); // a secret
    gl(['add', '-A'], dir);
    gl([...CREATOR_ID, 'commit', '--quiet', '-m', 'oops'], dir);
    const leaky = await gitc(['push', 'origin', `HEAD:${branch}`], dir);
    expect(leaky.code).not.toBe(0);
    expect(leaky.out).toMatch(/possible secret/);
    expect(leaky.out).not.toContain(PEM.split('\n')[1]);
    gl(['reset', '--quiet', '--hard', 'HEAD~1'], dir);

    // the real work, committed in the creator's name (the claim is kept as evidence only)
    write(dir, 'src/lib/b.ts', 'export const b = 2;\n');
    gl(['add', '-A'], dir);
    gl([...CREATOR_ID, 'commit', '--quiet', '-m', 'Improve b'], dir);
    const ok = await gitc(['push', 'origin', `HEAD:${branch}`], dir);
    expect(ok.code, ok.out).toBe(0);
    commit = (await agent.client.listSessionCommits(sessionId))[0].real_sha;
    expect(gl(['rev-parse', branch], upstream())).toBe(commit);
    expect(gl(['log', '-1', '--format=%an|%cn', commit], upstream())).toBe('Refactor Engine|Custody Core');
    expect(gl(['rev-parse', 'refs/heads/main'], upstream())).toBe(base); // the default branch is untouched
    const attribution = await agent.client.getAttribution(sessionId);
    expect(attribution[0]).toMatchObject({ commit, author: { kind: 'executor', principal_id: agent.id }, declared_author: { value: 'Alice Creator <alice.creator@example.com>', trusted: false } });
  }, 240_000);

  it('5. promotion is refused without evidence; then CI signs evidence, the authority attests, and a release principal asks', async () => {
    const refused = await release.client.requestPromotion(sessionId).then(() => null, (e) => e);
    expect(refused.status).toBe(422);
    expect(refused.code).toBe('evidence_not_ready');

    // the wrong principal cannot vouch; the named one can, and only for a real commit of this session
    const stranger = await ci.client.submitEvidence(sessionId, { evidence_type: 'tests', subject_commit: 'a'.repeat(40), status: 'pass', specification_hash: sha('spec v1'), evidence_hash: sha('r0') }).then(() => null, (e) => e);
    expect(stranger.status).toBe(422);
    const recorded = await ci.client.submitEvidence(sessionId, { evidence_type: 'tests', subject_commit: commit, status: 'pass', specification_hash: sha('spec v1'), evidence_hash: sha('report'), payload: { passed: 41, failed: 0 } });
    expect(recorded).toMatchObject({ recorded: true, status: 'pass' });
    expect((await agent.client.getEvidence(sessionId)).evaluation).toMatchObject({ commit, ready: true });

    const statement = { authority_id: authority!.id, work_session_id: sessionId, claim: 'release.approved', subject_commit: commit, payload_sha256: payloadSha256({}), issued_at: new Date().toISOString().replace(/\.\d+Z$/, 'Z') };
    const { work_session_id: _w, payload_sha256: _p, ...rest } = statement;
    const att = await h.api(creator, 'POST', `/projects/${projectId}/work-sessions/${sessionId}/attestations`, { ...rest, signature: { algorithm: 'ES256', value: signText(authority!.key.privateKey, 'ES256', attestationSigningInput(statement)) } });
    expect(att.status, JSON.stringify(att.body)).toBe(201);

    const asked = await release.client.requestPromotion(sessionId);
    expect(asked).toMatchObject({ status: 'pending', commit });
    expect(asked.attestations_at_request).toHaveLength(1);
    // the agent can neither ask for it nor approve it, and neither can the release bot approve
    expect((await agent.client.requestPromotion(sessionId).then(() => null, (e) => e)).status).toBe(403);
    expect((await h.api(creator, 'POST', `/projects/${projectId}/promotions/${asked.id}/approve`, {})).status).toBe(200);
    expect(gl(['rev-parse', 'refs/heads/main'], upstream())).toBe(commit);
    expect((await agent.client.getWorkSession(sessionId)).status).toBe('completed');
  }, 240_000);

  it('6. the platform closes the session; its credential is dead, and the principal can be revoked', async () => {
    expect((await agent.client.closeWorkSession(sessionId)).status).toBe('closed');
    const dead = await agent.client.issueSessionCredential(sessionId).then(() => null, (e) => e);
    expect(dead.status).toBe(409);
    const r = await cli(['revoke', '--principal', release.id]);
    expect(r.code).toBe(0);
    expect((await release.client.whoami().then(() => null, (e) => e)).status).toBe(401);
    expect((await agent.client.whoami()).principal.id).toBe(agent.id); // the others are unaffected
  });

  it('7. the project\'s record tells the whole story, in order, and contains no secret', async () => {
    const all = await names();
    expect(subsequence(all, [
      'project.claimed', 'work_session.requested', 'work_session.approved', 'session_credential.issued', 'work_session.provisioned', 'git.push_rejected', 'git.push_rejected',
      'attribution.recorded', 'git.push', 'evidence.submitted', 'attestation.recorded', 'promotion.requested', 'promotion.approved', 'session_credential.revoked', 'promotion.completed', 'work_session.closed'
    ]), all.join(' > ')).toBe(true);
    const rejected = (await events()).filter((e) => e.action === 'git.push_rejected').map((e) => e.payload.reason);
    expect(rejected).toEqual(['path_not_allowed', 'secret_found']);
    const text = JSON.stringify(await events());
    for (const secret of [PEM.split('\n')[1], 'hunter2-not-for-agents', secretWebhook, 'ccs_', agent.jwk.d, ci.jwk.d, release.jwk.d]) {
      expect(text, String(secret).slice(0, 12)).not.toContain(secret);
    }
  });

  it('8. signed webhooks arrived at the real HTTPS receiver: every event, in order, each verifiable', async () => {
    for (let i = 0; i < 20; i++) {
      await deliverDueWebhooks(db);
      const pending = (await db.query(`SELECT count(*)::int AS n FROM webhook_delivery d JOIN webhook_endpoint e ON e.id = d.endpoint_id WHERE d.status = 'pending' AND e.creator_id = $1`, [creator.id])).rows[0].n;
      if (pending === 0) break;
    }
    const bodies = received.map((r) => ({ ...r, msg: JSON.parse(r.body) }));
    for (const r of bodies) {
      expect(verifyWebhookSignature(secretWebhook, r.headers['custody-signature'], r.body)).toBe(true);
      expect(r.headers['custody-event-id']).toBe(r.msg.id);
    }
    const chain = await events();
    const delivered = new Map<string, any>();
    for (const r of bodies) delivered.set(r.msg.id, r.msg); // at least once: de-duplicate on the event id
    // everything after the endpoint existed was delivered
    const after = chain.filter((e) => delivered.has(e.id));
    expect(after.length).toBeGreaterThan(15);
    expect(after.map((e) => e.seq)).toEqual(chain.slice(chain.length - after.length).map((e) => e.seq)); // a contiguous tail of the record
    for (const e of after) expect(delivered.get(e.id).record).toMatchObject({ seq: Number(e.seq), hash: e.hash, prev_hash: e.prev_hash });
    expect(delivered.get(chain.at(-1)!.id).record.hash).toBe(chain.at(-1)!.hash); // including the newest
    const types = [...delivered.values()].sort((a, b) => a.record.seq - b.record.seq).map((m) => m.type);
    expect(subsequence(types, ['work_session.requested', 'git.push', 'evidence.submitted', 'promotion.completed', 'work_session.closed'])).toBe(true);
  }, 120_000);

  describe('9. the record verified by someone with none of our code (scripts/verify-chain.mjs)', () => {
    let exported: any[] = [];
    let file = '';
    const verify = async (args: string[]) => run(process.execPath, [VERIFY, ...args]);
    const write2 = (name: string, data: unknown) => {
      const f = path.join(work, name);
      fs.writeFileSync(f, JSON.stringify(data));
      return f;
    };
    const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x));
    beforeAll(async () => {
      // exactly what GET /api/v1/projects/:id/events answers (that route is { project_id, events: getProjectEvents(id), count })
      const body = { project_id: projectId, events: await getProjectEvents(projectId), connected: true };
      exported = JSON.parse(JSON.stringify(body.events));
      file = write2('events.json', { ...body, count: exported.length });
    });

    it('the exported record verifies, and the newest event is the one the webhooks last reported', async () => {
      const head = exported.at(-1).hash;
      const r = await verify([file, '--project', projectId, '--head', head]);
      expect(r.code, r.out).toBe(0);
      expect(r.out).toMatch(new RegExp(`OK: ${exported.length} events of project ${projectId}, newest hash ${head}`));
      const lastDelivery = received.map((x) => JSON.parse(x.body)).sort((a, b) => b.record.seq - a.record.seq)[0];
      expect(lastDelivery.record.hash).toBe(head);
      expect((await verify([write2('bare-array.json', exported)])).code).toBe(0); // a plain list works too
    });

    it('every way of changing the record is caught, and says where', async () => {
      const mid = Math.floor(exported.length / 2);
      const attacks: Array<[string, (e: any[]) => any[]]> = [
        ['a value changed in a payload', (e) => { const x = clone(e); x[mid].payload = { ...x[mid].payload, tampered: true }; return x; }],
        ['a payload and its hashed text changed together', (e) => { const x = clone(e); x[mid].payload = { tampered: 1 }; x[mid].canonical_payload = '{"tampered":1}'; return x; }],
        ['who did it changed', (e) => { const x = clone(e); x[mid].actor_id = 'someone-else'; return x; }],
        ['what happened changed', (e) => { const x = clone(e); x[mid].action = 'promotion.completed'; return x; }],
        ['the time changed', (e) => { const x = clone(e); x[mid].hashed_timestamp = '2000-01-01T00:00:00.000Z'; return x; }],
        ['a hash changed', (e) => { const x = clone(e); x[mid].hash = `${x[mid].hash[0] === 'a' ? 'b' : 'a'}${x[mid].hash.slice(1)}`; return x; }],
        ['an event removed from the middle', (e) => e.filter((_, i) => i !== mid)],
        ['two events swapped', (e) => { const x = clone(e); [x[mid], x[mid + 1]] = [x[mid + 1], x[mid]]; return x; }],
        ['an event inserted', (e) => { const x = clone(e); x.splice(mid, 0, clone(x[mid])); return x; }],
        ['the first event removed', (e) => e.slice(1)],
        ['an event moved to another project', (e) => { const x = clone(e); x[mid].project_id = crypto.randomUUID(); return x; }]
      ];
      for (const [why, attack] of attacks) {
        const r = await verify([write2('attack.json', attack(exported))]);
        expect(r.code, `${why}: ${r.out}`).toBe(1);
        expect(r.out, why).toMatch(/^FAIL/);
      }
      // the change is located: altering event N is reported at N
      const x = clone(exported);
      x[mid].payload = { ...x[mid].payload, tampered: true };
      expect((await verify([write2('located.json', x)])).out).toContain(`seq ${exported[mid].seq}`);
    });

    it('cutting off the NEWEST events leaves a valid chain, which is why a head recorded elsewhere (a webhook) is checked', async () => {
      const cut = write2('cut.json', exported.slice(0, -3));
      expect((await verify([cut])).code).toBe(0); // the documented limit: links only point backwards
      const withHead = await verify([cut, '--head', exported.at(-1).hash]);
      expect(withHead.code).toBe(1);
      expect(withHead.out).toMatch(/cut off/);
      expect((await verify([file, '--head', 'f'.repeat(64)])).code).toBe(1);
      expect((await verify([file, '--project', crypto.randomUUID()])).code).toBe(1);
    });

    it('each webhook delivery is verifiable on its own and against the record', async () => {
      const bodies = received.map((x) => x.body);
      const picks = [bodies[0], bodies[Math.floor(bodies.length / 2)], bodies.at(-1)!];
      for (const [i, b] of picks.entries()) {
        const f = path.join(work, `delivery-${i}.json`);
        fs.writeFileSync(f, b);
        const alone = await verify(['--delivery', f]);
        expect(alone.code, alone.out).toBe(0);
        const inRecord = await verify(['--delivery', f, '--chain', file]);
        expect(inRecord.code, inRecord.out).toBe(0);
        expect(inRecord.out).toMatch(/is in the record/);
        const forged = JSON.parse(b);
        forged.data = { ...forged.data, forged: true };
        const bad = await verify(['--delivery', write2(`forged-${i}.json`, forged)]);
        expect(bad.code).toBe(1);
        const other = JSON.parse(b);
        other.record.hash = 'c'.repeat(64);
        expect((await verify(['--delivery', write2(`other-${i}.json`, other), '--chain', file])).code).toBe(1);
      }
      expect((await verify(['--delivery', write2('not-a-delivery.json', { hello: 'world' })])).code).toBe(1);
      expect((await verify(['/does/not/exist.json'])).code).toBe(2);
    });

    it('agrees with the server\'s own verification, and imports nothing from this project', async () => {
      expect((await verifyServerProjectEvents(projectId)).isValid).toBe(true);
      const source = fs.readFileSync(VERIFY, 'utf8');
      const imports = [...source.matchAll(/^import .* from '([^']+)'/gm)].map((m) => m[1]);
      expect(imports.sort()).toEqual(['node:crypto', 'node:fs']);
    });
  });
});
