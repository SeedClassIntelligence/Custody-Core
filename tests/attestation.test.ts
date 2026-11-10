import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import crypto from 'node:crypto';
import { getAdminPool, getDbPool, runMigrations, verifyServerProjectEvents } from '../server/db';
import { addPrincipalKey, registerPrincipal } from '../server/servicePrincipals';
import { attestationSigningInput } from '../server/attestation';
import { payloadSha256 } from '../server/evidence';
import { assertPoolTargetsTestDb } from './support/safety';
import { startHarness, Harness } from './support/apiHarness';
import { startApp, RunningApp } from './support/api';
import { installGitleaks } from '../scripts/install-gitleaks';
import { assertion, newKey, sign, TestAlg, TestKey } from './support/principalKeys';

/**
 * Attestation by an external signing authority (CL-13, part 2): the owner registers a signer's public key; a detached signature by that signer
 * over a canonical statement is verified BEFORE it is stored, and kept unchanged. Nothing here knows any particular signing service.
 */
describe('Attestation by a signing authority', () => {
  const db = getDbPool()!;
  const admin = getAdminPool()!;
  let h: Harness;
  let app: RunningApp;
  let creator: any, other: any;
  let projectId = '', repoId = '';
  interface Caller { id: string; keyId: string; key: TestKey }
  let requester: Caller, stranger: Caller;
  const commitId = () => crypto.randomBytes(20).toString('hex');
  const now = () => new Date().toISOString().replace(/\.\d+Z$/, 'Z');

  async function caller(label: string, scopes: string[]): Promise<Caller> {
    const p = await registerPrincipal(db, creator.id, { name: `${label}-${crypto.randomUUID().slice(0, 6)}`, platform_type: 'agent', environment: 'development', allowed_scopes: scopes } as any, 'test');
    const key = newKey('Ed25519');
    return { id: p.id, keyId: (await addPrincipalKey(db, p.id, key.publicJwk, 'test')).key_id, key };
  }
  const v2get = async (c: Caller, p: string) => {
    const res = await fetch(`${app.base}/api/v2${p}`, { headers: { Authorization: `Bearer ${assertion(c.key, c.keyId, c.id)}` } });
    return { status: res.status, body: (await res.json().catch(() => ({}))) as any };
  };
  interface Authority { id: string; key: TestKey }
  async function authority(name: string, alg: TestAlg = 'Ed25519', who = creator): Promise<Authority> {
    const key = newKey(alg);
    const r = await h.api(who, 'POST', '/attestation-authorities', { name, public_key: key.publicJwk });
    expect(r.status, JSON.stringify(r.body)).toBe(201);
    return { id: r.body.authority.id, key };
  }
  async function session(commits = 1) {
    const res = await fetch(`${app.base}/api/v2/work-sessions`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${assertion(requester.key, requester.keyId, requester.id)}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        project_id: projectId, repository_id: repoId, executor: { type: 'ai_assistant', display_name: 'Engine' }, sponsor: { type: 'creator', id: creator.id }, objective: 'Add the export page',
        base_commit: 'a'.repeat(40), access: { repository: 'read_and_push', allowed_read_paths: ['src/**'], allowed_write_paths: ['src/lib/**'], prohibited_paths: [] }
      })
    });
    const id = ((await res.json()) as any).session_id as string;
    expect((await h.api(creator, 'POST', `/projects/${projectId}/work-sessions/${id}/approve`, {})).status).toBe(200);
    await admin.query(`UPDATE work_session SET status = 'active' WHERE id = $1`, [id]);
    const shas: string[] = [];
    for (let i = 0; i < commits; i++) {
      const real = commitId();
      shas.push(real);
      await admin.query(`INSERT INTO session_commit (work_session_id, view_sha, real_sha, parent_view_sha, declared_author) VALUES ($1, $2, $3, $4, 'x')`, [id, commitId(), real, commitId()]);
    }
    return { id, commits: shas };
  }
  function attest(sessionId: string, a: Authority, over: Record<string, unknown> = {}, payload: Record<string, unknown> = {}) {
    const f = { authority_id: a.id, work_session_id: sessionId, claim: 'owner.reviewed', subject_commit: '', payload_sha256: payloadSha256(payload), issued_at: now(), ...over };
    const { work_session_id: _w, payload_sha256: _p, ...rest } = f;
    return { ...rest, payload, signature: { algorithm: a.key.alg, value: sign(a.key, attestationSigningInput(f as any)) } };
  }
  const post = (who: any, sessionId: string, body: unknown, pid = projectId) => h.api(who, 'POST', `/projects/${pid}/work-sessions/${sessionId}/attestations`, body);
  const rows = async (id: string) => (await db.query('SELECT * FROM attestation WHERE work_session_id = $1', [id])).rows;
  const events = async () => (await db.query('SELECT action, actor_type, actor_id, subject_id, payload FROM event WHERE project_id = $1 ORDER BY seq', [projectId])).rows;

  beforeAll(async () => {
    await assertPoolTargetsTestDb(admin);
    expect((await runMigrations()).success).toBe(true);
    await installGitleaks();
    h = await startHarness();
    app = await startApp();
    creator = await h.newCreator('owner');
    other = await h.newCreator('other');
    projectId = (await db.query(`INSERT INTO project (creator_id, name, purpose) VALUES ($1, 'P', 'x') RETURNING id`, [creator.id])).rows[0].id;
    repoId = (await db.query(`INSERT INTO repository (project_id, github_repo_id, full_name) VALUES ($1, '1', 'org/app') RETURNING id`, [projectId])).rows[0].id;
    requester = await caller('requester', ['work-sessions:request', 'work-sessions:read']);
    stranger = await caller('stranger', ['work-sessions:read']);
  }, 120_000);
  afterAll(async () => {
    await app?.stop();
    await h?.stop();
  });

  describe('authorities', () => {
    it('are registered by the owner with a public key only, listed, and recorded', async () => {
      const key = newKey('ES256');
      const r = await h.api(creator, 'POST', '/attestation-authorities', { name: 'Notary', public_key: key.publicJwk });
      expect(r.status).toBe(201);
      expect(r.body.authority).toMatchObject({ name: 'Notary', algorithm: 'ES256', revoked_at: null });
      expect(r.body.authority.fingerprint).toMatch(/^[0-9a-f]{64}$/);
      expect((await h.api(creator, 'GET', '/attestation-authorities')).body.authorities.map((a: any) => a.name)).toContain('Notary');
      expect((await h.api(other, 'GET', '/attestation-authorities')).body.authorities).toEqual([]);
      const ev = (await admin.query(`SELECT action, payload FROM account_event WHERE action = 'attestation_authority.registered' ORDER BY seq DESC LIMIT 1`)).rows[0];
      expect(ev.payload).toMatchObject({ authority_id: r.body.authority.id, name: 'Notary', algorithm: 'ES256' });
    });

    it('refuses a private key, a malformed key, a duplicate name or key, and unknown fields', async () => {
      const key = newKey('Ed25519');
      const priv = { ...key.publicJwk, d: crypto.randomBytes(32).toString('base64url') };
      expect((await h.api(creator, 'POST', '/attestation-authorities', { name: 'x1', public_key: priv })).status).toBe(400);
      expect((await h.api(creator, 'POST', '/attestation-authorities', { name: 'x2', public_key: { kty: 'RSA' } })).status).toBe(400);
      expect((await h.api(creator, 'POST', '/attestation-authorities', { name: '', public_key: key.publicJwk })).status).toBe(400);
      expect((await h.api(creator, 'POST', '/attestation-authorities', { name: 'x3', public_key: key.publicJwk, extra: 1 })).status).toBe(400);
      expect((await h.api(creator, 'POST', '/attestation-authorities', { name: 'First', public_key: key.publicJwk })).status).toBe(201);
      expect((await h.api(creator, 'POST', '/attestation-authorities', { name: 'First', public_key: newKey('Ed25519').publicJwk })).status).toBe(409);
      expect((await h.api(creator, 'POST', '/attestation-authorities', { name: 'Second', public_key: key.publicJwk })).status).toBe(409);
    });

    it('can be revoked, once and for good; only by the owner', async () => {
      const a = await authority('To revoke');
      expect((await h.api(other, 'POST', `/attestation-authorities/${a.id}/revoke`, {})).status).toBe(404);
      const r = await h.api(creator, 'POST', `/attestation-authorities/${a.id}/revoke`, {});
      expect(r.status).toBe(200);
      expect(r.body.authority.revoked_at).not.toBeNull();
      const again = await h.api(creator, 'POST', `/attestation-authorities/${a.id}/revoke`, {});
      expect(again.body.authority.revoked_at).toBe(r.body.authority.revoked_at);
      await expect(admin.query(`UPDATE attestation_authority SET revoked_at = NULL WHERE id = $1`, [a.id])).rejects.toThrow(/cannot be undone/);
      await expect(admin.query(`DELETE FROM attestation_authority WHERE id = $1`, [a.id])).rejects.toThrow(/only be revoked|cannot be deleted/);
      await expect(admin.query(`UPDATE attestation_authority SET name = 'renamed' WHERE id = $1`, [a.id])).rejects.toThrow(/only revocation/);
      const n = (await admin.query(`SELECT count(*)::int AS n FROM account_event WHERE action = 'attestation_authority.revoked' AND payload->>'authority_id' = $1`, [a.id])).rows[0].n;
      expect(n).toBe(1);
    });
  });

  describe('attestations', () => {
    it('are verified, stored, recorded with hashes only, repeatable, and readable', async () => {
      const a = await authority('Signer A');
      const b = await authority('Signer B', 'ES256');
      const s = await session(2);
      const payload = { reviewer: 'alice', checklist: 12 };
      const body = attest(s.id, a, { subject_commit: s.commits[0] }, payload);
      const r = await post(creator, s.id, body);
      expect(r.status, JSON.stringify(r.body)).toBe(201);
      expect(r.body).toMatchObject({ recorded: true, claim: 'owner.reviewed', subject_commit: s.commits[0], authority: { id: a.id, name: 'Signer A', active: true }, signature: { algorithm: 'Ed25519' } });
      expect((await post(creator, s.id, attest(s.id, b, { subject_commit: s.commits[1], claim: 'ownership' }))).status).toBe(201); // ES256
      const stored = await rows(s.id);
      expect(stored).toHaveLength(2);
      expect(stored.find((x) => x.claim === 'owner.reviewed')).toMatchObject({ raw_payload: payload, payload_sha256: payloadSha256(payload), submitted_by_creator_id: creator.id });
      const ev = (await events()).filter((e) => e.action === 'attestation.recorded' && e.subject_id === s.id);
      expect(ev).toHaveLength(2);
      expect(ev[0]).toMatchObject({ actor_type: 'creator', actor_id: creator.id });
      expect(JSON.stringify(ev[0].payload)).not.toContain('alice');

      const again = await post(creator, s.id, body);
      expect(again.status).toBe(200);
      expect(again.body).toMatchObject({ recorded: false, id: r.body.id });
      expect(await rows(s.id)).toHaveLength(2);

      const list = await h.api(creator, 'GET', `/projects/${projectId}/work-sessions/${s.id}/attestations`);
      expect(list.body.attestations).toHaveLength(2);
      const filtered = await h.api(creator, 'GET', `/projects/${projectId}/work-sessions/${s.id}/attestations?commit=${s.commits[1]}`);
      expect(filtered.body.attestations.map((x: any) => x.claim)).toEqual(['ownership']);
      expect((await v2get(requester, `/work-sessions/${s.id}/attestations`)).body.attestations).toHaveLength(2);
      expect((await v2get(stranger, `/work-sessions/${s.id}/attestations`)).status).toBe(404);
    });

    it('can be verified again by anyone, offline, from the stored fields and the authority\'s public key', async () => {
      const a = await authority('Offline');
      const s = await session();
      expect((await post(creator, s.id, attest(s.id, a, { subject_commit: s.commits[0] }, { n: 1 }))).status).toBe(201);
      const t = (await rows(s.id))[0];
      const auth = (await db.query(`SELECT public_key_jwk FROM attestation_authority WHERE id = $1`, [a.id])).rows[0];
      const input = attestationSigningInput({ authority_id: t.authority_id, work_session_id: t.work_session_id, claim: t.claim, subject_commit: t.subject_commit, payload_sha256: t.payload_sha256, issued_at: new Date(t.issued_at).toISOString().replace('.000Z', 'Z') });
      expect(JSON.parse(input).format).toBe('custody-core.attestation.v1');
      const pub = crypto.createPublicKey({ key: auth.public_key_jwk, format: 'jwk' });
      expect(crypto.verify(null, Buffer.from(input), pub, Buffer.from(t.signature_value, 'base64url'))).toBe(true);
    });

    it('are refused unless the signature verifies over exactly this statement with the authority\'s own key', async () => {
      const a = await authority('Strict A');
      const b = await authority('Strict B');
      const s = await session(2);
      const good = attest(s.id, a, { subject_commit: s.commits[0] });
      const otherSession = await session();
      const cases: Array<[string, any]> = [
        ['changed claim', { ...good, claim: 'owner.approved' }],
        ['changed commit', { ...good, subject_commit: s.commits[1] }],
        ['changed time', { ...good, issued_at: '2030-01-01T00:00:00Z' }],
        ['changed payload', { ...good, payload: { extra: 1 } }],
        ['signed for another session', attest(otherSession.id, a, { subject_commit: s.commits[0] })],
        ['named another authority', { ...good, authority_id: b.id }],
        ['signed by another authority\'s key', attest(s.id, { id: a.id, key: b.key }, { subject_commit: s.commits[0] })],
        ['garbage signature', { ...good, signature: { algorithm: 'Ed25519', value: 'A'.repeat(86) } }]
      ];
      for (const [why, body] of cases) {
        const r = await post(creator, s.id, body);
        expect(r.status, `${why}: ${JSON.stringify(r.body)}`).toBe(422);
      }
      expect((await post(creator, s.id, { ...good, signature: { ...good.signature, algorithm: 'ES256' } })).body.code).toBe('bad_signature');
      expect(await rows(s.id)).toHaveLength(0);
    });

    it('is bound to the session\'s own commits and to a sensible time', async () => {
      const a = await authority('Binding');
      const s = await session();
      expect((await post(creator, s.id, attest(s.id, a, { subject_commit: commitId() }))).body.code).toBe('unknown_commit');
      const other = await session();
      expect((await post(creator, s.id, attest(s.id, a, { subject_commit: other.commits[0] }))).body.code).toBe('unknown_commit');
      expect((await post(creator, s.id, attest(s.id, a, { subject_commit: s.commits[0], issued_at: '2020-01-01T00:00:00Z' }))).body.code).toBe('issued_before_commit');
      const future = new Date(Date.now() + 3600_000).toISOString().replace(/\.\d+Z$/, 'Z');
      expect((await post(creator, s.id, attest(s.id, a, { subject_commit: s.commits[0], issued_at: future }))).body.code).toBe('issued_in_future');
      expect(await rows(s.id)).toHaveLength(0);
    });

    it('cannot be recorded for another owner\'s session or with another owner\'s authority; a revoked authority is refused, and what it signed earlier shows as inactive', async () => {
      const mine = await authority('Mine');
      const theirs = await authority('Theirs', 'Ed25519', other);
      const s = await session();
      expect((await post(creator, s.id, attest(s.id, theirs, { subject_commit: s.commits[0] }))).status).toBe(404);
      expect((await post(other, s.id, attest(s.id, mine, { subject_commit: s.commits[0] }))).status).toBe(404);
      expect((await post(creator, crypto.randomUUID(), attest(s.id, mine, { subject_commit: s.commits[0] }))).status).toBe(404);
      expect((await post(creator, s.id, attest(s.id, mine, { subject_commit: s.commits[0] }))).status).toBe(201);
      await h.api(creator, 'POST', `/attestation-authorities/${mine.id}/revoke`, {});
      const after = await post(creator, s.id, attest(s.id, mine, { subject_commit: s.commits[0], claim: 'second.claim' }));
      expect(after.status).toBe(422);
      expect(after.body.code).toBe('authority_revoked');
      const list = await h.api(creator, 'GET', `/projects/${projectId}/work-sessions/${s.id}/attestations`);
      expect(list.body.attestations).toHaveLength(1);
      expect(list.body.attestations[0].authority.active).toBe(false);
    });

    it('is checked for malformed input and for secrets in the payload', async () => {
      const a = await authority('Input');
      const s = await session();
      const good = attest(s.id, a, { subject_commit: s.commits[0] });
      for (const [why, body] of [
        ['unknown field', { ...good, extra: 1 }],
        ['bad claim', { ...good, claim: 'Owner Reviewed' }],
        ['bad commit', { ...good, subject_commit: 'abc' }],
        ['bad time', { ...good, issued_at: '2026-01-01 10:00' }],
        ['bad authority id', { ...good, authority_id: 'x' }],
        ['bad signature shape', { ...good, signature: { algorithm: 'RS256', value: 'x' } }],
        ['decimals in the payload', { ...good, payload: { score: 0.5 } }]
      ] as const) {
        expect((await post(creator, s.id, body)).status, why).toBe(400);
      }
      const { privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
      const pem = privateKey.export({ type: 'pkcs1', format: 'pem' }).toString();
      const leaky = await post(creator, s.id, attest(s.id, a, { subject_commit: s.commits[0] }, { log: pem }));
      expect(leaky.status).toBe(400);
      expect(leaky.body.code).toBe('secret_found');
      expect(JSON.stringify(leaky.body)).not.toContain(pem.split('\n')[1]);
      expect(await rows(s.id)).toHaveLength(0);
    });

    it('the database refuses what the application would refuse (the backstop), and the record is written once', async () => {
      const a = await authority('Backstop');
      const revoked = await authority('Backstop revoked');
      await h.api(creator, 'POST', `/attestation-authorities/${revoked.id}/revoke`, {});
      const theirs = await authority('Backstop theirs', 'Ed25519', other);
      const s = await session();
      const insert = (o: { authority: string; commit: string; alg?: string; by?: string }) =>
        db.query(
          `INSERT INTO attestation (work_session_id, authority_id, claim, subject_commit, payload_sha256, issued_at, signature_algorithm, signature_value, submitted_by_creator_id)
           VALUES ($1, $2, 'c', $3, $4, now(), $5, $6, $7)`,
          [s.id, o.authority, o.commit, crypto.createHash('sha256').update('{}').digest('hex'), o.alg ?? 'Ed25519', 'A'.repeat(86), o.by ?? creator.id]
        );
      await expect(insert({ authority: revoked.id, commit: s.commits[0] })).rejects.toThrow(/unrevoked authority/);
      await expect(insert({ authority: theirs.id, commit: s.commits[0] })).rejects.toThrow(/unrevoked authority/);
      await expect(insert({ authority: a.id, commit: s.commits[0], alg: 'ES256' })).rejects.toThrow(/unrevoked authority/);
      await expect(insert({ authority: a.id, commit: s.commits[0], by: other.id })).rejects.toThrow(/unrevoked authority/);
      await expect(insert({ authority: a.id, commit: commitId() })).rejects.toThrow(/not one this session produced/);
      await insert({ authority: a.id, commit: s.commits[0] });
      await expect(db.query(`UPDATE attestation SET claim = 'x' WHERE work_session_id = $1`, [s.id])).rejects.toThrow();
      await expect(db.query(`DELETE FROM attestation WHERE work_session_id = $1`, [s.id])).rejects.toThrow();
      await expect(admin.query(`UPDATE attestation SET claim = 'x' WHERE work_session_id = $1`, [s.id])).rejects.toThrow(/written once/);
    });
  });

  it('the project\'s record still verifies', async () => {
    const check = await verifyServerProjectEvents(projectId);
    expect(check.isValid, check.reason).toBe(true);
  });
});
