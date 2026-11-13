import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import crypto from 'node:crypto';
import fs from 'node:fs';
import { getAdminPool, getDbPool, runMigrations } from '../server/db';
import { addPrincipalKey, registerPrincipal, setPrincipalStatus } from '../server/servicePrincipals';
import { attestationSigningInput } from '../server/attestation';
import { payloadSha256 } from '../server/evidence';
import { assertPoolTargetsTestDb } from './support/safety';
import { startHarness, Harness } from './support/apiHarness';
import { startApp, RunningApp } from './support/api';
import { installGitleaks } from '../scripts/install-gitleaks';
import { assertion, newKey, sign, TestAlg, TestKey } from './support/principalKeys';
import { checkRequest, checkResponse, findOperation } from './support/openapiCheck';

/**
 * Contract "commit-attribution-submission" v1 (docs/contracts/commit-attribution-submission.v1.md): a service principal delivers a detached signed
 * statement about a commit of its own session. Everything here uses a disposable signer, disposable repositories and a disposable database.
 */
describe('Machine submission of commit attributions', () => {
  const db = getDbPool()!;
  const admin = getAdminPool()!;
  let h: Harness;
  let app: RunningApp;
  let creator: any, other: any;
  let projectA = '', projectB = '', repoA = '', repoB = '', otherProject = '', otherRepo = '';
  interface Caller { id: string; keyId: string; key: TestKey }
  let courier: Caller, courier2: Caller, ungranted: Caller, noScope: Caller, readOnly: Caller, otherCourier: Caller;
  interface Authority { id: string; key: TestKey }
  let signer: Authority, unrelated: Authority;
  const commitId = () => crypto.randomBytes(20).toString('hex');
  const now = () => new Date().toISOString().replace(/\.\d+Z$/, 'Z');
  const CLAIM = 'commit.attribution';

  async function caller(label: string, scopes: string[], who = creator, projects?: string[]): Promise<Caller> {
    const p = await registerPrincipal(db, who.id, { name: `${label}-${crypto.randomUUID().slice(0, 6)}`, platform_type: 'agent', environment: 'development', allowed_scopes: scopes, ...(projects ? { allowed_project_ids: projects } : {}) } as any, 'test');
    const key = newKey('Ed25519');
    return { id: p.id, keyId: (await addPrincipalKey(db, p.id, key.publicJwk, 'test')).key_id, key };
  }
  const bearer = (c: Caller) => `Bearer ${assertion(c.key, c.keyId, c.id)}`;
  async function v2(c: Caller, method: string, path: string, body?: unknown) {
    const res = await fetch(`${app.base}/api/v2${path}`, { method, headers: { Authorization: bearer(c), ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) }, body: body === undefined ? undefined : JSON.stringify(body) });
    return { status: res.status, body: (await res.json().catch(() => ({}))) as any };
  }
  async function authority(name: string, alg: TestAlg = 'Ed25519'): Promise<Authority> {
    const key = newKey(alg);
    const r = await h.api(creator, 'POST', '/attestation-authorities', { name: `${name}-${crypto.randomUUID().slice(0, 6)}`, public_key: key.publicJwk });
    expect(r.status, JSON.stringify(r.body)).toBe(201);
    return { id: r.body.authority.id, key };
  }
  const grant = (principal: Caller, a: Authority, project = projectA, who = creator) => h.api(who, 'POST', '/attestation-submission-grants', { principal_id: principal.id, authority_id: a.id, project_id: project });

  /** A session requested by `by`, approved by the owner, running, with real commits recorded (as the gateway records them). */
  async function session(by: Caller, project = projectA, repo = repoA, commits = 1, owner = creator) {
    const res = await v2(by, 'POST', '/work-sessions', {
      project_id: project, repository_id: repo, executor: { type: 'ai_assistant', display_name: 'Engine' }, sponsor: { type: 'creator', id: owner.id }, objective: 'Add the export page',
      base_commit: 'a'.repeat(40), access: { repository: 'read_and_push', allowed_read_paths: ['src/**'], allowed_write_paths: ['src/lib/**'], prohibited_paths: [] }
    });
    expect(res.status, JSON.stringify(res.body)).toBe(202);
    const id = res.body.session_id as string;
    expect((await h.api(owner, 'POST', `/projects/${project}/work-sessions/${id}/approve`, {})).status).toBe(200);
    await admin.query(`UPDATE work_session SET status = 'active' WHERE id = $1`, [id]);
    const shas: string[] = [];
    for (let i = 0; i < commits; i++) {
      const real = commitId();
      shas.push(real);
      await admin.query(`INSERT INTO session_commit (work_session_id, view_sha, real_sha, parent_view_sha, declared_author) VALUES ($1, $2, $3, $4, 'x')`, [id, commitId(), real, commitId()]);
    }
    return { id, commits: shas };
  }
  function statement(sessionId: string, a: Authority, over: Record<string, unknown> = {}, payload: Record<string, unknown> = { author_kind: 'ai_assistant', model: 'm1' }) {
    const f = { authority_id: a.id, work_session_id: sessionId, claim: CLAIM, subject_commit: '', payload_sha256: payloadSha256(payload), issued_at: now(), ...over };
    const { work_session_id: _w, payload_sha256: _p, ...rest } = f;
    return { ...rest, payload, signature: { algorithm: a.key.alg, value: sign(a.key, attestationSigningInput(f as any)) } };
  }
  const submit = (c: Caller, sessionId: string, body: unknown) => v2(c, 'POST', `/work-sessions/${sessionId}/attestations`, body);
  const stored = async (sessionId: string) => (await db.query('SELECT * FROM attestation WHERE work_session_id = $1', [sessionId])).rows;

  beforeAll(async () => {
    await assertPoolTargetsTestDb(admin);
    expect((await runMigrations()).success).toBe(true);
    await installGitleaks();
    h = await startHarness();
    app = await startApp();
    creator = await h.newCreator('owner');
    other = await h.newCreator('other');
    const mk = async (owner: any, name: string, n: string) => {
      const p = (await db.query(`INSERT INTO project (creator_id, name, purpose) VALUES ($1, $2, 'x') RETURNING id`, [owner.id, name])).rows[0].id as string;
      const r = (await db.query(`INSERT INTO repository (project_id, github_repo_id, full_name) VALUES ($1, $2, $3) RETURNING id`, [p, n, `org/app-${n}`])).rows[0].id as string;
      return [p, r];
    };
    [projectA, repoA] = await mk(creator, 'A', '1');
    [projectB, repoB] = await mk(creator, 'B', '2');
    [otherProject, otherRepo] = await mk(other, 'Other', '3');
    const submitScopes = ['work-sessions:request', 'work-sessions:read', 'attestations:submit'];
    courier = await caller('courier', submitScopes);
    courier2 = await caller('courier2', submitScopes);
    ungranted = await caller('ungranted', submitScopes);
    noScope = await caller('noscope', ['work-sessions:request', 'work-sessions:read']);
    readOnly = await caller('readonly', ['work-sessions:read']);
    otherCourier = await caller('othercourier', submitScopes, other);
    signer = await authority('Signer');
    unrelated = await authority('Unrelated', 'ES256');
    expect((await grant(courier, signer)).status).toBe(201);
    expect((await grant(courier2, signer)).status).toBe(201);
  }, 120_000);
  afterAll(async () => {
    await app?.stop();
    await h?.stop();
  });

  describe('the owner\'s grant', () => {
    it('is explicit, bounded to one principal, one authority and one project, and recorded', async () => {
      const p = await caller('granted', ['attestations:submit']);
      const r = await grant(p, signer);
      expect(r.status, JSON.stringify(r.body)).toBe(201);
      expect(r.body.grant).toMatchObject({ principal_id: p.id, authority_id: signer.id, project_id: projectA, revoked_at: null });
      expect((await h.api(creator, 'GET', '/attestation-submission-grants')).body.grants.map((g: any) => g.id)).toContain(r.body.grant.id);
      expect((await h.api(other, 'GET', '/attestation-submission-grants')).body.grants).toEqual([]);
      const ev = (await admin.query(`SELECT payload FROM account_event WHERE action = 'attestation_submission_grant.created' AND payload->>'grant_id' = $1`, [r.body.grant.id])).rows[0];
      expect(ev.payload).toMatchObject({ principal_id: p.id, authority_id: signer.id, project_id: projectA });
      expect((await grant(p, signer)).status).toBe(409);
    });

    it('cannot be made for a principal without the scope, another owner\'s things, an inactive principal, or a project off its list', async () => {
      const r = await grant(noScope, signer);
      expect(r.status).toBe(422);
      expect(r.body.code).toBe('scope_missing');
      expect((await grant(otherCourier, signer)).status).toBe(404); // not creator's principal
      expect((await grant(courier, signer, otherProject)).status).toBe(404);
      const theirs = (await h.api(other, 'POST', '/attestation-authorities', { name: 'theirs', public_key: newKey('Ed25519').publicJwk })).body.authority.id;
      expect((await h.api(creator, 'POST', '/attestation-submission-grants', { principal_id: courier.id, authority_id: theirs, project_id: projectA })).status).toBe(404);
      const listed = await caller('listed', ['attestations:submit'], creator, [projectA]);
      const off = await grant(listed, signer, projectB);
      expect(off.status).toBe(422);
      expect(off.body.code).toBe('project_not_allowed');
      const sus = await caller('suspended', ['attestations:submit']);
      await setPrincipalStatus(db, sus.id, 'suspended', 'test');
      expect((await grant(sus, signer)).body.code).toBe('principal_inactive');
      expect((await h.api(creator, 'POST', '/attestation-submission-grants', { principal_id: courier.id, authority_id: signer.id, project_id: projectA, extra: 1 })).status).toBe(400);
    });

    it('can be revoked, once and for good, and only by its owner', async () => {
      const p = await caller('torevoke', ['attestations:submit', 'work-sessions:request']);
      const id = (await grant(p, signer)).body.grant.id;
      expect((await h.api(other, 'POST', `/attestation-submission-grants/${id}/revoke`, {})).status).toBe(404);
      const r = await h.api(creator, 'POST', `/attestation-submission-grants/${id}/revoke`, {});
      expect(r.body.grant.revoked_at).not.toBeNull();
      expect((await h.api(creator, 'POST', `/attestation-submission-grants/${id}/revoke`, {})).body.grant.revoked_at).toBe(r.body.grant.revoked_at);
      await expect(admin.query(`UPDATE attestation_submission_grant SET revoked_at = NULL WHERE id = $1`, [id])).rejects.toThrow(/cannot be undone/);
      await expect(admin.query(`DELETE FROM attestation_submission_grant WHERE id = $1`, [id])).rejects.toThrow(/only be revoked|cannot be deleted/);
      expect((await grant(p, signer)).status).toBe(409); // a revoked grant stays revoked
      const s = await session(p);
      const sub = await submit(p, s.id, statement(s.id, signer, { subject_commit: s.commits[0] }));
      expect(sub.status).toBe(403);
      expect(sub.body.code).toBe('not_granted');
    });
  });

  describe('submitting', () => {
    it('records the statement, answers with a receipt, and the receipt is readable through the existing read path', async () => {
      const s = await session(courier);
      const body = statement(s.id, signer, { subject_commit: s.commits[0] });
      const r = await submit(courier, s.id, body);
      expect(r.status, JSON.stringify(r.body)).toBe(201);
      const stmt = { authority_id: signer.id, work_session_id: s.id, claim: CLAIM, subject_commit: s.commits[0], payload_sha256: payloadSha256(body.payload), issued_at: body.issued_at };
      expect(r.body).toMatchObject({
        recorded: true, claim: CLAIM, subject_commit: s.commits[0], authority: { id: signer.id, active: true },
        receipt: { contract: 'commit-attribution-submission/1', work_session_id: s.id, authority_id: signer.id, claim: CLAIM, subject_commit: s.commits[0], statement_sha256: crypto.createHash('sha256').update(attestationSigningInput(stmt), 'utf8').digest('hex') }
      });
      expect(r.body.receipt.attestation_id).toBe(r.body.id);
      const read = await v2(courier, 'GET', `/work-sessions/${s.id}/attestations?commit=${s.commits[0]}`);
      expect(read.status).toBe(200);
      expect(read.body.attestations).toHaveLength(1);
      expect(read.body.attestations[0]).toMatchObject({ id: r.body.receipt.attestation_id, claim: CLAIM, subject_commit: s.commits[0], recorded_at: r.body.receipt.recorded_at });
      const row = (await stored(s.id))[0];
      expect(row.submitted_by_principal_id).toBe(courier.id);
      expect(row.submitted_by_creator_id).toBe(creator.id); // the owner it was resolved to, from our records
      const ev = (await admin.query(`SELECT actor_type, actor_id, payload FROM event WHERE project_id = $1 AND action = 'attestation.recorded' AND subject_id = $2`, [projectA, s.id])).rows;
      expect(ev).toHaveLength(1);
      expect(ev[0]).toMatchObject({ actor_type: 'system', actor_id: `principal:${courier.id}` });
      expect(ev[0].payload).toMatchObject({ attestation_id: r.body.id, submitted_by_principal_id: courier.id, claim: CLAIM, subject_commit: s.commits[0] });
      expect(JSON.stringify(ev[0].payload)).not.toContain(body.signature.value); // hashes and ids only, as for the owner's route
    });

    it('answers an identical retry with the same receipt and records nothing twice', async () => {
      const s = await session(courier);
      const body = statement(s.id, signer, { subject_commit: s.commits[0] });
      const first = await submit(courier, s.id, body);
      const again = await submit(courier, s.id, body);
      expect(first.status).toBe(201);
      expect(again.status).toBe(200);
      expect(again.body.recorded).toBe(false);
      expect(again.body.receipt).toEqual(first.body.receipt);
      expect(await stored(s.id)).toHaveLength(1);
      expect((await admin.query(`SELECT count(*)::int AS n FROM event WHERE project_id = $1 AND action = 'attestation.recorded' AND subject_id = $2`, [projectA, s.id])).rows[0].n).toBe(1);
    });

    it('handles concurrent identical submissions: one record, one event, one receipt', async () => {
      const s = await session(courier);
      const body = statement(s.id, signer, { subject_commit: s.commits[0] });
      const results = await Promise.all(Array.from({ length: 8 }, () => submit(courier, s.id, body)));
      expect(results.map((r) => r.status).sort()).toEqual([200, 200, 200, 200, 200, 200, 200, 201]);
      expect(new Set(results.map((r) => JSON.stringify(r.body.receipt))).size).toBe(1);
      expect(await stored(s.id)).toHaveLength(1);
      expect((await admin.query(`SELECT count(*)::int AS n FROM event WHERE project_id = $1 AND action = 'attestation.recorded' AND subject_id = $2`, [projectA, s.id])).rows[0].n).toBe(1);
    });

    it('takes nothing about the owner, sponsor, requester, repository or project from the request', async () => {
      const s = await session(courier);
      const body = statement(s.id, signer, { subject_commit: s.commits[0] });
      for (const extra of [{ creator_id: other.id }, { sponsor: { type: 'creator', id: other.id } }, { requester: courier2.id }, { project_id: projectB }, { repository_id: repoB }, { submitted_by_principal_id: courier2.id }]) {
        const r = await submit(courier, s.id, { ...body, ...extra });
        expect(r.status, JSON.stringify(extra)).toBe(400);
      }
      expect(await stored(s.id)).toHaveLength(0);
    });
  });

  describe('what is refused', () => {
    it('a principal without the scope, with the scope but no grant, or with only read access', async () => {
      const s = await session(noScope);
      const body = statement(s.id, signer, { subject_commit: s.commits[0] });
      expect((await submit(noScope, s.id, body)).status).toBe(403);
      expect((await submit(readOnly, s.id, body)).status).toBe(403);
      const mine = await session(ungranted);
      const r = await submit(ungranted, mine.id, statement(mine.id, signer, { subject_commit: mine.commits[0] }));
      expect(r.status).toBe(403);
      expect(r.body.code).toBe('not_granted');
      expect(await stored(s.id)).toHaveLength(0);
      expect(await stored(mine.id)).toHaveLength(0);
    });

    it('an authority that was not granted, even a real one of the same owner; an authority of another owner reads the same', async () => {
      const s = await session(courier);
      const viaUnrelated = await submit(courier, s.id, statement(s.id, unrelated, { subject_commit: s.commits[0] }));
      expect(viaUnrelated.status).toBe(403);
      expect(viaUnrelated.body.code).toBe('not_granted');
      const foreign = { id: crypto.randomUUID(), key: newKey('Ed25519') };
      const viaForeign = await submit(courier, s.id, statement(s.id, foreign, { subject_commit: s.commits[0] }));
      expect(viaForeign.status).toBe(403);
      expect(viaForeign.body).toEqual(viaUnrelated.body);
      expect(await stored(s.id)).toHaveLength(0);
    });

    it('a revoked authority, even though the grant still stands', async () => {
      const a = await authority('Short-lived');
      const p = await caller('c3', ['work-sessions:request', 'attestations:submit']);
      expect((await grant(p, a)).status).toBe(201);
      const s = await session(p);
      expect((await h.api(creator, 'POST', `/attestation-authorities/${a.id}/revoke`, {})).status).toBe(200);
      const r = await submit(p, s.id, statement(s.id, a, { subject_commit: s.commits[0] }));
      expect(r.status).toBe(422);
      expect(r.body.code).toBe('authority_revoked');
      expect(await stored(s.id)).toHaveLength(0);
      const fresh = await authority('Replacement');
      await expect(grant(p, fresh).then((x) => x.status)).resolves.toBe(201);
    });

    it('another project, another session, and another owner\'s session', async () => {
      // The grant is for project A. A session of the same principal in project B is not covered.
      const inB = await session(courier, projectB, repoB);
      const r = await submit(courier, inB.id, statement(inB.id, signer, { subject_commit: inB.commits[0] }));
      expect(r.status).toBe(403);
      expect(r.body.code).toBe('not_granted');
      // A session requested by a different principal (which holds its own grant) is not found.
      const theirs = await session(courier2);
      const cross = await submit(courier, theirs.id, statement(theirs.id, signer, { subject_commit: theirs.commits[0] }));
      expect(cross.status).toBe(404);
      // Another owner's session is not found either.
      const foreign = await session(otherCourier, otherProject, otherRepo, 1, other);
      expect((await submit(courier, foreign.id, statement(foreign.id, signer, { subject_commit: foreign.commits[0] }))).status).toBe(404);
      expect((await submit(courier, crypto.randomUUID(), statement(theirs.id, signer, { subject_commit: theirs.commits[0] }))).status).toBe(404);
      for (const id of [inB.id, theirs.id, foreign.id]) expect(await stored(id)).toHaveLength(0);
    });

    it('a principal whose project list excludes the session\'s project', async () => {
      const p = await caller('narrow', ['work-sessions:request', 'attestations:submit'], creator, [projectA, projectB]);
      expect((await grant(p, signer, projectA)).status).toBe(201);
      const s = await session(p, projectB, repoB); // allowed to request, but not granted for B
      expect((await submit(p, s.id, statement(s.id, signer, { subject_commit: s.commits[0] }))).body.code).toBe('not_granted');
      await db.query(`UPDATE service_principal SET allowed_project_ids = $2 WHERE id = $1`, [p.id, [projectA]]);
      expect((await submit(p, s.id, statement(s.id, signer, { subject_commit: s.commits[0] }))).status).toBe(404);
    });

    it('a commit the session did not produce', async () => {
      const s = await session(courier);
      const r = await submit(courier, s.id, statement(s.id, signer, { subject_commit: commitId() }));
      expect(r.status).toBe(422);
      expect(r.body.code).toBe('unknown_commit');
      const mine = await session(courier2);
      const crossSession = await submit(courier, s.id, statement(s.id, signer, { subject_commit: mine.commits[0] })); // another session's commit
      expect(crossSession.body.code).toBe('unknown_commit');
      expect(await stored(s.id)).toHaveLength(0);
    });

    it('any claim but commit.attribution', async () => {
      const s = await session(courier);
      const r = await submit(courier, s.id, statement(s.id, signer, { subject_commit: s.commits[0], claim: 'owner.reviewed' }));
      expect(r.status).toBe(422);
      expect(r.body.code).toBe('claim_not_allowed');
      expect(await stored(s.id)).toHaveLength(0);
    });

    it('a statement changed after it was signed: the claim, the commit, the payload, the time or the signature', async () => {
      const s = await session(courier, projectA, repoA, 2);
      const good = statement(s.id, signer, { subject_commit: s.commits[0] });
      const bad = (over: Record<string, unknown>) => submit(courier, s.id, { ...good, ...over });
      for (const over of [{ subject_commit: s.commits[1] }, { payload: { author_kind: 'human' } }, { issued_at: new Date(Date.parse(good.issued_at) + 1000).toISOString().replace(/\.\d+Z$/, 'Z') }, { signature: { ...good.signature, value: 'A'.repeat(86) } }]) {
        const r = await bad(over);
        expect(r.status, JSON.stringify(over)).toBe(422);
        expect(r.body.code).toBe('bad_signature');
      }
      // A statement signed for a different claim does not verify as an attribution either.
      const signedAsOther = statement(s.id, signer, { subject_commit: s.commits[0], claim: 'owner.reviewed' });
      expect((await bad({ signature: signedAsOther.signature })).body.code).toBe('bad_signature');
      // The wrong algorithm for the authority's key.
      expect((await bad({ signature: { algorithm: 'ES256', value: good.signature.value } })).body.code).toBe('bad_signature');
      expect(await stored(s.id)).toHaveLength(0);
      expect((await submit(courier, s.id, good)).status).toBe(201); // and the untouched statement still goes through
    });

    it('a secret in the payload, a statement from the future, and one older than its commit', async () => {
      const s = await session(courier);
      const secret = await submit(courier, s.id, statement(s.id, signer, { subject_commit: s.commits[0] }, { note: 'ghp_' + 'a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8' }));
      expect(secret.body.code).toBe('secret_found');
      const future = await submit(courier, s.id, statement(s.id, signer, { subject_commit: s.commits[0], issued_at: new Date(Date.now() + 3_600_000).toISOString().replace(/\.\d+Z$/, 'Z') }));
      expect(future.body.code).toBe('issued_in_future');
      const early = await submit(courier, s.id, statement(s.id, signer, { subject_commit: s.commits[0], issued_at: '2001-01-01T00:00:00Z' }));
      expect(early.body.code).toBe('issued_before_commit');
      expect(await stored(s.id)).toHaveLength(0);
    });

    it('a suspended principal is refused before anything else', async () => {
      const p = await caller('soonsuspended', ['work-sessions:request', 'attestations:submit']);
      expect((await grant(p, signer)).status).toBe(201);
      const s = await session(p);
      const body = statement(s.id, signer, { subject_commit: s.commits[0] });
      await setPrincipalStatus(db, p.id, 'suspended', 'test');
      expect((await submit(p, s.id, body)).status).toBe(401);
      expect(await stored(s.id)).toHaveLength(0);
    });
  });

  describe('the database holds the line too', () => {
    const insert = (sessionId: string, principalId: string | null, over: Record<string, unknown> = {}) => {
      const f = { authority: signer.id, claim: CLAIM, ...over };
      return admin.query(
        `INSERT INTO attestation (work_session_id, authority_id, claim, subject_commit, payload_sha256, issued_at, signature_algorithm, signature_value, submitted_by_creator_id, submitted_by_principal_id)
         SELECT $1, $2, $3, c.real_sha, $4, now(), 'Ed25519', $5, $6, $7 FROM session_commit c WHERE c.work_session_id = $1 LIMIT 1`,
        [sessionId, f.authority, f.claim, payloadSha256({}), 'A'.repeat(86), creator.id, principalId]
      );
    };
    it('refuses a machine submission without a live grant, for another claim, or by a principal that did not request the session', async () => {
      const s = await session(courier);
      await expect(insert(s.id, ungranted.id)).rejects.toThrow(/no live grant/);
      await expect(insert(s.id, courier2.id)).rejects.toThrow(/no live grant/); // granted, but not the requester
      await expect(insert(s.id, courier.id, { claim: 'owner.reviewed' })).rejects.toThrow(/only carry the commit.attribution claim/);
      await expect(insert(s.id, courier.id, { authority: unrelated.id })).rejects.toThrow(/no live grant|authority must be/);
      await insert(s.id, courier.id); // the lawful row is accepted
      expect(await stored(s.id)).toHaveLength(1);
      await insert(s.id, null, { claim: 'owner.reviewed' }); // the owner's own path is unchanged: any claim
    });

    it('refuses a grant whose principal lacks the scope, and the scope on a principal that approves', async () => {
      await expect(admin.query(`INSERT INTO attestation_submission_grant (creator_id, principal_id, authority_id, project_id) VALUES ($1, $2, $3, $4)`, [creator.id, noScope.id, signer.id, projectA])).rejects.toThrow(/must all belong/);
      await expect(registerPrincipal(db, creator.id, { name: 'both', platform_type: 'agent', environment: 'development', allowed_scopes: ['attestations:submit', 'work-sessions:approve'] } as any, 'test')).rejects.toThrow(/cannot also hold/);
      await expect(admin.query(`UPDATE service_principal SET allowed_scopes = allowed_scopes || ARRAY['attestations:submit'] WHERE id = $1`, [noScope.id])).rejects.toThrow(/scopes can only be removed/);
    });
  });

  describe('existing behaviour is unchanged', () => {
    it('the owner\'s route still takes any claim, records the owner as the actor, and has no principal', async () => {
      const s = await session(courier);
      const body = statement(s.id, signer, { subject_commit: s.commits[0], claim: 'owner.reviewed' });
      const r = await h.api(creator, 'POST', `/projects/${projectA}/work-sessions/${s.id}/attestations`, body);
      expect(r.status, JSON.stringify(r.body)).toBe(201);
      expect(r.body).toMatchObject({ recorded: true, claim: 'owner.reviewed' });
      expect(r.body.receipt).toBeUndefined();
      const row = (await stored(s.id))[0];
      expect(row.submitted_by_principal_id).toBeNull();
      const ev = (await admin.query(`SELECT actor_type, actor_id, payload FROM event WHERE project_id = $1 AND action = 'attestation.recorded' AND subject_id = $2`, [projectA, s.id])).rows[0];
      expect(ev).toMatchObject({ actor_type: 'creator', actor_id: creator.id });
      expect(ev.payload.submitted_by_principal_id).toBeUndefined();
      expect((await h.api(creator, 'POST', `/projects/${projectA}/work-sessions/${s.id}/attestations`, body)).status).toBe(200); // retry: as before
      expect((await h.api(other, 'POST', `/projects/${projectA}/work-sessions/${s.id}/attestations`, body)).status).toBe(404);
    });

    it('existing scopes confer nothing: the read, request and push scopes cannot submit', async () => {
      const s = await session(noScope);
      for (const c of [noScope, readOnly]) expect((await submit(c, s.id, statement(s.id, signer, { subject_commit: s.commits[0] }))).status).toBe(403);
      expect((await v2(noScope, 'GET', `/work-sessions/${s.id}/attestations`)).status).toBe(200); // reading still works
    });
  });

  describe('the published contract', () => {
    it('is advertised in the API description, so a client can tell whether this server supports it', async () => {
      const doc = (await (await fetch(`${app.base}/api/v2/openapi.json`)).json()) as any;
      expect(doc.info['x-custody-contracts']['commit-attribution-submission']).toMatchObject({ version: '1', scope: 'attestations:submit', route: 'POST /api/v2/work-sessions/{id}/attestations', claim: CLAIM });
      expect(Object.keys(doc.paths['/api/v2/work-sessions/{id}/attestations'])).toContain('post');
    });

    it('request, receipt and every error example conform to the description', async () => {
      const s = await session(courier);
      const body = statement(s.id, signer, { subject_commit: s.commits[0] });
      const path = `/api/v2/work-sessions/${s.id}/attestations`;
      const op = findOperation('POST', path)!;
      expect(op).not.toBeNull();
      expect(checkRequest(op, body)).toEqual([]);
      const first = await submit(courier, s.id, body);
      const retry = await submit(courier, s.id, body);
      for (const r of [first, retry]) expect(checkResponse(op, r.status, r.body)).toEqual([]);
      const errs = [
        await submit(ungranted, (await session(ungranted)).id, body),
        await submit(courier, s.id, statement(s.id, signer, { subject_commit: commitId() })),
        await submit(courier, s.id, statement(s.id, signer, { subject_commit: s.commits[0], claim: 'x.y' })),
        await submit(courier, crypto.randomUUID(), body)
      ];
      expect(errs.map((e) => e.status)).toEqual([403, 422, 422, 404]);
      for (const e of errs) expect(checkResponse(op, e.status, e.body)).toEqual([]);
      // With CONTRACT_EXAMPLES_OUT set (npm run contract:receipt), the real answers of this run are kept as the contract's examples.
      if (process.env.CONTRACT_EXAMPLES_OUT) {
        const ex = (label: string, r: { status: number; body: unknown }) => ({ label, status: r.status, body: r.body });
        fs.writeFileSync(process.env.CONTRACT_EXAMPLES_OUT, JSON.stringify({
          request: body,
          responses: [ex('recorded', first), ex('identical retry', retry), ex('no grant for this authority and project', errs[0]), ex('commit the session did not produce', errs[1]), ex('claim other than commit.attribution', errs[2]), ex('not your session', errs[3])]
        }, null, 2));
      }
      const gop = findOperation('POST', '/api/v1/attestation-submission-grants')!;
      expect(checkRequest(gop, { principal_id: courier.id, authority_id: signer.id, project_id: projectA })).toEqual([]);
      const g = await h.api(creator, 'GET', '/attestation-submission-grants');
      expect(checkResponse(findOperation('GET', '/api/v1/attestation-submission-grants')!, 200, g.body)).toEqual([]);
    });
  });
});
