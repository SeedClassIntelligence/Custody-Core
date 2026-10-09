import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import crypto from 'node:crypto';
import { getAdminPool, getDbPool, runMigrations, insertEvent, verifyServerProjectEvents } from '../server/db';
import { CONSENT_TEXT } from '../server/agreements';
import { assertPoolTargetsTestDb } from './support/safety';
import { startHarness, Harness } from './support/apiHarness';
import { inviteToken, newSigningKey, statementFor } from './support/developerFlow';

/**
 * Developer accounts and agreement signing, against the real database and API routers. Signatures are made with
 * WebCrypto ECDSA P-256 keys exactly as the browser makes them. (The login and code step the developer goes through
 * are the same as a creator's and are tested in auth_api.test.ts and second_factor.test.ts.)
 */
describe('Developer invitations, accounts and agreement signing', () => {
  const db = getDbPool()!;
  const admin = getAdminPool()!;
  let h: Harness;
  let creator: any, dev: any, impostor: any, sameEmailOther: any;
  let projectId = '';
  let repoId = '';
  const DEV_EMAIL = `dana_${Date.now()}@example.com`;

  const api = (who: any, method: string, path: string, body?: unknown) => h.api(who, method, path, body);
  const actions = async () => (await db.query('SELECT action, payload FROM event WHERE project_id = $1 ORDER BY seq', [projectId])).rows;

  async function newDoor(email = DEV_EMAIL) {
    const r = await api(creator, 'POST', `/projects/${projectId}/doors`, {
      developer_email: email,
      job_description: 'Build the export page',
      rights_type: 'contribute',
      expires_at: new Date(Date.now() + 5 * 86400_000).toISOString(),
      repositories: [{ repository_id: repoId, access: 'write' }]
    });
    expect(r.status).toBe(201);
    return r.body.door.id as string;
  }
  const invite = async (doorId: string) => {
    const r = await api(creator, 'POST', `/projects/${projectId}/doors/${doorId}/invite`);
    expect(r.status).toBe(200);
    return r.body;
  };

  beforeAll(async () => {
    await assertPoolTargetsTestDb(admin);
    expect((await runMigrations()).success).toBe(true);
    h = await startHarness();
    creator = await h.newCreator('owner');
    dev = await h.newCreator('dana');
    impostor = await h.newCreator('mallory');
    sameEmailOther = await h.newCreator('dana2');
    for (const p of [dev, sameEmailOther]) {
      p.email = DEV_EMAIL;
      await db.query('UPDATE creator SET email = $2 WHERE id = $1', [p.id, DEV_EMAIL]);
    }
    await db.query(
      `INSERT INTO github_installation (creator_id, installation_id, account_login, account_type, connected_by_github_login) VALUES ($1, 1, 'org', 'Organization', 'octo')`,
      [creator.id]
    );
    projectId = (await db.query(`INSERT INTO project (creator_id, name, purpose) VALUES ($1, 'Signing test', 'Testing signatures') RETURNING id`, [creator.id])).rows[0].id;
    await insertEvent({ project_id: projectId, actor_type: 'creator', actor_id: creator.id, action: 'project.claimed', subject_type: 'project', subject_id: projectId, payload: {} });
    repoId = (await db.query(`INSERT INTO repository (project_id, github_repo_id, full_name) VALUES ($1, '1', 'org/app') RETURNING id`, [projectId])).rows[0].id;
  });

  afterAll(async () => {
    await h?.stop();
  });

  let doorId = '';
  let link = '';

  it('inviting fixes the agreement text and its SHA-256 on the door, and records the invitation without the link', async () => {
    doorId = await newDoor();
    const body = await invite(doorId);
    link = body.invite.url;
    expect(body.door.status).toBe('awaiting_signature');
    const agreement = (await api(creator, 'GET', `/projects/${projectId}/doors/${doorId}/agreement`)).body.agreement;
    expect(agreement.agreement_text).toContain('CUSTODY CORE DOOR AGREEMENT');
    expect(agreement.agreement_text).toContain('Build the export page');
    expect(agreement.agreement_text).toContain(`door/${doorId}/`);
    expect(agreement.agreement_sha256).toBe(crypto.createHash('sha256').update(agreement.agreement_text).digest('hex'));
    const ev = (await actions()).find((e) => e.action === 'door.invited');
    expect(ev.payload).toMatchObject({ developer_email: DEV_EMAIL, agreement_sha256: agreement.agreement_sha256 });
    expect(JSON.stringify(await actions())).not.toContain(inviteToken(link));
  });

  it('a new link replaces the old one and keeps the same agreement', async () => {
    const before = (await api(creator, 'GET', `/projects/${projectId}/doors/${doorId}/agreement`)).body.agreement.agreement_sha256;
    const again = await invite(doorId);
    expect((await api(dev, 'GET', `/developer/invites/${inviteToken(link)}`)).status).toBe(410);
    link = again.invite.url;
    expect((await api(creator, 'GET', `/projects/${projectId}/doors/${doorId}/agreement`)).body.agreement.agreement_sha256).toBe(before);
  });

  it('only a login with the invited email address can use the link', async () => {
    const r = await api(impostor, 'GET', `/developer/invites/${inviteToken(link)}`);
    expect(r.status).toBe(403);
    expect(r.body.error).toMatch(/This invitation is for d\*+@example\.com/);
    expect((await api(impostor, 'POST', `/developer/invites/${inviteToken(link)}/accept`)).status).toBe(403);
    expect((await api(dev, 'GET', `/developer/invites/cci_${'A'.repeat(32)}`)).status).toBe(404);
  });

  it('the invited developer sees the agreement and accepts; a second account cannot take the same door', async () => {
    const shown = await api(dev, 'GET', `/developer/invites/${inviteToken(link)}`);
    expect(shown.status).toBe(200);
    expect(shown.body.invite.door.agreement_text).toContain('CUSTODY CORE DOOR AGREEMENT');
    expect((await api(dev, 'POST', `/developer/invites/${inviteToken(link)}/accept`)).status).toBe(200);
    expect((await api(dev, 'POST', `/developer/invites/${inviteToken(link)}/accept`)).status).toBe(200); // idempotent
    expect((await api(sameEmailOther, 'POST', `/developer/invites/${inviteToken(link)}/accept`)).status).toBe(409);
    expect((await actions()).filter((e) => e.action === 'door.invite_accepted')).toHaveLength(1);
  });

  let key: Awaited<ReturnType<typeof newSigningKey>>;
  let door: any;

  it('refuses to sign without a registered key, and refuses a credential before signing', async () => {
    door = (await api(dev, 'GET', '/developer/doors')).body.doors.find((d: any) => d.id === doorId);
    const k = await newSigningKey();
    const statement = statementFor(door, dev);
    expect((await api(dev, 'POST', `/developer/doors/${doorId}/sign`, { statement, signature: await k.sign(statement) })).status).toBe(409);
    expect((await api(dev, 'POST', `/developer/doors/${doorId}/credential`)).status).toBe(409);
    expect((await api(dev, 'POST', '/developer/keys', { public_key_spki: 'bm90IGEga2V5' })).status).toBe(400);
    key = k;
    expect((await api(dev, 'POST', '/developer/keys', { public_key_spki: key.spki })).status).toBe(201);
  });

  it('refuses statements that do not name exactly this agreement, this login and now, and signatures by any other key', async () => {
    const good = JSON.parse(statementFor(door, dev));
    const tries: Array<[string, (s: any) => string, (m: string) => Promise<string>]> = [
      ['other agreement', (s) => JSON.stringify({ ...s, agreement_sha256: 'f'.repeat(64) }), key.sign],
      ['other identity', (s) => JSON.stringify({ ...s, developer_identity: impostor.userId }), key.sign],
      ['changed consent', (s) => JSON.stringify({ ...s, consent: 'ok' }), key.sign],
      ['old signature time', (s) => JSON.stringify({ ...s, signed_at: new Date(Date.now() - 3600_000).toISOString() }), key.sign],
      ['extra field', (s) => JSON.stringify({ ...s, extra: 1 }), key.sign],
      ['not canonical', (s) => JSON.stringify(s, null, 1), key.sign]
    ];
    for (const [label, make, sign] of tries) {
      const statement = make(good);
      const r = await api(dev, 'POST', `/developer/doors/${doorId}/sign`, { statement, signature: await sign(statement) });
      expect(r.status, label).toBe(422);
    }
    // Right statement, wrong key.
    const other = await newSigningKey();
    const statement = statementFor(door, dev);
    const r = await api(dev, 'POST', `/developer/doors/${doorId}/sign`, { statement, signature: await other.sign(statement) });
    expect(r.status).toBe(422);
    expect(r.body.error).toMatch(/does not verify/);
    expect((await db.query('SELECT status FROM door WHERE id = $1', [doorId])).rows[0].status).toBe('awaiting_signature');
  });

  it('a valid signature opens the door and is recorded so anyone can check it without trusting the server', async () => {
    const statement = statementFor(door, dev, 'Dana Q. Developer');
    const r = await api(dev, 'POST', `/developer/doors/${doorId}/sign`, { statement, signature: await key.sign(statement) });
    expect(r.status).toBe(200);
    const evs = await actions();
    const signed = evs.find((e) => e.action === 'agreement.signed');
    expect(evs.at(-1).action).toBe('door.opened');

    // Independent check: the public key, exact statement and signature from the record verify with plain OpenSSL-backed code,
    // and the statement names the SHA-256 of the agreement text stored on the door.
    const p = signed.payload;
    const ok = crypto.verify('sha256', Buffer.from(p.signed_statement, 'utf8'),
      { key: crypto.createPublicKey({ key: Buffer.from(p.public_key_spki, 'base64'), format: 'der', type: 'spki' }), dsaEncoding: 'ieee-p1363' },
      Buffer.from(p.signature, 'base64'));
    expect(ok).toBe(true);
    const text = (await api(creator, 'GET', `/projects/${projectId}/doors/${doorId}/agreement`)).body.agreement.agreement_text;
    expect(JSON.parse(p.signed_statement)).toMatchObject({
      agreement_sha256: crypto.createHash('sha256').update(text).digest('hex'),
      signer_name: 'Dana Q. Developer',
      consent: CONSENT_TEXT,
      developer_email: DEV_EMAIL
    });
    expect((await api(dev, 'POST', `/developer/doors/${doorId}/sign`, { statement, signature: await key.sign(statement) })).status).toBe(409);
  });

  it('the developer gets the credential; asking again replaces it and revokes the old one', async () => {
    const first = (await api(dev, 'POST', `/developer/doors/${doorId}/credential`)).body.credential.token;
    const second = (await api(dev, 'POST', `/developer/doors/${doorId}/credential`)).body.credential.token;
    expect(first).not.toBe(second);
    const rows = (await db.query('SELECT token_hash, revoked_at FROM gateway_credential WHERE door_id = $1 ORDER BY created_at', [doorId])).rows;
    const hash = (t: string) => crypto.createHash('sha256').update(t).digest('hex');
    expect(rows.find((r) => r.token_hash === hash(first)).revoked_at).not.toBeNull();
    expect(rows.find((r) => r.token_hash === hash(second)).revoked_at).toBeNull();
    expect((await api(impostor, 'POST', `/developer/doors/${doorId}/credential`)).status).toBe(404);
  });

  it('the database keeps a signed agreement fixed, and never opens a door without one', async () => {
    await expect(admin.query(`UPDATE door SET agreement_text = 'changed' WHERE id = $1`, [doorId])).rejects.toThrow(/cannot change after it was sent/);
    await expect(admin.query(`UPDATE door SET agreement_signature = 'x' WHERE id = $1`, [doorId])).rejects.toThrow(/signed agreement cannot change/);
    const unsigned = await newDoor();
    await expect(admin.query(`UPDATE door SET status = 'open' WHERE id = $1`, [unsigned])).rejects.toThrow(/without a signed agreement/);
  });

  it('a new device key retires the old one and is on the developer\'s own record', async () => {
    const k2 = await newSigningKey();
    expect((await api(dev, 'POST', '/developer/keys', { public_key_spki: k2.spki })).status).toBe(201);
    const keys = (await db.query(
      'SELECT retired_at FROM developer_key k JOIN developer d ON d.id = k.developer_id WHERE d.identity_id = $1 ORDER BY k.created_at', [dev.userId]
    )).rows;
    expect(keys.map((k) => k.retired_at === null)).toEqual([false, true]);
    const ev = await db.query(`SELECT count(*)::int AS n FROM account_event WHERE account_id = $1 AND action = 'developer.key_registered'`, [dev.userId]);
    expect(ev.rows[0].n).toBe(2);
  });

  it('closing a door withdraws its unused invitation', async () => {
    const id = await newDoor();
    const { invite: inv } = await invite(id);
    expect((await api(creator, 'POST', `/projects/${projectId}/doors/${id}/close`)).status).toBe(200);
    expect((await api(dev, 'POST', `/developer/invites/${inviteToken(inv.url)}/accept`)).status).toBe(410);
  });

  it('every step is in a record whose hashes verify', async () => {
    expect((await verifyServerProjectEvents(projectId)).isValid).toBe(true);
  });

  it('the real app keeps the developer routes behind the full login', async () => {
    const { startApp } = await import('./support/api');
    const running = await startApp();
    try {
      for (const p of ['/api/v1/developer/doors', `/api/v1/developer/invites/${inviteToken(link)}`]) {
        expect([401, 503]).toContain((await fetch(`${running.base}${p}`)).status);
      }
    } finally {
      await running.stop();
    }
  });
});
