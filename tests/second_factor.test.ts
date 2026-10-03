import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawn, ChildProcess } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateSync } from 'otplib';
import { getAdminPool, getDbPool, runMigrations } from '../server/db';
import { base32Decode, base32Encode, hotp, matchingStep, newSecret, otpauthUri, stepAt } from '../server/totp';
import { open, seal, SecretBoxNotConfigured, encryptionKey } from '../server/secretBox';
import { MAX_WRONG, LOCK_MINUTES } from '../server/mfa';
import { verifyAccountChain } from '../shared/crypto';
import { assertPoolTargetsTestDb } from './support/safety';
import { freePort } from './support/dbProcess';
import { api, startApp, RunningApp } from './support/api';
import { authStack, createSupabaseMfaUser, withAuthDb, codeAt, enrollCode, signIn, signUp, uniqueEmail, verifyCode, mfaStatus, createMfaUser, AuthSession } from './support/authStack';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

// ------------------------------------------------------------------------------------------------ code math

describe('Authenticator codes (server/totp.ts)', () => {
  // RFC 6238 Appendix B, SHA-1, 8 digits, secret "12345678901234567890".
  const rfcSecret = Buffer.from('12345678901234567890', 'ascii');
  const vectors: Array<[number, string]> = [
    [59, '94287082'], [1111111109, '07081804'], [1111111111, '14050471'],
    [1234567890, '89005924'], [2000000000, '69279037'], [20000000000, '65353130']
  ];

  it.each(vectors)('matches the RFC 6238 test vector at T=%i', (t, expected) => {
    expect(hotp(rfcSecret, Math.floor(t / 30), 8)).toBe(expected);
    expect(hotp(rfcSecret, Math.floor(t / 30))).toBe(expected.slice(-6));
  });

  it('agrees with an independent library (otplib) for fresh random keys at many times', () => {
    for (let i = 0; i < 25; i++) {
      const secret = newSecret();
      const t = 1_700_000_000 + i * 977;
      expect(hotp(base32Decode(secret), stepAt(t * 1000))).toBe(generateSync({ secret, epoch: t }));
    }
  });

  it('base32 round-trips and new keys are 160 bits', () => {
    for (let n = 1; n <= 32; n++) {
      const b = randomBytes(n);
      expect(base32Decode(base32Encode(b)).equals(b)).toBe(true);
    }
    expect(base32Decode(newSecret()).length).toBe(20);
    expect(() => base32Decode('not base32!')).toThrow();
  });

  it('accepts a code from one step either side (clock drift), not two, and rejects anything that is not 6 digits', () => {
    const secret = base32Decode(newSecret());
    const now = Date.now();
    const step = stepAt(now);
    for (const offset of [-1, 0, 1]) expect(matchingStep(secret, hotp(secret, step + offset), now)).toBe(step + offset);
    for (const offset of [-2, 2]) {
      const code = hotp(secret, step + offset);
      // (a far-away code could coincide with a nearby one by chance; only assert when it does not)
      if (![-1, 0, 1].some((o) => hotp(secret, step + o) === code)) expect(matchingStep(secret, code, now)).toBeNull();
    }
    for (const bad of ['', '12345', '1234567', 'abcdef', '12 345', '١٢٣٤٥٦']) expect(matchingStep(secret, bad, now)).toBeNull();
  });

  it('the setup link carries the key and the standard settings', () => {
    const uri = new URL(otpauthUri('JBSWY3DPEHPK3PXPJBSWY3DP', 'a@example.com'));
    expect(uri.protocol).toBe('otpauth:');
    expect(uri.searchParams.get('secret')).toBe('JBSWY3DPEHPK3PXPJBSWY3DP');
    expect(uri.searchParams.get('digits')).toBe('6');
    expect(uri.searchParams.get('period')).toBe('30');
    expect(uri.searchParams.get('algorithm')).toBe('SHA1');
  });
});

describe('Stored authenticator keys are encrypted (server/secretBox.ts)', () => {
  const key = randomBytes(32);

  it('round-trips, and a tampered value or another owner cannot decrypt', () => {
    const sealed = seal('JBSWY3DPEHPK3PXP', 'user-a', key);
    expect(sealed).not.toContain('JBSWY3DPEHPK3PXP');
    expect(open(sealed, 'user-a', key)).toBe('JBSWY3DPEHPK3PXP');
    expect(() => open(sealed, 'user-b', key)).toThrow();
    const parts = sealed.split('.');
    const flipped = Buffer.from(parts[3], 'base64');
    flipped[0] ^= 1;
    expect(() => open([parts[0], parts[1], parts[2], flipped.toString('base64')].join('.'), 'user-a', key)).toThrow();
    expect(() => open(sealed, 'user-a', randomBytes(32))).toThrow();
    // a shortened authentication tag is refused outright
    expect(() => open([parts[0], parts[1], Buffer.from(parts[2], 'base64').subarray(0, 4).toString('base64'), parts[3]].join('.'), 'user-a', key)).toThrow();
  });

  it('refuses to work without a proper key', () => {
    const saved = process.env.MFA_ENCRYPTION_KEY;
    try {
      delete process.env.MFA_ENCRYPTION_KEY;
      expect(() => encryptionKey()).toThrow(SecretBoxNotConfigured);
      process.env.MFA_ENCRYPTION_KEY = randomBytes(16).toString('base64');
      expect(() => encryptionKey()).toThrow(/32 bytes/);
    } finally {
      process.env.MFA_ENCRYPTION_KEY = saved;
    }
  });
});

// ------------------------------------------------------------------------------------------------ the code step over HTTP

describe('Code step on the server: setup, lockout after 5 wrong codes, kept in the database', () => {
  const adminDb = getAdminPool()!;
  let running: RunningApp;

  beforeAll(async () => {
    authStack();
    await assertPoolTargetsTestDb(adminDb);
    const res = await runMigrations();
    if (!res.success) throw new Error(res.message);
    running = await startApp();
  });

  afterAll(async () => {
    await running.stop();
  });

  const wrongCodeFor = (secret: string) => {
    const near = [-1, 0, 1].map((o) => codeAt(secret, o));
    let c = 0;
    while (near.includes(String(c).padStart(6, '0'))) c++;
    return String(c).padStart(6, '0');
  };
  const attempts = async (userId: string): Promise<Record<string, number>> =>
    (await adminDb.query('SELECT outcome, count(*)::int AS n FROM mfa_attempt WHERE identity_id = $1 GROUP BY outcome', [userId])).rows
      .reduce((acc: Record<string, number>, r: any) => ({ ...acc, [r.outcome]: r.n }), {});
  const accountActions = async (userId: string) =>
    (await adminDb.query('SELECT action FROM account_event WHERE account_id = $1 ORDER BY seq', [userId])).rows.map((r) => r.action);

  /** A person with a verified authenticator, plus a NEW session that has not passed the code step yet. */
  async function personWithFreshSession(label: string) {
    const made = await createMfaUser(label, running.base);
    const fresh = await signIn(made.email);
    return { ...made, fresh };
  }

  it('setup: the key is shown once, stored only encrypted, and the first good code completes setup and opens the API', async () => {
    const pw = await signUp(uniqueEmail('setup'));
    expect((await mfaStatus(running.base, pw)).body).toEqual({ enrolled: false, verified: false, locked_until: null, needs_reset: false });
    const { secret, otpauthUri } = await enrollCode(running.base, pw);
    expect(new URL(otpauthUri).searchParams.get('secret')).toBe(secret);

    const row = (await adminDb.query('SELECT status, secret_ciphertext FROM mfa_factor WHERE identity_id = $1', [pw.userId])).rows[0];
    expect(row.status).toBe('unverified');
    expect(row.secret_ciphertext).not.toContain(secret);
    expect(row.secret_ciphertext.startsWith('v1.')).toBe(true);

    expect((await api(running.base, pw, '/projects')).status).toBe(403);
    expect((await verifyCode(running.base, pw, codeAt(secret))).status).toBe(200);
    expect((await api(running.base, pw, '/projects')).status).toBe(200);
    expect((await mfaStatus(running.base, pw)).body).toEqual({ enrolled: true, verified: true, locked_until: null, needs_reset: false });
    expect(await accountActions(pw.userId)).toEqual(['account.second_factor_enrolled']);
    // the actor is the person's creator record, as in project events
    const creatorId = (await adminDb.query('SELECT id FROM creator WHERE identity_id = $1', [pw.userId])).rows[0].id;
    expect((await adminDb.query('SELECT actor_type, actor_id FROM account_event WHERE account_id = $1', [pw.userId])).rows[0]).toEqual({ actor_type: 'creator', actor_id: creatorId });

    // Once an authenticator is verified, nobody can set up another one (including someone with only the password).
    const other = await signIn(pw.email);
    expect((await api(running.base, other, '/mfa/enroll', { method: 'POST', body: {} })).status).toBe(409);
  });

  it('starting setup again replaces the half-finished one: only the newest key works', async () => {
    const pw = await signUp(uniqueEmail('resetup'));
    const first = await enrollCode(running.base, pw);
    const second = await enrollCode(running.base, pw);
    const rows = (await adminDb.query('SELECT status FROM mfa_factor WHERE identity_id = $1 ORDER BY created_at', [pw.userId])).rows.map((r) => r.status);
    expect(rows).toEqual(['abandoned', 'unverified']);
    const firstCode = codeAt(first.secret);
    if (![-1, 0, 1].map((o) => codeAt(second.secret, o)).includes(firstCode)) {
      expect((await verifyCode(running.base, pw, firstCode)).status).toBe(422);
    }
    expect((await verifyCode(running.base, pw, codeAt(second.secret))).status).toBe(200);
  });

  it(`after ${MAX_WRONG} wrong codes the authenticator locks: even the right code is refused, and the lockout is recorded`, async () => {
    const p = await personWithFreshSession('lock');
    const wrong = wrongCodeFor(p.secret);
    const left: number[] = [];
    for (let i = 1; i < MAX_WRONG; i++) {
      const r = await verifyCode(running.base, p.fresh, wrong);
      expect(r.status).toBe(422);
      left.push(r.body.attempts_left);
    }
    expect(left).toEqual([4, 3, 2, 1]);

    const fifth = await verifyCode(running.base, p.fresh, wrong);
    expect(fifth.status).toBe(429);
    const until = new Date(fifth.body.locked_until).getTime();
    expect(until - Date.now()).toBeGreaterThan((LOCK_MINUTES - 1) * 60_000);
    expect(until - Date.now()).toBeLessThanOrEqual(LOCK_MINUTES * 60_000 + 5_000);
    expect(Number(fifth.headers.get('retry-after'))).toBeGreaterThan(0);

    // The right code is now refused without being checked.
    const right = await verifyCode(running.base, p.fresh, codeAt(p.secret, 1));
    expect(right.status).toBe(429);
    expect((await api(running.base, p.fresh, '/projects')).status).toBe(403);
    expect((await mfaStatus(running.base, p.fresh)).body.locked_until).toBe(new Date(until).toISOString());

    expect(await attempts(p.session.userId)).toEqual({ accepted: 1, wrong_code: 5, locked: 1 });

    // The account's own record shows the lockout, and its chain verifies (read from the earlier, already-verified session).
    expect(await accountActions(p.session.userId)).toEqual(['account.second_factor_enrolled', 'account.second_factor_locked']);
    const record = await api(running.base, p.session, '/account/events');
    expect(record.status).toBe(200);
    expect(record.body.valid).toBe(true);
    const lock = record.body.events[1];
    expect(lock.actor_type).toBe('system');
    expect(lock.payload).toMatchObject({ wrong_codes: MAX_WRONG, window_minutes: 15, locked_minutes: LOCK_MINUTES });
    expect((await verifyAccountChain(record.body.events.map((e: any) => ({ ...e, timestamp: e.hashed_timestamp })))).isValid).toBe(true);
  });

  it('20 wrong codes sent at the same moment: exactly 5 are checked, the rest are refused as locked', async () => {
    const p = await personWithFreshSession('parallel');
    const wrong = wrongCodeFor(p.secret);
    const results = await Promise.all(Array.from({ length: 20 }, () => verifyCode(running.base, p.fresh, wrong)));
    const statuses = results.map((r) => r.status).sort();
    expect(statuses.filter((s) => s === 422)).toHaveLength(MAX_WRONG - 1);
    expect(statuses.filter((s) => s === 429)).toHaveLength(20 - (MAX_WRONG - 1));
    expect(await attempts(p.session.userId)).toEqual({ accepted: 1, wrong_code: MAX_WRONG, locked: 20 - MAX_WRONG });
    expect((await verifyCode(running.base, p.fresh, codeAt(p.secret, 1))).status).toBe(429);
    expect((await accountActions(p.session.userId)).filter((a) => a === 'account.second_factor_locked')).toHaveLength(1);
  });

  it('wrong codes spread over many sessions of the same person still add up to one lock', async () => {
    const p = await createMfaUser('manysessions', running.base);
    const wrong = wrongCodeFor(p.secret);
    for (let i = 0; i < MAX_WRONG; i++) {
      const s = await signIn(p.email);
      await verifyCode(running.base, s, wrong);
    }
    const last = await signIn(p.email);
    expect((await verifyCode(running.base, last, codeAt(p.secret, 1))).status).toBe(429);
  });

  it('a lock on one person does not affect anyone else', async () => {
    const a = await personWithFreshSession('lockA');
    const b = await personWithFreshSession('lockB');
    const wrong = wrongCodeFor(a.secret);
    for (let i = 0; i < MAX_WRONG; i++) await verifyCode(running.base, a.fresh, wrong);
    expect((await verifyCode(running.base, a.fresh, codeAt(a.secret, 1))).status).toBe(429);
    expect((await verifyCode(running.base, b.fresh, codeAt(b.secret, 1))).status).toBe(200);
  });

  it('a code that was already accepted cannot be used again, and counts as a wrong attempt', async () => {
    const pw = await signUp(uniqueEmail('reuse'));
    const { secret } = await enrollCode(running.base, pw);
    const used = codeAt(secret); // keep the exact code that is accepted, so a 30-second boundary cannot change it
    expect((await verifyCode(running.base, pw, used)).status).toBe(200);
    const again = await signIn(pw.email);
    const r = await verifyCode(running.base, again, used);
    expect(r.status).toBe(422);
    expect(r.body.error).toMatch(/already used/);
    expect((await attempts(pw.userId)).reused_code).toBe(1);
    expect((await verifyCode(running.base, again, codeAt(secret, 1))).status).toBe(200);
  });

  it('when the lock has expired and the wrong codes are older than the window, the right code works again', async () => {
    const p = await personWithFreshSession('expire');
    const wrong = wrongCodeFor(p.secret);
    for (let i = 0; i < MAX_WRONG; i++) await verifyCode(running.base, p.fresh, wrong);
    expect((await verifyCode(running.base, p.fresh, codeAt(p.secret, 1))).status).toBe(429);

    // Move time forward for this person: the lock ended and the wrong codes happened 16 minutes ago.
    await adminDb.query(`UPDATE mfa_factor SET locked_until = now() - interval '1 second' WHERE identity_id = $1`, [p.session.userId]);
    await adminDb.query(`UPDATE mfa_attempt SET attempted_at = attempted_at - interval '16 minutes' WHERE identity_id = $1`, [p.session.userId]);
    expect((await verifyCode(running.base, p.fresh, codeAt(p.secret, 1))).status).toBe(200);
    expect((await api(running.base, p.fresh, '/projects')).status).toBe(200);
  });

  // ---- the 15-minute window and the reset after a right code (each would ship broken without these)

  const ageAttempts = (userId: string, minutes: number) =>
    adminDb.query(`UPDATE mfa_attempt SET attempted_at = attempted_at - make_interval(mins => $2) WHERE identity_id = $1`, [userId, minutes]);

  it('wrong codes older than 15 minutes no longer count: 4 old + 1 new is not a lock', async () => {
    const p = await personWithFreshSession('window-old');
    const wrong = wrongCodeFor(p.secret);
    for (let i = 0; i < MAX_WRONG - 1; i++) expect((await verifyCode(running.base, p.fresh, wrong)).status).toBe(422);
    await ageAttempts(p.session.userId, 16);
    const r = await verifyCode(running.base, p.fresh, wrong);
    expect(r.status).toBe(422);
    expect(r.body.attempts_left).toBe(MAX_WRONG - 1);
  });

  it('wrong codes 14 minutes old still count: 4 of those + 1 new is a lock', async () => {
    const p = await personWithFreshSession('window-young');
    const wrong = wrongCodeFor(p.secret);
    for (let i = 0; i < MAX_WRONG - 1; i++) expect((await verifyCode(running.base, p.fresh, wrong)).status).toBe(422);
    await ageAttempts(p.session.userId, 14);
    expect((await verifyCode(running.base, p.fresh, wrong)).status).toBe(429);
  });

  it('a right code does not wipe out recent wrong codes: 4 wrong, 1 right, then 1 wrong within 15 minutes is a lock', async () => {
    const p = await personWithFreshSession('strict');
    const wrong = wrongCodeFor(p.secret);
    for (let i = 0; i < MAX_WRONG - 1; i++) expect((await verifyCode(running.base, p.fresh, wrong)).status).toBe(422);
    expect((await verifyCode(running.base, p.fresh, codeAt(p.secret, 1))).status).toBe(200);
    const later = await signIn(p.email);
    expect((await verifyCode(running.base, later, wrongCodeFor(p.secret))).status).toBe(429);
  });

  it('an account recorded at deploy time as having an old authenticator stays blocked, even once Supabase no longer shows it', async () => {
    // (On the hosted project, migration 005 fills mfa_legacy_reset from auth.mfa_factors; tests/data_api_exposure
    // proves that on the real Supabase image. Here the row is added directly.)
    const pw = await signUp(uniqueEmail('snapshot-http'));
    const started = await enrollCode(running.base, pw); // a setup begun before the deploy
    await adminDb.query('INSERT INTO mfa_legacy_reset (identity_id) VALUES ($1)', [pw.userId]);
    expect((await mfaStatus(running.base, pw)).body.needs_reset).toBe(true);
    const enroll = await api(running.base, pw, '/mfa/enroll', { method: 'POST', body: {} });
    expect(enroll.status).toBe(409);
    expect(enroll.body.required).toBe('operator_reset');
    // finishing the half-done setup is refused too
    const finish = await verifyCode(running.base, pw, codeAt(started.secret));
    expect(finish.status).toBe(409);
    expect(finish.body.required).toBe('operator_reset');
    expect((await api(running.base, pw, '/projects')).status).toBe(403);
    // the app's own database account cannot clear it
    await expect(getDbPool()!.query('UPDATE mfa_legacy_reset SET cleared_at = now() WHERE identity_id = $1', [pw.userId])).rejects.toThrow(/permission denied/);
    await expect(getDbPool()!.query('DELETE FROM mfa_legacy_reset WHERE identity_id = $1', [pw.userId])).rejects.toThrow(/permission denied/);

    // The operator clears it; then setup works.
    await adminDb.query('UPDATE mfa_legacy_reset SET cleared_at = now() WHERE identity_id = $1', [pw.userId]);
    expect((await verifyCode(running.base, pw, codeAt(started.secret))).status).toBe(200);
  });

  it('a stored key moved to another authenticator row of the same person does not decrypt (error, not a pass)', async () => {
    const pw = await signUp(uniqueEmail('moved'));
    const first = await enrollCode(running.base, pw);
    await enrollCode(running.base, pw); // first row is now abandoned, second is the live one
    const rows = (await adminDb.query('SELECT id, secret_ciphertext FROM mfa_factor WHERE identity_id = $1 ORDER BY created_at', [pw.userId])).rows;
    await adminDb.query('UPDATE mfa_factor SET secret_ciphertext = $2 WHERE id = $1', [rows[1].id, rows[0].secret_ciphertext]);
    expect((await verifyCode(running.base, pw, codeAt(first.secret))).status).toBe(500);
    expect((await api(running.base, pw, '/projects')).status).toBe(403);
  });

  it("an account with an authenticator from Supabase's old code step cannot be set up again by whoever has the password", async () => {
    const legacy = await createSupabaseMfaUser('legacy');
    const pw = await signIn(legacy.email);
    expect((await mfaStatus(running.base, pw)).body).toMatchObject({ enrolled: false, needs_reset: true });
    const r = await api(running.base, pw, '/mfa/enroll', { method: 'POST', body: {} });
    expect(r.status).toBe(409);
    expect(r.body.required).toBe('operator_reset');
    expect((await adminDb.query('SELECT count(*)::int AS n FROM mfa_factor WHERE identity_id = $1', [pw.userId])).rows[0].n).toBe(0);
    // Its Supabase aal2 session does not help either.
    expect((await api(running.base, legacy.session, '/projects')).status).toBe(403);

    // After the operator removes the old authenticator (docs/LOGIN_SETUP.md), the person can set up here.
    await withAuthDb((c) => c.query('DELETE FROM auth.mfa_factors WHERE user_id = $1', [pw.userId]));
    const again = await signIn(legacy.email);
    expect((await mfaStatus(running.base, again)).body.needs_reset).toBe(false);
    const { secret } = await enrollCode(running.base, again);
    expect((await verifyCode(running.base, again, codeAt(secret))).status).toBe(200);
  });

  it('the lock survives a restart: a freshly started server process still refuses the right code', async () => {
    const p = await personWithFreshSession('restart');
    const wrong = wrongCodeFor(p.secret);
    for (let i = 0; i < MAX_WRONG; i++) await verifyCode(running.base, p.fresh, wrong);

    const port = await freePort();
    const child: ChildProcess = spawn(process.execPath, ['--import', 'tsx', 'server.ts'], {
      cwd: root,
      env: {
        ...process.env,
        NODE_ENV: 'production',
        VITEST: '', // otherwise server.ts thinks it is inside the test runner and does not listen
        PORT: String(port),
        HOST: '127.0.0.1',
        DATABASE_URL: process.env.TEST_DATABASE_URL,
        ADMIN_DATABASE_URL: '',
        APP_DATABASE_URL: ''
      },
      stdio: ['ignore', 'pipe', 'pipe']
    });
    let log = '';
    child.stdout!.on('data', (c) => (log += c));
    child.stderr!.on('data', (c) => (log += c));
    try {
      const base = `http://127.0.0.1:${port}`;
      let up = false;
      for (let i = 0; i < 120 && !up; i++) {
        try {
          up = (await fetch(`${base}/api/v1/health`)).ok;
        } catch {
          await new Promise((r) => setTimeout(r, 250));
        }
      }
      if (!up) throw new Error(`the restarted server did not come up:\n${log}`);
      const r = await verifyCode(base, p.fresh, codeAt(p.secret, 1));
      expect(r.status).toBe(429);
      expect((await api(base, p.fresh, '/projects')).status).toBe(403);
    } finally {
      child.kill('SIGTERM');
    }
  }, 60_000);

  it('codes that are not 6 digits are refused (400) and not counted', async () => {
    const p = await personWithFreshSession('format');
    for (const code of ['', '12345', '1234567', 'abcdef', '12 34 5']) {
      expect((await verifyCode(running.base, p.fresh, code)).status).toBe(400);
    }
    expect((await attempts(p.session.userId)).wrong_code ?? 0).toBe(0);
  });

  it('without a session nothing works, and without the server key the code step is unavailable (503), never skipped', async () => {
    expect((await api(running.base, null, '/mfa/status')).status).toBe(401);
    expect((await api(running.base, null, '/mfa/verify', { method: 'POST', body: { code: '123456' } })).status).toBe(401);
    const pw = await signUp(uniqueEmail('nokey'));
    const saved = process.env.MFA_ENCRYPTION_KEY;
    try {
      delete process.env.MFA_ENCRYPTION_KEY;
      expect((await api(running.base, pw, '/mfa/enroll', { method: 'POST', body: {} })).status).toBe(503);
      expect((await api(running.base, pw, '/mfa/verify', { method: 'POST', body: { code: '123456' } })).status).toBe(503);
      expect((await api(running.base, pw, '/projects')).status).toBe(403);
    } finally {
      process.env.MFA_ENCRYPTION_KEY = saved;
    }
  });

  it('the app database account can add attempts but never change or delete them, and cannot write account events directly', async () => {
    const appDb = getDbPool()!;
    await expect(appDb.query(`UPDATE mfa_attempt SET outcome = 'accepted'`)).rejects.toThrow(/permission denied/);
    await expect(appDb.query(`DELETE FROM mfa_attempt`)).rejects.toThrow(/permission denied/);
    await expect(appDb.query(`DELETE FROM mfa_factor`)).rejects.toThrow(/permission denied/);
    await expect(appDb.query(`UPDATE mfa_session SET identity_id = 'x'`)).rejects.toThrow(/permission denied/);
    await expect(appDb.query(
      `INSERT INTO account_event (account_id, seq, actor_type, actor_id, action, payload, canonical_payload, prev_hash, hash, hashed_timestamp)
       VALUES ('x', 1, 'system', 's', 'forged', '{}'::jsonb, '{}', repeat('0', 64), repeat('1', 64), '2026-01-01T00:00:00.000Z')`
    )).rejects.toThrow(/permission denied/);
    // and the account record is append-only even for the table owner
    const any = (await adminDb.query('SELECT id FROM account_event LIMIT 1')).rows[0];
    if (any) await expect(adminDb.query(`UPDATE account_event SET action = 'x' WHERE id = $1`, [any.id])).rejects.toThrow(/append-only/);
  });

  it('a person can only ever be checked against their own authenticator', async () => {
    const a = await createMfaUser('ownA', running.base);
    const b = await personWithFreshSession('ownB');
    // A's current code, sent by B's fresh session, is just a wrong code for B.
    const r = await verifyCode(running.base, b.fresh, codeAt(a.secret, 1));
    if (codeAt(a.secret, 1) !== codeAt(b.secret, 1)) expect(r.status).toBe(422);
    expect((await api(running.base, b.fresh, '/projects')).status).toBe(403);
  });
});

export type { AuthSession };
