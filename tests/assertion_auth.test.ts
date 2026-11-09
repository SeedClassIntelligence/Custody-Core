import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import crypto from 'node:crypto';
import { getAdminPool, getDbPool, runMigrations } from '../server/db';
import { addPrincipalKey, registerPrincipal, revokeKey, setPrincipalStatus } from '../server/servicePrincipals';
import { assertPoolTargetsTestDb } from './support/safety';
import { startApp, RunningApp } from './support/api';
import { TestKey, assertion, claimsFor, jwtAlg, newKey, sign } from './support/principalKeys';

/**
 * Machine login on /api/v2 (CL-07): the real Express app over real HTTP, real keys, real database.
 * Every "must be refused" case is checked to be refused with the same plain 401, and, where it matters, to leave no
 * trace (a refused token must not use up a jti).
 */
describe('Service principal login: client assertions on /api/v2', () => {
  const db = getDbPool()!;
  const admin = getAdminPool()!;
  let app: RunningApp;
  let creatorId = '';

  interface Fixture { id: string; keyId: string; key: TestKey }
  async function fixture(alg: 'Ed25519' | 'ES256' = 'Ed25519', scopes = ['work-sessions:request', 'evidence:submit']): Promise<Fixture> {
    const p = await registerPrincipal(db, creatorId, { name: `p-${crypto.randomUUID().slice(0, 8)}`, platform_type: 'ci', environment: 'development', allowed_scopes: scopes }, 'test');
    const key = newKey(alg);
    const k = await addPrincipalKey(db, p.id, key.publicJwk, 'test');
    return { id: p.id, keyId: k.key_id, key };
  }
  const get = async (token: string | null, path = '/whoami', headers: Record<string, string> = {}) => {
    const res = await fetch(`${app.base}/api/v2${path}`, { headers: { ...(token ? { Authorization: `Bearer ${token}` } : {}), ...headers } });
    return { status: res.status, body: await res.json().catch(() => ({})), www: res.headers.get('www-authenticate') };
  };
  const refused = async (token: string | null, label: string) => {
    const r = await get(token);
    expect(r.status, label).toBe(401);
    expect(r.body, label).toEqual({ error: 'Invalid or missing credentials.' }); // never says which check failed
    expect(r.www, label).toBe('Bearer');
  };
  const jtiCount = async (principalId: string) => (await db.query('SELECT count(*)::int AS n FROM used_client_assertion WHERE principal_id = $1', [principalId])).rows[0].n;
  const nowS = () => Math.floor(Date.now() / 1000);

  beforeAll(async () => {
    await assertPoolTargetsTestDb(admin);
    expect((await runMigrations()).success).toBe(true);
    creatorId = (await db.query('INSERT INTO creator (identity_id, display_name, email) VALUES ($1, $2, $3) RETURNING id', [`user-${crypto.randomUUID()}`, 'owner', `owner_${Date.now()}@example.com`])).rows[0].id;
    app = await startApp();
  });
  afterAll(async () => {
    await app?.stop();
  });

  describe('accepts a correct assertion', () => {
    for (const alg of ['Ed25519', 'ES256'] as const) {
      it(`${alg}: answers who the caller is, from our records`, async () => {
        const f = await fixture(alg);
        const r = await get(assertion(f.key, f.keyId, f.id));
        expect(r.status).toBe(200);
        expect(r.body.principal).toMatchObject({ id: f.id, platform_type: 'ci', environment: 'development', allowed_project_ids: null });
        expect([...r.body.principal.scopes].sort()).toEqual(['evidence:submit', 'work-sessions:request']);
      });
    }

    it('scopes come from the database, never from the token: a token that claims more scopes gets no more', async () => {
      const f = await fixture('Ed25519', ['work-sessions:read']);
      const r = await get(assertion(f.key, f.keyId, f.id, { claims: { scope: 'repositories:promote principals:manage', scopes: ['work-sessions:approve'] } }));
      expect(r.status).toBe(200);
      expect(r.body.principal.scopes).toEqual(['work-sessions:read']);
    });

    it('a lifetime of exactly 300 seconds is allowed', async () => {
      const f = await fixture();
      const t = nowS();
      expect((await get(assertion(f.key, f.keyId, f.id, { claims: { iat: t, exp: t + 300 } }))).status).toBe(200);
    });

    it('a few seconds of clock difference is tolerated (iat 10 s ahead), but not more than 30', async () => {
      const f = await fixture();
      const t = nowS();
      expect((await get(assertion(f.key, f.keyId, f.id, { claims: { iat: t + 10, exp: t + 100 } }))).status).toBe(200);
      await refused(assertion(f.key, f.keyId, f.id, { claims: { iat: t + 45, exp: t + 100 } }), 'iat 45 s in the future');
    });
  });

  describe('replay', () => {
    it('the same assertion cannot be used twice, and is recorded once', async () => {
      const f = await fixture();
      const token = assertion(f.key, f.keyId, f.id);
      expect((await get(token)).status).toBe(200);
      await refused(token, 'second use');
      await refused(token, 'third use');
      expect(await jtiCount(f.id)).toBe(1);
    });

    it('many requests at once with one assertion: exactly one succeeds', async () => {
      const f = await fixture();
      const token = assertion(f.key, f.keyId, f.id);
      const results = await Promise.all(Array.from({ length: 12 }, () => get(token)));
      expect(results.filter((r) => r.status === 200)).toHaveLength(1);
      expect(results.filter((r) => r.status === 401)).toHaveLength(11);
    });

    it('a jti is unique per principal: two principals may use the same value', async () => {
      const a = await fixture();
      const b = await fixture();
      const jti = 'shared-value';
      expect((await get(assertion(a.key, a.keyId, a.id, { claims: { jti } }))).status).toBe(200);
      expect((await get(assertion(b.key, b.keyId, b.id, { claims: { jti } }))).status).toBe(200);
    });

    it('a refused token does not use up its jti: a forged signature cannot burn the real caller\'s value', async () => {
      const f = await fixture();
      const jti = crypto.randomUUID();
      const good = assertion(f.key, f.keyId, f.id, { claims: { jti } });
      const [h, p] = good.split('.');
      const forged = `${h}.${p}.${crypto.randomBytes(64).toString('base64url')}`;
      await refused(forged, 'forged signature');
      expect(await jtiCount(f.id)).toBe(0);
      expect((await get(good)).status).toBe(200);
    });

    it('every refusal below leaves no jti behind', async () => {
      const f = await fixture();
      const t = nowS();
      await refused(assertion(f.key, f.keyId, f.id, { claims: { aud: 'someone-else' } }), 'aud');
      await refused(assertion(f.key, f.keyId, f.id, { claims: { exp: t - 10, iat: t - 100 } }), 'expired');
      expect(await jtiCount(f.id)).toBe(0);
    });
  });

  describe('refuses a missing or malformed credential', () => {
    it('no header, wrong scheme, empty, garbage, wrong number of parts', async () => {
      await refused(null, 'no header');
      for (const bad of ['', 'garbage', 'a.b', 'a.b.c.d', '....', '!!!.@@@.###']) {
        const res = await fetch(`${app.base}/api/v2/whoami`, { headers: { Authorization: `Bearer ${bad}` } });
        expect(res.status, bad).toBe(401);
      }
      const basic = await fetch(`${app.base}/api/v2/whoami`, { headers: { Authorization: 'Basic abc' } });
      expect(basic.status).toBe(401);
    });

    it('a person\'s login token is not a machine credential', async () => {
      const fake = `${Buffer.from('{"alg":"HS256","typ":"JWT"}').toString('base64url')}.${Buffer.from('{"sub":"abc","role":"authenticated"}').toString('base64url')}.sig`;
      await refused(fake, 'supabase-style token');
    });
  });

  describe('algorithm and key handling', () => {
    it('"alg": "none" (unsigned) is refused', async () => {
      const f = await fixture();
      const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT', kid: f.keyId })).toString('base64url');
      const body = Buffer.from(JSON.stringify(claimsFor(f.id))).toString('base64url');
      await refused(`${header}.${body}.`, 'none, empty signature');
      await refused(`${header}.${body}.AAAA`, 'none, any signature');
    });

    it('HS256 signed with the public key as a shared secret is refused (algorithm confusion)', async () => {
      const f = await fixture('ES256');
      const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT', kid: f.keyId })).toString('base64url');
      const body = Buffer.from(JSON.stringify(claimsFor(f.id))).toString('base64url');
      const mac = crypto.createHmac('sha256', f.key.publicJwk.x).update(`${header}.${body}`).digest('base64url');
      await refused(`${header}.${body}.${mac}`, 'HS256');
    });

    it('an algorithm that is not the registered key\'s is refused, even if the signature is otherwise valid', async () => {
      const ed = await fixture('Ed25519');
      const es = await fixture('ES256');
      // Ed25519 key, but the header claims ES256 (signed with the Ed25519 key)
      await refused(assertion(ed.key, ed.keyId, ed.id, { header: { alg: 'ES256' } }), 'ES256 claimed for an Ed25519 key');
      // P-256 key, but the header claims EdDSA
      await refused(assertion(es.key, es.keyId, es.id, { header: { alg: 'EdDSA' } }), 'EdDSA claimed for a P-256 key');
    });

    it('a key carried in the token\'s own header is never used', async () => {
      const victim = await fixture();
      const attacker = newKey('Ed25519');
      // signed by the attacker, naming the victim's kid, with the attacker's public key embedded as jwk
      const token = assertion(attacker, victim.keyId, victim.id, { header: { jwk: attacker.publicJwk, jku: 'https://example.invalid/keys' } });
      await refused(token, 'embedded jwk');
      // and naming no kid at all
      const header = Buffer.from(JSON.stringify({ alg: 'EdDSA', jwk: attacker.publicJwk })).toString('base64url');
      const body = Buffer.from(JSON.stringify(claimsFor(victim.id))).toString('base64url');
      await refused(`${header}.${body}.${sign(attacker, `${header}.${body}`)}`, 'no kid');
    });

    it('an unknown kid, a kid that is not an id, and a missing kid are refused', async () => {
      const f = await fixture();
      await refused(assertion(f.key, crypto.randomUUID(), f.id), 'unknown kid');
      await refused(assertion(f.key, 'not-a-uuid', f.id), 'bad kid');
      await refused(assertion(f.key, undefined as any, f.id, { header: { kid: undefined } }), 'no kid');
    });

    it('a signature by another principal\'s key is refused', async () => {
      const a = await fixture();
      const b = await fixture();
      await refused(assertion(b.key, a.keyId, a.id), 'signed by the wrong key');
    });

    it('a changed payload (or header) invalidates the signature', async () => {
      const f = await fixture();
      const [h, p, s] = assertion(f.key, f.keyId, f.id).split('.');
      const changed = { ...JSON.parse(Buffer.from(p, 'base64url').toString()), jti: 'different' };
      await refused(`${h}.${Buffer.from(JSON.stringify(changed)).toString('base64url')}.${s}`, 'payload changed');
      const changedHeader = { ...JSON.parse(Buffer.from(h, 'base64url').toString()), typ: 'other' };
      await refused(`${Buffer.from(JSON.stringify(changedHeader)).toString('base64url')}.${p}.${s}`, 'header changed');
    });

    it('a truncated or padded signature is refused', async () => {
      const f = await fixture('ES256');
      const [h, p, s] = assertion(f.key, f.keyId, f.id).split('.');
      await refused(`${h}.${p}.${s.slice(0, -4)}`, 'short');
      await refused(`${h}.${p}.${s}AAAA`, 'long');
      // a DER-encoded signature (what OpenSSL produces by default) is not the JWS form and is refused
      const input = `${h}.${p}`;
      const der = crypto.sign('sha256', Buffer.from(input), f.key.privateKey).toString('base64url');
      await refused(`${input}.${der}`, 'DER signature');
    });
  });

  describe('claims', () => {
    it('wrong, missing or array audience', async () => {
      const f = await fixture();
      await refused(assertion(f.key, f.keyId, f.id, { claims: { aud: 'custody-core.example' } }), 'wrong aud');
      await refused(assertion(f.key, f.keyId, f.id, { claims: { aud: undefined } }), 'no aud');
      await refused(assertion(f.key, f.keyId, f.id, { claims: { aud: ['custody-core', 'other'] } }), 'aud array');
    });

    it('iss and sub must both be the key\'s principal', async () => {
      const a = await fixture();
      const b = await fixture();
      await refused(assertion(a.key, a.keyId, a.id, { claims: { iss: b.id } }), 'iss is another principal');
      await refused(assertion(a.key, a.keyId, a.id, { claims: { sub: b.id } }), 'sub is another principal');
      await refused(assertion(a.key, a.keyId, a.id, { claims: { iss: undefined } }), 'no iss');
      await refused(assertion(a.key, a.keyId, a.id, { claims: { sub: 'someone' } }), 'sub is a name');
    });

    it('expired, lifetime over 300 s, exp before iat, and non-integer or missing times', async () => {
      const f = await fixture();
      const t = nowS();
      await refused(assertion(f.key, f.keyId, f.id, { claims: { iat: t - 200, exp: t - 1 } }), 'expired');
      await refused(assertion(f.key, f.keyId, f.id, { claims: { iat: t, exp: t + 301 } }), '301 s');
      await refused(assertion(f.key, f.keyId, f.id, { claims: { iat: t, exp: t + 86400 } }), 'a day');
      await refused(assertion(f.key, f.keyId, f.id, { claims: { iat: t, exp: t - 5 } }), 'exp before iat');
      await refused(assertion(f.key, f.keyId, f.id, { claims: { iat: t, exp: t } }), 'exp equals iat');
      await refused(assertion(f.key, f.keyId, f.id, { claims: { iat: String(t) as any } }), 'iat as text');
      await refused(assertion(f.key, f.keyId, f.id, { claims: { exp: t + 10.5 } }), 'exp fraction');
      await refused(assertion(f.key, f.keyId, f.id, { claims: { exp: undefined } }), 'no exp');
      await refused(assertion(f.key, f.keyId, f.id, { claims: { iat: undefined } }), 'no iat');
    });

    it('jti missing, empty, not text, or longer than 128 characters', async () => {
      const f = await fixture();
      await refused(assertion(f.key, f.keyId, f.id, { claims: { jti: undefined } }), 'no jti');
      await refused(assertion(f.key, f.keyId, f.id, { claims: { jti: '' } }), 'empty jti');
      await refused(assertion(f.key, f.keyId, f.id, { claims: { jti: 12345 as any } }), 'numeric jti');
      await refused(assertion(f.key, f.keyId, f.id, { claims: { jti: 'x'.repeat(129) } }), 'long jti');
      expect((await get(assertion(f.key, f.keyId, f.id, { claims: { jti: 'x'.repeat(128) } }))).status).toBe(200);
    });
  });

  describe('suspension, revocation and expiry take effect on the next request', () => {
    it('a revoked key is refused; the principal\'s other key still works', async () => {
      const f = await fixture();
      const second = newKey('ES256');
      const k2 = await addPrincipalKey(db, f.id, second.publicJwk, 'test');
      expect((await get(assertion(f.key, f.keyId, f.id))).status).toBe(200);
      await revokeKey(db, f.keyId, 'test');
      await refused(assertion(f.key, f.keyId, f.id), 'revoked key');
      expect((await get(assertion(second, k2.key_id, f.id))).status).toBe(200);
    });

    it('a suspended principal is refused, and works again once reactivated', async () => {
      const f = await fixture();
      expect((await get(assertion(f.key, f.keyId, f.id))).status).toBe(200);
      await setPrincipalStatus(db, f.id, 'suspended', 'test');
      await refused(assertion(f.key, f.keyId, f.id), 'suspended');
      await setPrincipalStatus(db, f.id, 'active', 'test');
      expect((await get(assertion(f.key, f.keyId, f.id))).status).toBe(200);
    });

    it('a revoked principal is refused for good', async () => {
      const f = await fixture();
      await setPrincipalStatus(db, f.id, 'revoked', 'test');
      await refused(assertion(f.key, f.keyId, f.id), 'revoked principal');
      await expect(setPrincipalStatus(db, f.id, 'active', 'test')).rejects.toThrow();
      await refused(assertion(f.key, f.keyId, f.id), 'still revoked');
    });

    it('a principal past its expiry is refused', async () => {
      const f = await fixture();
      await db.query(`UPDATE service_principal SET expires_at = now() - interval '1 minute' WHERE id = $1`, [f.id]);
      await refused(assertion(f.key, f.keyId, f.id), 'expired principal');
    });

    it('a key past its expiry is refused', async () => {
      const f = await fixture();
      await admin.query(`UPDATE service_principal_key SET expires_at = now() - interval '1 minute' WHERE id = $1`, [f.keyId]);
      await refused(assertion(f.key, f.keyId, f.id), 'expired key');
    });
  });

  describe('what a machine login does not give', () => {
    it('only /api/v2 accepts it: person endpoints do not recognize a client assertion', async () => {
      const f = await fixture();
      const res = await fetch(`${app.base}/api/v1/projects`, { headers: { Authorization: `Bearer ${assertion(f.key, f.keyId, f.id)}` } });
      // 401 when person login is configured (as in CI, with the local Supabase Auth stack); 503 when it is not set up
      // at all (a machine without Docker). Never a success, and never any project data.
      expect([401, 503]).toContain(res.status);
      expect(await res.json().catch(() => ({}))).not.toHaveProperty('projects');
    });

    it('an unknown /api/v2 path still requires a valid assertion first (nothing is learned without one)', async () => {
      expect((await get(null, '/nothing-here')).status).toBe(401);
    });

    it('a request with a valid assertion for a path that does not exist is a 404, not a login failure', async () => {
      const f = await fixture();
      expect((await get(assertion(f.key, f.keyId, f.id), '/nothing-here')).status).toBe(404);
    });
  });
});
