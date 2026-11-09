import { describe, it, expect, beforeAll } from 'vitest';
import crypto from 'node:crypto';
import { getAdminPool, getDbPool, runMigrations } from '../server/db';
import {
  PrincipalError,
  addPrincipalKey,
  jwkFingerprint,
  listPrincipals,
  readPublicJwk,
  registerPrincipal,
  revokeKey,
  setPrincipalStatus
} from '../server/servicePrincipals';
import { verifyAccountChain } from '../shared/crypto';
import { assertPoolTargetsTestDb } from './support/safety';
import { newKey } from './support/principalKeys';

/**
 * Service principals: the registry (CL-06). Real database, real custody_app role, real hash-chained account
 * record. The assertion login itself is in assertion_auth.test.ts.
 */
describe('Service principals and their keys', () => {
  const db = getDbPool()!;
  const admin = getAdminPool()!;
  let creator: { id: string; userId: string };
  let other: { id: string; userId: string };
  let projectId = '';
  let otherProjectId = '';

  async function newCreator(label: string) {
    const userId = `user-${crypto.randomUUID()}`;
    const id = (await db.query('INSERT INTO creator (identity_id, display_name, email) VALUES ($1, $2, $3) RETURNING id', [userId, label, `${label}_${Date.now()}@example.com`])).rows[0].id;
    return { id, userId };
  }
  const principal = (over: Record<string, unknown> = {}, who = creator) =>
    registerPrincipal(db, who.id, { name: `p-${crypto.randomUUID().slice(0, 8)}`, platform_type: 'ci', environment: 'development', allowed_scopes: ['work-sessions:request'], ...over } as any, 'test-operator');
  const rejects = async (p: Promise<unknown>, code: string, text?: RegExp) => {
    const err: any = await p.then(() => null, (e) => e);
    expect(err, 'expected a rejection').toBeInstanceOf(PrincipalError);
    expect(err.code).toBe(code);
    if (text) expect(err.message).toMatch(text);
  };

  beforeAll(async () => {
    await assertPoolTargetsTestDb(admin);
    expect((await runMigrations()).success).toBe(true);
    creator = await newCreator('owner');
    other = await newCreator('other');
    projectId = (await db.query(`INSERT INTO project (creator_id, name, purpose) VALUES ($1, 'P', 'x') RETURNING id`, [creator.id])).rows[0].id;
    otherProjectId = (await db.query(`INSERT INTO project (creator_id, name, purpose) VALUES ($1, 'Q', 'x') RETURNING id`, [other.id])).rows[0].id;
  });

  it('migration 010 is recorded', async () => {
    const r = await db.query(`SELECT 1 FROM schema_migrations WHERE version = '010_service_principals_and_scopes.sql'`).catch(() => null);
    // The app account cannot read schema_migrations (by design); the admin account can.
    const a = await admin.query(`SELECT 1 FROM schema_migrations WHERE version = '010_service_principals_and_scopes.sql'`);
    expect(a.rowCount).toBe(1);
    expect(r).toBeNull();
  });

  describe('registering', () => {
    it('stores the principal for its creator, removes duplicate scopes, and records it on the creator\'s account record', async () => {
      const p = await principal({ name: 'orchestrator-1', allowed_scopes: ['work-sessions:request', 'evidence:submit', 'work-sessions:request'], allowed_project_ids: [projectId] });
      expect(p.creator_id).toBe(creator.id);
      expect(p.status).toBe('active');
      expect([...p.allowed_scopes].sort()).toEqual(['evidence:submit', 'work-sessions:request']);
      expect(p.allowed_project_ids).toEqual([projectId]);

      const events = (await db.query('SELECT * FROM account_event WHERE account_id = $1 ORDER BY seq', [creator.userId])).rows;
      const e = events.find((x) => x.action === 'service_principal.registered' && x.payload.principal_id === p.id);
      expect(e).toBeTruthy();
      expect(e.actor_type).toBe('system');
      expect(e.actor_id).toBe('test-operator');
      expect(e.payload).toMatchObject({ name: 'orchestrator-1', environment: 'development', project_ids: [projectId] });
      // the chain still verifies from the stored rows
      const chain = await verifyAccountChain(events.map((x) => ({ ...x, seq: Number(x.seq), timestamp: x.hashed_timestamp })));
      expect(chain.isValid).toBe(true);
    });

    it('refuses unknown scopes, bad environments, empty names, past expiry, and another creator\'s projects', async () => {
      await rejects(principal({ allowed_scopes: ['everything'] }), 'invalid', /Unknown scope/);
      await rejects(principal({ environment: 'prod' }), 'invalid', /environment/);
      await rejects(principal({ name: '   ' }), 'invalid', /name/);
      await rejects(principal({ expires_at: new Date(Date.now() - 1000).toISOString() }), 'invalid', /future/);
      await rejects(principal({ allowed_project_ids: [otherProjectId] }), 'invalid', /own projects/);
      await rejects(principal({ allowed_project_ids: ['not-an-id'] }), 'invalid', /project ids/);
    });

    it('refuses a second principal with the same name for the same creator, but another creator may use it', async () => {
      await principal({ name: 'dup' });
      await rejects(principal({ name: 'dup' }), 'conflict', /already has/);
      await expect(principal({ name: 'dup' }, other)).resolves.toBeTruthy();
    });

    it('a failed registration leaves nothing behind (no row, no event)', async () => {
      const before = (await db.query('SELECT count(*)::int AS n FROM account_event WHERE account_id = $1', [creator.userId])).rows[0].n;
      await rejects(principal({ allowed_scopes: ['nope'] }), 'invalid');
      expect((await db.query('SELECT count(*)::int AS n FROM account_event WHERE account_id = $1', [creator.userId])).rows[0].n).toBe(before);
    });

    it('each creator sees only their own principals', async () => {
      const mine = await principal({ name: 'only-mine' });
      expect((await listPrincipals(db, creator.id)).map((p: any) => p.id)).toContain(mine.id);
      expect((await listPrincipals(db, other.id)).map((p: any) => p.id)).not.toContain(mine.id);
    });
  });

  describe('keys', () => {
    it('accepts Ed25519 and P-256 public keys, and records each with its fingerprint', async () => {
      const p = await principal();
      const ed = newKey('Ed25519');
      const es = newKey('ES256');
      const a = await addPrincipalKey(db, p.id, ed.publicJwk, 'test-operator');
      const b = await addPrincipalKey(db, p.id, es.publicJwk, 'test-operator');
      expect(a.algorithm).toBe('Ed25519');
      expect(b.algorithm).toBe('ES256');
      expect(a.fingerprint).toMatch(/^[0-9a-f]{64}$/);
      const added = (await db.query(`SELECT payload FROM account_event WHERE account_id = $1 AND action = 'service_principal.key_added'`, [creator.userId])).rows.map((r) => r.payload.key_id);
      expect(added).toEqual(expect.arrayContaining([a.key_id, b.key_id]));
    });

    it('refuses a private key outright, without storing it', async () => {
      const p = await principal();
      const k = newKey('Ed25519');
      const priv = k.privateKey.export({ format: 'jwk' }) as Record<string, string>;
      await rejects(addPrincipalKey(db, p.id, priv, 'op'), 'invalid', /private key/);
      expect((await db.query('SELECT count(*)::int AS n FROM service_principal_key WHERE principal_id = $1', [p.id])).rows[0].n).toBe(0);
    });

    it('refuses other curves, other key types, malformed values and points that are not on the curve', async () => {
      const p = await principal();
      const p384 = crypto.generateKeyPairSync('ec', { namedCurve: 'P-384' }).publicKey.export({ format: 'jwk' }) as any;
      const rsa = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }).publicKey.export({ format: 'jwk' }) as any;
      const good = newKey('ES256').publicJwk;
      for (const bad of [p384, rsa, null, 'x', [], {}, { ...good, x: 'AAAA' }, { ...good, y: good.x.slice(0, -2) }, { kty: 'EC', crv: 'P-256', x: good.x, y: good.x }]) {
        await rejects(addPrincipalKey(db, p.id, bad, 'op'), 'invalid');
      }
    });

    it('stores only the members that define the key (extra members such as "use" or "alg" are dropped)', async () => {
      const p = await principal();
      const k = newKey('Ed25519');
      const r = await addPrincipalKey(db, p.id, { ...k.publicJwk, use: 'sig', alg: 'EdDSA', kid: 'mine' }, 'op');
      const stored = (await db.query('SELECT public_key_jwk FROM service_principal_key WHERE id = $1', [r.key_id])).rows[0].public_key_jwk;
      expect(Object.keys(stored).sort()).toEqual(['crv', 'kty', 'x']);
    });

    it('the fingerprint is the RFC 7638 thumbprint (checked against the RFC 8037 appendix A.3 Ed25519 example)', () => {
      const jwk = { kty: 'OKP', crv: 'Ed25519', x: '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo' } as const;
      const hex = jwkFingerprint(jwk as any);
      expect(Buffer.from(hex, 'hex').toString('base64url')).toBe('kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k');
      expect(readPublicJwk(jwk).algorithm).toBe('Ed25519');
    });

    it('one key cannot be registered twice, nor on two principals', async () => {
      const p1 = await principal();
      const p2 = await principal();
      const k = newKey('ES256');
      await addPrincipalKey(db, p1.id, k.publicJwk, 'op');
      await rejects(addPrincipalKey(db, p1.id, k.publicJwk, 'op'), 'conflict', /already registered/);
      await rejects(addPrincipalKey(db, p2.id, k.publicJwk, 'op'), 'conflict', /already registered/);
    });

    it('the database refuses to alter a registered key, or to un-revoke it', async () => {
      const p = await principal();
      const k = await addPrincipalKey(db, p.id, newKey('Ed25519').publicJwk, 'op');
      const other = newKey('Ed25519').publicJwk;
      await expect(db.query('UPDATE service_principal_key SET public_key_jwk = $2::jsonb WHERE id = $1', [k.key_id, JSON.stringify(other)])).rejects.toThrow(/cannot be altered/);
      await expect(db.query(`UPDATE service_principal_key SET principal_id = $2 WHERE id = $1`, [k.key_id, (await principal()).id])).rejects.toThrow(/cannot be altered/);
      await revokeKey(db, k.key_id, 'op');
      await expect(db.query('UPDATE service_principal_key SET revoked_at = NULL WHERE id = $1', [k.key_id])).rejects.toThrow(/cannot be undone/);
    });

    it('revoking a key is recorded once; revoking it again records nothing more', async () => {
      const p = await principal();
      const k = await addPrincipalKey(db, p.id, newKey('ES256').publicJwk, 'op');
      await revokeKey(db, k.key_id, 'op');
      await revokeKey(db, k.key_id, 'op');
      const n = (await db.query(`SELECT count(*)::int AS n FROM account_event WHERE account_id = $1 AND action = 'service_principal.key_revoked' AND payload->>'key_id' = $2`, [creator.userId, k.key_id])).rows[0].n;
      expect(n).toBe(1);
      await rejects(revokeKey(db, crypto.randomUUID(), 'op'), 'not_found');
    });
  });

  describe('suspending and revoking', () => {
    it('a suspended principal can be reactivated; each change is recorded', async () => {
      const p = await principal();
      await setPrincipalStatus(db, p.id, 'suspended', 'op');
      expect((await db.query('SELECT status FROM service_principal WHERE id = $1', [p.id])).rows[0].status).toBe('suspended');
      await setPrincipalStatus(db, p.id, 'active', 'op');
      expect((await db.query('SELECT status FROM service_principal WHERE id = $1', [p.id])).rows[0].status).toBe('active');
      const actions = (await db.query(`SELECT action FROM account_event WHERE account_id = $1 AND payload->>'principal_id' = $2 ORDER BY seq`, [creator.userId, p.id])).rows.map((r) => r.action);
      expect(actions).toEqual(['service_principal.registered', 'service_principal.suspended', 'service_principal.reactivated']);
    });

    it('revoking is final: the code refuses to undo it, and so does the database', async () => {
      const p = await principal();
      await setPrincipalStatus(db, p.id, 'revoked', 'op');
      const row = (await db.query('SELECT status, revoked_at FROM service_principal WHERE id = $1', [p.id])).rows[0];
      expect(row.status).toBe('revoked');
      expect(row.revoked_at).toBeTruthy();
      await rejects(setPrincipalStatus(db, p.id, 'active', 'op'), 'conflict');
      await rejects(addPrincipalKey(db, p.id, newKey('Ed25519').publicJwk, 'op'), 'conflict', /revoked/);
      await expect(db.query(`UPDATE service_principal SET status = 'active', revoked_at = NULL WHERE id = $1`, [p.id])).rejects.toThrow(/cannot be undone/);
      // even with the timestamp left in place
      await expect(db.query(`UPDATE service_principal SET status = 'suspended' WHERE id = $1`, [p.id])).rejects.toThrow();
    });

    it('a principal cannot be moved to another creator', async () => {
      const p = await principal();
      await expect(db.query('UPDATE service_principal SET creator_id = $2 WHERE id = $1', [p.id, other.id])).rejects.toThrow(/cannot change/);
    });
  });

  describe('approval rules (created now, used in a later phase)', () => {
    it('a rule cannot be edited, and a retired rule cannot be reactivated', async () => {
      const rule = { max_ttl_seconds: 600 };
      const sha = crypto.createHash('sha256').update(JSON.stringify(rule)).digest('hex');
      const id = (await db.query(`INSERT INTO approval_policy (creator_id, name, rule, rule_sha256, created_by) VALUES ($1, 'r', $2::jsonb, $3, 'op') RETURNING id`, [creator.id, JSON.stringify(rule), sha])).rows[0].id;
      await expect(db.query(`UPDATE approval_policy SET rule = '{"max_ttl_seconds": 99999}'::jsonb WHERE id = $1`, [id])).rejects.toThrow(/cannot be edited/);
      await expect(db.query(`UPDATE approval_policy SET name = 'renamed' WHERE id = $1`, [id])).rejects.toThrow(/cannot be edited/);
      await db.query(`UPDATE approval_policy SET status = 'retired' WHERE id = $1`, [id]);
      await expect(db.query(`UPDATE approval_policy SET status = 'active' WHERE id = $1`, [id])).rejects.toThrow(/cannot be reactivated/);
    });
  });

  describe('what the application\'s database account may do', () => {
    it('custody_app has no DELETE or TRUNCATE on any of the new tables', async () => {
      for (const t of ['service_principal', 'service_principal_key', 'used_client_assertion', 'approval_policy']) {
        for (const priv of ['DELETE', 'TRUNCATE']) {
          const r = await db.query(`SELECT has_table_privilege(current_user, $1, $2) AS ok`, [`public.${t}`, priv]);
          expect(r.rows[0].ok, `${priv} on ${t}`).toBe(false);
        }
      }
      await expect(db.query('DELETE FROM service_principal_key')).rejects.toThrow(/permission denied/);
    });

    it('expired client assertions are removed by one narrow function, which leaves recent ones', async () => {
      const p = await principal();
      const rows: Array<[string, string]> = [
        ['old', "now() - interval '3 hours'"],
        ['just-expired', "now() - interval '5 minutes'"],
        ['future', "now() + interval '5 minutes'"]
      ];
      for (const [jti, when] of rows) {
        await db.query(`INSERT INTO used_client_assertion (principal_id, jti, expires_at) VALUES ($1, $2, ${when})`, [p.id, jti]);
      }
      const removed = (await db.query('SELECT purge_expired_client_assertions() AS n')).rows[0].n;
      expect(removed).toBeGreaterThanOrEqual(1);
      const left = (await db.query('SELECT jti FROM used_client_assertion WHERE principal_id = $1 ORDER BY jti', [p.id])).rows.map((r) => r.jti);
      expect(left).toEqual(['future', 'just-expired']);
    });
  });
});
