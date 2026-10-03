import express from 'express';
import type pg from 'pg';
import { getDbPool } from './db';
import { authenticateSession, sessionOf } from './auth';
import { randomUUID } from 'node:crypto';
import { matchingStep, newSecret, otpauthUri, base32Decode } from './totp';
import { open, seal, SecretBoxNotConfigured, encryptionKey } from './secretBox';

/**
 * The authenticator-code step, run by this server (not by Supabase) so that wrong codes can be limited.
 *
 *   GET  /api/v1/mfa/status   is an authenticator set up, did this session pass, is it locked
 *   POST /api/v1/mfa/enroll   start setting up an authenticator (only when none is verified yet)
 *   POST /api/v1/mfa/verify   check a 6-digit code: completes setup, or passes the code step for this session
 *
 * All of these need a real Supabase session (step 1). Limits:
 *   - after MAX_WRONG wrong (or reused) codes within WINDOW_MINUTES, the authenticator locks for LOCK_MINUTES;
 *   - while locked, every attempt is refused WITHOUT checking the code, so guesses reveal nothing;
 *   - attempts are counted in the database, one at a time per authenticator (row lock), so parallel
 *     guesses cannot slip past the count, and the lock survives restarts and covers every server instance;
 *   - a code that was already accepted cannot be used again;
 *   - every lockout is recorded in the account's tamper-evident record (account_event).
 */
export const MAX_WRONG = 5;
export const WINDOW_MINUTES = 15;
export const LOCK_MINUTES = 15;

export const mfaRouter = express.Router();
mfaRouter.use(authenticateSession);

function pool(res: express.Response): pg.Pool | null {
  const db = getDbPool();
  if (!db) res.status(503).json({ error: 'Database not connected.' });
  return db;
}

function keyOr503(res: express.Response): boolean {
  try {
    encryptionKey();
    return true;
  } catch (err) {
    if (err instanceof SecretBoxNotConfigured) {
      res.status(503).json({ error: 'The authenticator step is not configured on the server (MFA_ENCRYPTION_KEY).' });
      return false;
    }
    throw err;
  }
}

mfaRouter.get('/status', async (_req, res) => {
  const db = pool(res);
  if (!db) return;
  const session = sessionOf(res);
  try {
    // Lock times are decided by the database clock only (never this server's), so every instance agrees.
    const factor = await db.query(
      `SELECT id, CASE WHEN locked_until > now() THEN locked_until END AS locked_until
         FROM mfa_factor WHERE identity_id = $1 AND status = 'verified'`,
      [session.userId]
    );
    const passed = await db.query('SELECT 1 FROM mfa_session WHERE session_id = $1 AND identity_id = $2', [session.sessionId, session.userId]);
    const lockedUntil = factor.rows[0]?.locked_until ? new Date(factor.rows[0].locked_until).toISOString() : null;
    res.json({
      enrolled: factor.rowCount === 1,
      verified: passed.rowCount === 1,
      locked_until: lockedUntil,
      // An authenticator from Supabase's old code step that has not been reset: setup here is refused (see /enroll).
      needs_reset: factor.rowCount === 0 && (await needsOperatorReset(db, session))
    });
  } catch (err: any) {
    console.error('[mfa] status failed:', err?.message ?? err);
    res.status(500).json({ error: 'Something went wrong on the server.' });
  }
});

mfaRouter.post('/enroll', async (_req, res) => {
  const db = pool(res);
  if (!db || !keyOr503(res)) return;
  const session = sessionOf(res);
  const client = await db.connect();
  try {
    await client.query('BEGIN');
    // Serialise enrollments for this login.
    await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', [`mfa_enroll:${session.userId}`]);
    const verified = await client.query(`SELECT 1 FROM mfa_factor WHERE identity_id = $1 AND status = 'verified'`, [session.userId]);
    if (verified.rowCount) {
      await client.query('ROLLBACK');
      return res.status(409).json({ error: 'An authenticator is already set up for this account.' });
    }
    // The account already had an authenticator in Supabase's old code step. Letting whoever holds the password
    // set up a new one here would hand them the account, so the operator must reset it first.
    if (await needsOperatorReset(client, session)) {
      await client.query('ROLLBACK');
      return res.status(409).json(RESET_NEEDED);
    }
    // A half-finished setup is replaced; it never counted as a second factor.
    await client.query(`UPDATE mfa_factor SET status = 'abandoned' WHERE identity_id = $1 AND status = 'unverified'`, [session.userId]);
    const secret = newSecret();
    const factorId = randomUUID();
    const row = await client.query(
      `INSERT INTO mfa_factor (id, identity_id, secret_ciphertext, status) VALUES ($1, $2, $3, 'unverified') RETURNING id`,
      [factorId, session.userId, seal(secret, sealOwner(session.userId, factorId))]
    );
    await client.query('COMMIT');
    // The key is shown once, so the person can add it to their authenticator app. It is not stored in clear.
    res.status(201).json({ factor_id: row.rows[0].id, secret, otpauth_uri: otpauthUri(secret, session.email) });
  } catch (err: any) {
    await client.query('ROLLBACK').catch(() => undefined);
    console.error('[mfa] enroll failed:', err?.message ?? err);
    res.status(500).json({ error: 'Something went wrong on the server.' });
  } finally {
    client.release();
  }
});

mfaRouter.post('/verify', async (req, res) => {
  const db = pool(res);
  if (!db || !keyOr503(res)) return;
  const session = sessionOf(res);
  const code = typeof req.body?.code === 'string' ? req.body.code.trim() : '';
  if (!/^\d{6}$/.test(code)) {
    return res.status(400).json({ error: 'Enter the 6-digit code from your authenticator app.' });
  }

  const client = await db.connect();
  try {
    await client.query('BEGIN');
    // The same lock as /enroll, so a setup cannot start while this check finishes another one.
    await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', [`mfa_enroll:${session.userId}`]);
    // The verified authenticator if there is one, otherwise the one being set up. Never chosen by the browser.
    const found = await client.query(
      `SELECT id, status, secret_ciphertext, last_used_step, locked_until, locked_until > clock_timestamp() AS is_locked
         FROM mfa_factor
        WHERE identity_id = $1 AND status IN ('verified', 'unverified')
        ORDER BY (status = 'verified') DESC, created_at DESC
        LIMIT 1
        FOR UPDATE`,
      [session.userId]
    );
    if (!found.rowCount) {
      await client.query('ROLLBACK');
      return res.status(409).json({ error: 'Set up your authenticator app first.' });
    }
    const factor = found.rows[0];
    if (factor.status === 'unverified' && (await needsOperatorReset(client, session))) {
      await client.query('ROLLBACK');
      return res.status(409).json(RESET_NEEDED);
    }

    const record = (outcome: string) =>
      // clock_timestamp(): the moment of the attempt itself, not the start of its transaction.
      client.query('INSERT INTO mfa_attempt (factor_id, identity_id, outcome, attempted_at) VALUES ($1, $2, $3, clock_timestamp())', [factor.id, session.userId, outcome]);

    // Locked: refuse without looking at the code.
    if (factor.is_locked) {
      await record('locked');
      await client.query('COMMIT');
      return locked(res, new Date(factor.locked_until));
    }

    const secret = base32Decode(open(factor.secret_ciphertext, sealOwner(session.userId, factor.id)));
    const step = matchingStep(secret, code, Date.now());
    const reused = step !== null && factor.last_used_step !== null && step <= Number(factor.last_used_step);

    if (step === null || reused) {
      await record(reused ? 'reused_code' : 'wrong_code');
      const wrong = Number((await client.query(
        `SELECT count(*) AS n FROM mfa_attempt
          WHERE factor_id = $1 AND outcome IN ('wrong_code', 'reused_code')
            AND attempted_at > clock_timestamp() - make_interval(mins => $2)`,
        [factor.id, WINDOW_MINUTES]
      )).rows[0].n);

      if (wrong >= MAX_WRONG) {
        const until = (await client.query(
          `UPDATE mfa_factor SET locked_until = clock_timestamp() + make_interval(mins => $2) WHERE id = $1 RETURNING locked_until`,
          [factor.id, LOCK_MINUTES]
        )).rows[0].locked_until as Date;
        await client.query(
          `SELECT * FROM append_account_event($1, 'system', 'second-factor-guard', 'account.second_factor_locked', $2::jsonb)`,
          [session.userId, JSON.stringify({
            factor_id: factor.id,
            wrong_codes: wrong,
            window_minutes: WINDOW_MINUTES,
            locked_minutes: LOCK_MINUTES,
            locked_until: new Date(until).toISOString()
          })]
        );
        await client.query('COMMIT');
        return locked(res, new Date(until));
      }

      await client.query('COMMIT');
      return res.status(422).json({
        error: reused ? 'That code was already used. Wait for the next one.' : 'That code is not correct.',
        attempts_left: MAX_WRONG - wrong
      });
    }

    // Accepted.
    await client.query(
      `UPDATE mfa_factor
          SET last_used_step = $2,
              status = 'verified',
              verified_at = COALESCE(verified_at, now()),
              locked_until = NULL
        WHERE id = $1`,
      [factor.id, step]
    );
    await record('accepted');
    await client.query(
      `INSERT INTO mfa_session (session_id, identity_id, factor_id) VALUES ($1, $2, $3) ON CONFLICT (session_id) DO NOTHING`,
      [session.sessionId, session.userId, factor.id]
    );
    if (factor.status === 'unverified') {
      // The person who just finished setup is the actor: their creator record (created here on first setup).
      const creator = await client.query(
        `INSERT INTO creator (identity_id, display_name, email) VALUES ($1, $2, $3)
         ON CONFLICT (identity_id) DO UPDATE SET email = EXCLUDED.email, updated_at = now()
         RETURNING id`,
        [session.userId, String(res.locals.displayName), session.email]
      );
      await client.query(
        `SELECT * FROM append_account_event($1, 'creator', $2, 'account.second_factor_enrolled', $3::jsonb)`,
        [session.userId, creator.rows[0].id, JSON.stringify({ factor_id: factor.id })]
      );
    }
    await client.query('COMMIT');
    res.json({ verified: true });
  } catch (err: any) {
    await client.query('ROLLBACK').catch(() => undefined);
    if (err?.code === '23505') {
      // Two setups finished at the same moment; the other one won.
      return res.status(409).json({ error: 'An authenticator is already set up for this account.' });
    }
    console.error('[mfa] verify failed:', err?.message ?? err);
    res.status(500).json({ error: 'Something went wrong on the server.' });
  } finally {
    client.release();
  }
});

const RESET_NEEDED = {
  error: 'This account has an authenticator from the previous sign-in system. Ask the operator to reset it, then sign in again.',
  required: 'operator_reset'
};

/**
 * True when this login had an authenticator in Supabase's old code step that the operator has not reset:
 * recorded at deploy time (mfa_legacy_reset), or still visible in Supabase's own record of the account.
 */
async function needsOperatorReset(db: pg.Pool | pg.PoolClient, session: { userId: string; hasSupabaseFactor: boolean }): Promise<boolean> {
  if (session.hasSupabaseFactor) return true;
  const r = await db.query('SELECT 1 FROM mfa_legacy_reset WHERE identity_id = $1 AND cleared_at IS NULL', [session.userId]);
  return r.rowCount === 1;
}

/** What a stored key is bound to: this login and this authenticator row. */
function sealOwner(identityId: string, factorId: string): string {
  return `${identityId}:${factorId}`;
}

function locked(res: express.Response, until: Date) {
  res.set('Retry-After', String(Math.max(1, Math.ceil((until.getTime() - Date.now()) / 1000))));
  return res.status(429).json({
    error: `Too many wrong codes. This authenticator is locked until ${until.toISOString()}.`,
    locked_until: until.toISOString()
  });
}
