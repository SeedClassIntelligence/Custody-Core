import crypto from 'node:crypto';

/**
 * Keys and client assertions for service principal tests, made with Node's own crypto exactly as a real caller
 * would make them (Ed25519 signs the raw input; ES256 uses the 64-byte r||s form that JWS requires).
 */
export type TestAlg = 'Ed25519' | 'ES256';

export interface TestKey {
  alg: TestAlg;
  privateKey: crypto.KeyObject;
  publicJwk: Record<string, string>;
}

export function newKey(alg: TestAlg): TestKey {
  const { privateKey, publicKey } =
    alg === 'Ed25519' ? crypto.generateKeyPairSync('ed25519') : crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  return { alg, privateKey, publicJwk: publicKey.export({ format: 'jwk' }) as Record<string, string> };
}

const b64u = (v: unknown) => Buffer.from(typeof v === 'string' ? v : JSON.stringify(v)).toString('base64url');
export const jwtAlg = (alg: TestAlg) => (alg === 'Ed25519' ? 'EdDSA' : 'ES256');

export function sign(key: TestKey, input: string): string {
  const data = Buffer.from(input);
  const sig = key.alg === 'Ed25519' ? crypto.sign(null, data, key.privateKey) : crypto.sign('sha256', data, { key: key.privateKey, dsaEncoding: 'ieee-p1363' });
  return sig.toString('base64url');
}

export function claimsFor(principalId: string, over: Record<string, unknown> = {}): Record<string, unknown> {
  const now = Math.floor(Date.now() / 1000);
  return { iss: principalId, sub: principalId, aud: 'custody-core', iat: now, exp: now + 120, jti: crypto.randomUUID(), ...over };
}

/** A correctly signed assertion; `header` and `claims` can be overridden to build a bad one. */
export function assertion(key: TestKey, kid: string, principalId: string, over: { header?: Record<string, unknown>; claims?: Record<string, unknown> } = {}): string {
  const header = { alg: jwtAlg(key.alg), typ: 'JWT', kid, ...(over.header ?? {}) };
  const claims = claimsFor(principalId, over.claims ?? {});
  for (const k of Object.keys(claims)) if (claims[k] === undefined) delete claims[k];
  const input = `${b64u(header)}.${b64u(claims)}`;
  return `${input}.${sign(key, input)}`;
}
