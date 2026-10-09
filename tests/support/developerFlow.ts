import { webcrypto } from 'node:crypto';
import { expect } from 'vitest';
import { CONSENT_TEXT, SIGNATURE_PURPOSE, canonicalStatement } from '../../server/agreements';

/**
 * The developer's side of a door, done the way the browser does it: a real ECDSA P-256 key made with WebCrypto
 * (private half never exported), the canonical statement signed with it, then the credential.
 */
export type ApiFn = (who: any, method: string, path: string, body?: unknown) => Promise<{ status: number; body: any }>;

export async function newSigningKey() {
  const pair = await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
  const spki = Buffer.from(await webcrypto.subtle.exportKey('spki', pair.publicKey)).toString('base64');
  const sign = async (message: string) =>
    Buffer.from(await webcrypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, Buffer.from(message, 'utf8'))).toString('base64');
  return { spki, sign };
}

export function statementFor(door: { id: string; project_id: string; agreement_sha256: string }, dev: { userId: string; email: string }, name = 'Dana Developer') {
  return canonicalStatement({
    purpose: SIGNATURE_PURPOSE,
    agreement_sha256: door.agreement_sha256,
    door_id: door.id,
    project_id: door.project_id,
    developer_email: dev.email,
    developer_identity: dev.userId,
    signer_name: name,
    consent: CONSENT_TEXT,
    signed_at: new Date().toISOString()
  });
}

export function inviteToken(url: string): string {
  return new URL(url).searchParams.get('invite')!;
}

/** Accepts the invitation, registers a key, signs, and gets the gateway credential. Returns the credential. */
export async function acceptSignAndGetCredential(api: ApiFn, dev: { id: string; userId: string; email: string }, inviteUrl: string): Promise<string> {
  const token = inviteToken(inviteUrl);
  expect((await api(dev, 'GET', `/developer/invites/${token}`)).status).toBe(200);
  const accepted = await api(dev, 'POST', `/developer/invites/${token}/accept`);
  expect(accepted.status).toBe(200);
  const key = await newSigningKey();
  expect((await api(dev, 'POST', '/developer/keys', { public_key_spki: key.spki })).status).toBeLessThan(300);
  const door = (await api(dev, 'GET', '/developer/doors')).body.doors.find((d: any) => d.id === accepted.body.door_id);
  const statement = statementFor(door, dev);
  const signed = await api(dev, 'POST', `/developer/doors/${door.id}/sign`, { statement, signature: await key.sign(statement) });
  expect(signed.status, JSON.stringify(signed.body)).toBe(200);
  const cred = await api(dev, 'POST', `/developer/doors/${door.id}/credential`);
  expect(cred.status).toBe(200);
  return cred.body.credential.token;
}
