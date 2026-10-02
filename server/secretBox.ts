import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

/**
 * Encrypts authenticator keys before they are stored (AES-256-GCM). The key comes from the server's
 * environment (MFA_ENCRYPTION_KEY, 32 random bytes, base64) and never reaches the database or the browser.
 * Each value is bound to its owner (authenticated data: the login id and the authenticator's row id), so a
 * stored key cannot be moved to another account's row, or to another authenticator row, and still decrypt.
 */
export class SecretBoxNotConfigured extends Error {}

const TAG_BYTES = 16;

export function encryptionKey(): Buffer {
  const raw = process.env.MFA_ENCRYPTION_KEY;
  if (!raw) throw new SecretBoxNotConfigured('MFA_ENCRYPTION_KEY is not set on the server.');
  const key = Buffer.from(raw, 'base64');
  if (key.length !== 32) throw new SecretBoxNotConfigured('MFA_ENCRYPTION_KEY must be 32 bytes, base64-encoded.');
  return key;
}

export function seal(plaintext: string, owner: string, key = encryptionKey()): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv, { authTagLength: TAG_BYTES });
  cipher.setAAD(Buffer.from(owner, 'utf8'));
  const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return ['v1', iv.toString('base64'), cipher.getAuthTag().toString('base64'), ct.toString('base64')].join('.');
}

export function open(sealed: string, owner: string, key = encryptionKey()): string {
  const [version, iv, tag, ct] = sealed.split('.');
  if (version !== 'v1' || !iv || !tag || !ct) throw new Error('Unrecognised sealed value.');
  const tagBytes = Buffer.from(tag, 'base64');
  // A shortened tag would make forgery easier; accept only the full 16 bytes.
  if (tagBytes.length !== TAG_BYTES) throw new Error('Unrecognised sealed value.');
  const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(iv, 'base64'), { authTagLength: TAG_BYTES });
  decipher.setAAD(Buffer.from(owner, 'utf8'));
  decipher.setAuthTag(tagBytes);
  return Buffer.concat([decipher.update(Buffer.from(ct, 'base64')), decipher.final()]).toString('utf8');
}
