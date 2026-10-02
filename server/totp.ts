import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

/**
 * Authenticator-app codes (TOTP, RFC 6238 over HOTP, RFC 4226): HMAC-SHA1, 30-second steps, 6 digits.
 * These are the settings every common authenticator app uses by default.
 */
export const STEP_SECONDS = 30;
export const DIGITS = 6;

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Encode(buf: Buffer): string {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

export function base32Decode(text: string): Buffer {
  const clean = text.toUpperCase().replace(/=+$/, '').replace(/\s+/g, '');
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of clean) {
    const idx = ALPHABET.indexOf(ch);
    if (idx === -1) throw new Error('Not a base32 string.');
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

/** RFC 4226 HOTP. */
export function hotp(secret: Buffer, counter: number, digits = DIGITS): string {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const mac = createHmac('sha1', secret).update(msg).digest();
  const offset = mac[mac.length - 1] & 0x0f;
  const binary = ((mac[offset] & 0x7f) << 24) | (mac[offset + 1] << 16) | (mac[offset + 2] << 8) | mac[offset + 3];
  return String(binary % 10 ** digits).padStart(digits, '0');
}

export function stepAt(nowMs: number): number {
  return Math.floor(nowMs / 1000 / STEP_SECONDS);
}

/**
 * Returns the time step the code belongs to, allowing one step either side for clock drift, or null.
 * Every candidate is compared in constant time so the answer does not leak through timing.
 */
export function matchingStep(secret: Buffer, code: string, nowMs: number, drift = 1): number | null {
  if (!/^\d{6}$/.test(code)) return null;
  const given = Buffer.from(code);
  const now = stepAt(nowMs);
  let found: number | null = null;
  for (let step = now - drift; step <= now + drift; step++) {
    if (timingSafeEqual(Buffer.from(hotp(secret, step)), given) && found === null) found = step;
  }
  return found;
}

export function newSecret(): string {
  return base32Encode(randomBytes(20)); // 160 bits, as RFC 4226 recommends
}

export function otpauthUri(secretBase32: string, accountName: string, issuer = 'Custody Core'): string {
  const label = encodeURIComponent(`${issuer}:${accountName}`);
  const params = new URLSearchParams({ secret: secretBase32, issuer, algorithm: 'SHA1', digits: String(DIGITS), period: String(STEP_SECONDS) });
  return `otpauth://totp/${label}?${params.toString()}`;
}
