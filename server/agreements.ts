import crypto from 'node:crypto';

/**
 * Door agreements and their signatures.
 *
 * The agreement text is generated from the door when the invitation is sent and stored on the door with its SHA-256;
 * from then on it cannot change. The developer signs a small JSON statement naming that SHA-256 with an ECDSA P-256
 * key created in their own browser (the private half never leaves their device). Anyone can check a signature later
 * with the stored message, signature and public key (docs/AGREEMENT_SIGNATURES.md).
 *
 * The texts below are a plain starting point, not legal advice. A creator who relies on them should have a lawyer
 * review them for their jurisdiction.
 */

export const AGREEMENT_VERSION = 'custody-core-door-agreement/1';
export const SIGNATURE_PURPOSE = 'custody-core/agreement-signature/v1';
export const CONSENT_TEXT =
  'I agree to sign this agreement electronically, and that my electronic signature has the same effect as a handwritten signature.';

const RIGHTS: Record<string, { title: string; body: string }> = {
  contribute: {
    title: 'Contribution (work made for the Creator)',
    body:
      'Everything the Developer creates under this door (code, documentation and other material) is made for the Creator. ' +
      'The Developer assigns to the Creator all rights, title and interest in it, including copyright, from the moment it is created, ' +
      'to the extent the law allows, and waives moral rights in it where the law permits. The Developer will not reuse it elsewhere.'
  },
  license: {
    title: 'License (the Developer keeps ownership)',
    body:
      'The Developer keeps ownership of what they create under this door and grants the Creator a perpetual, worldwide, royalty-free, ' +
      'irrevocable, non-exclusive license to use, copy, modify, distribute and sublicense it, as part of the project or separately.'
  },
  transfer: {
    title: 'Transfer (including material the Developer brings)',
    body:
      'Everything the Developer creates under this door, and any pre-existing material of the Developer that they add to the repositories, ' +
      'is transferred to the Creator: the Developer assigns all rights, title and interest in it, including copyright, to the extent the law ' +
      'allows, and confirms they have the right to do so.'
  },
  maintain: {
    title: 'Maintenance',
    body:
      'The Developer maintains the existing code. Changes the Developer makes belong to the Creator, who receives all rights in them as in a ' +
      'contribution. The Developer receives no rights in the existing code beyond using it to do this work while the door is open.'
  }
};

export interface AgreementInput {
  creatorName: string;
  creatorEmail: string;
  developerEmail: string;
  projectName: string;
  projectId: string;
  doorId: string;
  jobDescription: string;
  rightsType: string;
  repositories: Array<{ full_name: string; access: string }>;
  expiresAt: string;
}

export function renderAgreement(a: AgreementInput): { version: string; text: string; sha256: string } {
  const rights = RIGHTS[a.rightsType];
  if (!rights) throw new Error(`unknown rights type ${a.rightsType}`);
  const lines = [
    'CUSTODY CORE DOOR AGREEMENT',
    `Template: ${AGREEMENT_VERSION}`,
    '',
    `Creator: ${a.creatorName} <${a.creatorEmail}>`,
    `Developer: <${a.developerEmail}>`,
    `Project: ${a.projectName} (${a.projectId})`,
    `Door: ${a.doorId}`,
    '',
    '1. The work',
    a.jobDescription,
    '',
    '2. Access',
    'The Developer gets access only to these repositories, only through Custody Core, never directly on GitHub:',
    ...a.repositories.map((r) => `   - ${r.full_name}: ${r.access === 'write' ? `read, and push to branches under door/${a.doorId}/` : 'read only'}`),
    `Access ends at ${a.expiresAt} (UTC) or earlier if the Creator closes the door. The Developer will not copy the code outside`,
    'what the work needs, will not share their access credential, and will delete local copies when the door closes, unless the',
    'Creator agrees otherwise in writing.',
    '',
    `3. Rights: ${rights.title}`,
    rights.body,
    '',
    '4. Confidentiality',
    'The Developer keeps the code and anything they learn about the project confidential, during the door and after it closes, except',
    'what is already public or what the law requires them to disclose.',
    '',
    '5. Record',
    'Every fetch and push, refused pushes included, is recorded in the project\'s tamper-evident record, together with this agreement\'s',
    'SHA-256 and the Developer\'s signature.',
    '',
    '6. Other terms',
    'Payment and any other terms are agreed separately between the Creator and the Developer. If they conflict with this agreement on',
    'rights in the work, this agreement applies.',
    '',
    'This text is a template from Custody Core, not legal advice.'
  ];
  const text = lines.join('\n') + '\n';
  return { version: AGREEMENT_VERSION, text, sha256: crypto.createHash('sha256').update(text, 'utf8').digest('hex') };
}

/** The exact statement a developer signs (canonical JSON: sorted keys, no spaces). */
export interface SignedStatement {
  purpose: string;
  agreement_sha256: string;
  door_id: string;
  project_id: string;
  developer_email: string;
  developer_identity: string;
  signer_name: string;
  consent: string;
  signed_at: string;
}

export function canonicalStatement(s: SignedStatement): string {
  const keys = Object.keys(s).sort() as Array<keyof SignedStatement>;
  return JSON.stringify(Object.fromEntries(keys.map((k) => [k, s[k]])));
}

export interface PublicKeyInfo {
  spki: string;
  fingerprint: string;
}

/** Checks a submitted public key: base64 DER SubjectPublicKeyInfo of an ECDSA P-256 key. */
export function readPublicKey(spkiB64: unknown): PublicKeyInfo | null {
  if (typeof spkiB64 !== 'string' || spkiB64.length > 400 || !/^[A-Za-z0-9+/=]+$/.test(spkiB64)) return null;
  try {
    const der = Buffer.from(spkiB64, 'base64');
    const key = crypto.createPublicKey({ key: der, format: 'der', type: 'spki' });
    if (key.asymmetricKeyType !== 'ec' || key.asymmetricKeyDetails?.namedCurve !== 'prime256v1') return null;
    const canonical = key.export({ format: 'der', type: 'spki' });
    return { spki: canonical.toString('base64'), fingerprint: crypto.createHash('sha256').update(canonical).digest('hex') };
  } catch {
    return null;
  }
}

/** Verifies an ECDSA P-256 / SHA-256 signature in IEEE P1363 form (what the browser's WebCrypto produces). */
export function verifyStatement(spkiB64: string, message: string, signatureB64: string): boolean {
  try {
    const key = crypto.createPublicKey({ key: Buffer.from(spkiB64, 'base64'), format: 'der', type: 'spki' });
    const sig = Buffer.from(signatureB64, 'base64');
    if (sig.length !== 64) return false;
    return crypto.verify('sha256', Buffer.from(message, 'utf8'), { key, dsaEncoding: 'ieee-p1363' }, sig);
  } catch {
    return false;
  }
}
