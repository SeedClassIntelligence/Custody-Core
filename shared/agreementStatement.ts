/**
 * The statement a developer signs for a door agreement, shared by the browser (which builds and signs it) and the
 * server (which checks it). Canonical JSON: keys sorted, no spaces.
 */
export const SIGNATURE_PURPOSE = 'custody-core/agreement-signature/v1';
export const CONSENT_TEXT =
  'I agree to sign this agreement electronically, and that my electronic signature has the same effect as a handwritten signature.';

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
