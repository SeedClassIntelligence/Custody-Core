import type { LockResult } from './repositoryLock';

/**
 * Where a repository lives, behind one seam (docs/integration/PHASE5_DESIGN.md, 4.1; PHASE0_SPEC.md section 5).
 *
 * The git gateway, the backup snapshots and the repository lock all need the same few things from wherever the code
 * is hosted: a git address and credentials to fetch from and push to, and a way to keep the repository locked. They
 * ask a provider, never GitHub directly, so another host (a local repository, custody-managed storage) can be added
 * without touching them. Only GitHub exists today. Connecting an account and listing what it can see (the OAuth hand-
 * shake, installation discovery) is the GitHub *connection* and stays in the GitHub modules; it is not repository access.
 */

/** Everything a provider needs to name one repository. `installationId` is GitHub's; other providers will carry their own fields. */
export interface RepositoryRef {
  id: string;
  fullName: string;
  provider: 'github';
  installationId: number;
}

/** A git address and the HTTP header git must send (given to git as http.extraHeader, never put in a URL or a file). */
export interface GitRemote {
  url: string;
  authHeader: string;
}

/** The provider is not set up on this server (for example the GitHub App settings are missing). */
export class ProviderNotConfigured extends Error {
  constructor(
    readonly provider: string,
    message: string,
    /** What a person using the gateway is told. */
    readonly publicMessage: string
  ) {
    super(message);
  }
}

/** The provider answered, and refused. `message` is the provider's own words; `status` is its HTTP status where it has one. */
export class ProviderError extends Error {
  constructor(
    readonly provider: string,
    message: string,
    readonly status?: number
  ) {
    super(message);
  }
}

export interface RepositoryProvider {
  readonly kind: RepositoryRef['provider'];
  /** How people are told about it ("GitHub"). */
  readonly label: string;
  isConfigured(): boolean;
  /**
   * The address and credentials for one repository. By default the credential can fetch and push; `readOnly` asks for one that
   * can only read (used for backups). Throws ProviderNotConfigured or ProviderError.
   */
  remote(ref: RepositoryRef, opts?: { readOnly?: boolean }): Promise<GitRemote>;
  /** Locks the repository (or re-checks and repairs the lock) and reports what was found. Never throws: failure is in the result. */
  lock(ref: RepositoryRef): Promise<LockResult>;
}

const providers = new Map<RepositoryRef['provider'], RepositoryProvider>();

export function registerProvider(provider: RepositoryProvider): void {
  providers.set(provider.kind, provider);
}

export function providerFor(kind: RepositoryRef['provider']): RepositoryProvider {
  const p = providers.get(kind);
  if (!p) throw new Error(`No repository provider is registered for "${kind}".`);
  return p;
}

/** A GitHub repository from a database row that carries its installation id. */
export function githubRef(row: { id: string; full_name: string; installation_id: number | string }): RepositoryRef {
  return { id: row.id, fullName: row.full_name, provider: 'github', installationId: Number(row.installation_id) };
}
