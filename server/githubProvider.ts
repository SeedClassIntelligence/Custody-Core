import { GitHubError, GitHubNotConfigured, githubConfig, gitAuthHeader, installationToken, upstreamGitUrl } from './github';
import { lockRepository } from './repositoryLock';
import { ProviderError, ProviderNotConfigured, registerProvider, type RepositoryProvider } from './repositoryProvider';

/**
 * GitHub, as a repository provider: installation tokens from the Custody Core GitHub App, and the repository lock
 * (a ruleset on the default branch). A behavior-preserving wrapper: the calls, permissions, caching and messages are
 * exactly those the gateway, the snapshots and the lock service made directly before the provider seam existed.
 */
export const githubProvider: RepositoryProvider = {
  kind: 'github',
  label: 'GitHub',

  isConfigured: () => githubConfig() !== null,

  async remote(ref, opts = {}) {
    try {
      const token = await installationToken(
        ref.installationId,
        ref.fullName.split('/')[1],
        // The default (contents: write) is what the gateway has always used; backups ask for less.
        opts.readOnly ? { contents: 'read', metadata: 'read' } : undefined
      );
      return { authHeader: gitAuthHeader(token), url: upstreamGitUrl(ref.fullName) };
    } catch (err) {
      if (err instanceof GitHubNotConfigured) throw new ProviderNotConfigured('github', err.message, 'The GitHub App is not set up on this server.');
      if (err instanceof GitHubError) throw new ProviderError('github', err.message, err.status);
      throw err;
    }
  },

  lock: (ref) => lockRepository(ref.installationId, ref.fullName)
};

registerProvider(githubProvider);
