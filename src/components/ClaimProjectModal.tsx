import React, { useState, useEffect } from 'react';
import { FolderPlus, X, Loader2, GitBranch, Check, Sparkles } from 'lucide-react';
import { fetchGitHubRepositories, GitHubRepository, GitHubStatus } from '../utils/api';

interface ClaimProjectModalProps {
  isOpen: boolean;
  onClose: () => void;
  onClaimProject: (data: { name: string; purpose: string; repositoryFullName?: string }) => Promise<void>;
  github?: GitHubStatus | null;
  initialRepoFullName?: string | null;
}

export const ClaimProjectModal: React.FC<ClaimProjectModalProps> = ({
  isOpen,
  onClose,
  onClaimProject,
  github,
  initialRepoFullName
}) => {
  const [name, setName] = useState('');
  const [purpose, setPurpose] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // GitHub import state
  const [repos, setRepos] = useState<GitHubRepository[]>([]);
  const [loadingRepos, setLoadingRepos] = useState(false);
  const [selectedRepo, setSelectedRepo] = useState<GitHubRepository | null>(null);
  const [autoLock, setAutoLock] = useState(true);

  useEffect(() => {
    if (!isOpen) {
      setName('');
      setPurpose('');
      setSelectedRepo(null);
      setError(null);
      return;
    }

    if (github?.connected) {
      setLoadingRepos(true);
      fetchGitHubRepositories()
        .then((list) => {
          setRepos(list);
          if (initialRepoFullName) {
            const found = list.find((r) => r.full_name.toLowerCase() === initialRepoFullName.toLowerCase());
            if (found) selectRepo(found);
          }
        })
        .catch(() => setRepos([]))
        .finally(() => setLoadingRepos(false));
    }
  }, [isOpen, github?.connected, initialRepoFullName]);

  const selectRepo = (r: GitHubRepository) => {
    setSelectedRepo(r);
    // Auto-populate Project Name and Purpose
    const repoTitle = r.name || r.full_name.split('/').pop() || r.full_name;
    setName(repoTitle);
    const desc = r.description?.trim();
    setPurpose(
      desc || `Secure custody, code gating, and outside developer access control for ${r.full_name}.`
    );
  };

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim() || !purpose.trim()) return;

    setIsSubmitting(true);
    setError(null);
    try {
      await onClaimProject({
        name: name.trim(),
        purpose: purpose.trim(),
        repositoryFullName: selectedRepo && autoLock ? selectedRepo.full_name : undefined
      });
      setName('');
      setPurpose('');
      setSelectedRepo(null);
      onClose();
    } catch (err: any) {
      setError(err.message || 'The project could not be recorded.');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="bg-zinc-900 border border-zinc-700/80 rounded-2xl max-w-xl w-full shadow-2xl overflow-hidden flex flex-col max-h-[92vh]">
        <div className="px-6 py-5 border-b border-zinc-800 bg-zinc-950 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-indigo-600/20 border border-indigo-500/30 flex items-center justify-center text-indigo-400">
              <FolderPlus className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-lg font-semibold text-zinc-100">Claim a Project</h2>
              <p className="text-xs text-zinc-400">Record your project and its purpose in the permanent event log.</p>
            </div>
          </div>
          {!isSubmitting && (
            <button
              onClick={onClose}
              className="text-zinc-400 hover:text-zinc-200 p-1.5 rounded-lg hover:bg-zinc-800 transition-colors"
            >
              <X className="w-5 h-5" />
            </button>
          )}
        </div>

        <form onSubmit={handleSubmit} className="p-6 overflow-y-auto space-y-5 text-sm text-zinc-300 flex-1">
          {github?.connected && (
            <div className="bg-zinc-950 border border-zinc-800 rounded-xl p-3.5 space-y-2.5">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-zinc-200 flex items-center gap-1.5">
                  <GitBranch className="w-3.5 h-3.5 text-indigo-400" />
                  Auto-fill from Connected GitHub
                </span>
                <span className="text-[11px] text-zinc-400">
                  @{github.account_login}
                </span>
              </div>

              {loadingRepos ? (
                <div className="flex items-center gap-2 text-xs text-zinc-400 py-1">
                  <Loader2 className="w-3.5 h-3.5 animate-spin" />
                  <span>Loading your repositories...</span>
                </div>
              ) : repos.length > 0 ? (
                <div className="space-y-2">
                  <select
                    disabled={isSubmitting}
                    value={selectedRepo?.full_name || ''}
                    onChange={(e) => {
                      const found = repos.find((r) => r.full_name === e.target.value);
                      if (found) selectRepo(found);
                      else setSelectedRepo(null);
                    }}
                    className="w-full bg-zinc-900 border border-zinc-800 rounded-lg px-3 py-2 text-xs text-zinc-100 focus:outline-none focus:border-indigo-500 font-mono"
                  >
                    <option value="">-- Choose a repository to auto-fill --</option>
                    {repos.map((r) => (
                      <option key={r.id} value={r.full_name}>
                        {r.full_name} {r.private ? '(private)' : '(public)'}
                      </option>
                    ))}
                  </select>

                  {selectedRepo && (
                    <label className="flex items-center gap-2 text-xs text-emerald-400 pt-1 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={autoLock}
                        onChange={(e) => setAutoLock(e.target.checked)}
                        className="rounded border-zinc-800 text-indigo-600 focus:ring-0"
                      />
                      <span className="flex items-center gap-1 text-[11px]">
                        <Check className="w-3 h-3" />
                        Automatically attach & lock {selectedRepo.full_name} to this project
                      </span>
                    </label>
                  )}
                </div>
              ) : (
                <p className="text-[11px] text-zinc-500">
                  No repositories shared with the GitHub App yet.
                </p>
              )}
            </div>
          )}

          <div>
            <label className="block text-xs font-semibold text-zinc-200 mb-1 flex items-center justify-between">
              <span>Project Name <span className="text-rose-400">*</span></span>
              {selectedRepo && (
                <span className="text-[11px] text-indigo-400 flex items-center gap-1 font-normal">
                  <Sparkles className="w-3 h-3" /> Auto-populated
                </span>
              )}
            </label>
            <input
              type="text"
              required
              disabled={isSubmitting}
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="The name you call this project"
              className="w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 text-xs text-zinc-100 focus:outline-none focus:border-indigo-500"
            />
          </div>

          <div>
            <label className="block text-xs font-semibold text-zinc-200 mb-1 flex items-center justify-between">
              <span>Purpose (in your own words) <span className="text-rose-400">*</span></span>
              {selectedRepo && (
                <span className="text-[11px] text-indigo-400 flex items-center gap-1 font-normal">
                  <Sparkles className="w-3 h-3" /> Auto-populated
                </span>
              )}
            </label>
            <textarea
              required
              disabled={isSubmitting}
              rows={3}
              value={purpose}
              onChange={(e) => setPurpose(e.target.value)}
              placeholder="What this software does and why you are building it."
              className="w-full bg-zinc-950 border border-zinc-800 rounded-lg p-3 text-xs text-zinc-100 focus:outline-none focus:border-indigo-500 resize-none leading-relaxed"
            />
          </div>

          {error && (
            <div className="bg-rose-950/50 border border-rose-800 p-3 rounded-lg text-xs text-rose-200">
              {error}
            </div>
          )}

          <div className="pt-2 flex justify-end gap-2">
            <button
              type="button"
              disabled={isSubmitting}
              onClick={onClose}
              className="px-4 py-2 text-xs font-medium text-zinc-400 hover:text-zinc-200 bg-zinc-900 hover:bg-zinc-800 rounded-lg transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isSubmitting || !name.trim() || !purpose.trim()}
              className="bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white font-medium px-5 py-2 rounded-lg text-xs flex items-center gap-2 transition-colors"
            >
              {isSubmitting && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
              <span>{isSubmitting ? 'Recording...' : 'Record Project'}</span>
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
