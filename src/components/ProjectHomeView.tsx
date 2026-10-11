import React, { useState, useEffect } from 'react';
import { FolderLock, DoorOpen, Plus, ArrowRight, AlertCircle, Database, Loader2 } from 'lucide-react';
import { Project, CustodyEvent } from '../types/custody';
import { formatHash } from '../utils/crypto';
import { fetchGitHubRepositories, GitHubRepository, GitHubStatus, ServerDoor } from '../utils/api';

interface ProjectHomeViewProps {
  project?: Project | null;
  events: CustodyEvent[];
  eventsError?: string | null;
  onOpenNewDoor: () => void;
  onClaimNewProject: () => void;
  onClaimWithRepo?: (fullName: string) => void;
  onSelectTab: (tab: string) => void;
  github: GitHubStatus | null;
  doors: ServerDoor[];
  doorsError?: string | null;
  onConnectGitHub: () => void;
  onAddRepositories: (fullNames: string[]) => Promise<void>;
  onCheckLock: (repositoryId: string) => Promise<void>;
  onSelectDoor: (doorId: string) => void;
}

/** One repository's lock state, as last read back from GitHub, with a button to check it again. */
const LockLine: React.FC<{ repo: Project['repositories'][number]; canCheck: boolean; onCheck: (id: string) => Promise<void> }> = ({ repo, canCheck, onCheck }) => {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  return (
    <li className="space-y-0.5">
      <div className="flex items-center justify-between gap-2">
        <span>{repo.full_name}</span>
        <span className="flex items-center gap-2">
          {repo.locked_at ? (
            <span className="text-emerald-400" title={`Checked ${repo.lock_checked_at ? new Date(repo.lock_checked_at).toLocaleString() : ''}`}>
              locked
            </span>
          ) : (
            <span className="text-amber-400">not locked</span>
          )}
          {canCheck && (
            <button
              disabled={busy}
              onClick={async () => {
                setBusy(true);
                setError(null);
                try {
                  await onCheck(repo.id);
                } catch (err: any) {
                  setError(err.message);
                } finally {
                  setBusy(false);
                }
              }}
              className="text-indigo-400 hover:text-indigo-300 disabled:opacity-50 font-sans"
            >
              {busy ? 'checking...' : repo.locked_at ? 'check' : 'lock'}
            </button>
          )}
        </span>
      </div>
      {!repo.locked_at && repo.lock_error && <div className="text-[11px] text-amber-300/90 font-sans">{repo.lock_error}</div>}
      {!repo.github_repo_id && <div className="text-[11px] text-zinc-500 font-sans">Name only, not checked with GitHub.</div>}
      {error && <div className="text-[11px] text-rose-300 font-sans">{error}</div>}
    </li>
  );
};

/** Picks repositories the GitHub App can see and adds them to the project. */
const AddRepositories: React.FC<{ project: Project; onAdd: (names: string[]) => Promise<void> }> = ({ project, onAdd }) => {
  const [repos, setRepos] = useState<GitHubRepository[] | null>(null);
  const [picked, setPicked] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const have = new Set(project.repositories.map((r) => r.full_name.toLowerCase()));

  if (!repos) {
    return (
      <div className="space-y-1">
        <button
          onClick={async () => {
            setError(null);
            try {
              setRepos(await fetchGitHubRepositories());
            } catch (err: any) {
              setError(err.message);
            }
          }}
          className="text-xs text-indigo-400 hover:text-indigo-300 font-medium"
        >
          + Add repositories from GitHub
        </button>
        {error && <div className="text-xs text-rose-300">{error}</div>}
      </div>
    );
  }
  const available = repos.filter((r) => !have.has(r.full_name.toLowerCase()));
  return (
    <div className="space-y-2 border border-zinc-800 rounded-lg p-3">
      {available.length === 0 ? (
        <p className="text-xs text-zinc-400">No other repositories are shared with the GitHub App. Give it access on GitHub, then try again.</p>
      ) : (
        available.map((r) => (
          <label key={r.full_name} className="flex items-center gap-2 text-xs font-mono text-zinc-200">
            <input
              type="checkbox"
              checked={picked.includes(r.full_name)}
              onChange={(e) => setPicked(e.target.checked ? [...picked, r.full_name] : picked.filter((n) => n !== r.full_name))}
            />
            {r.full_name} {r.private ? '' : <span className="text-amber-400">(public)</span>}
          </label>
        ))
      )}
      {error && <div className="text-xs text-rose-300">{error}</div>}
      <div className="flex gap-3 text-xs">
        <button
          disabled={busy || picked.length === 0}
          onClick={async () => {
            setBusy(true);
            setError(null);
            try {
              await onAdd(picked);
              setRepos(null);
              setPicked([]);
            } catch (err: any) {
              setError(err.message);
            } finally {
              setBusy(false);
            }
          }}
          className="bg-indigo-600 disabled:opacity-50 text-white font-semibold px-3 py-1.5 rounded-lg"
        >
          {busy ? 'Adding...' : `Add ${picked.length || ''}`.trim()}
        </button>
        <button onClick={() => setRepos(null)} className="text-zinc-400">
          Cancel
        </button>
      </div>
    </div>
  );
};

const NotConnected: React.FC = () => (
  <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full bg-amber-950/60 border border-amber-800/80 text-amber-300 text-[11px] font-mono font-medium">
    <AlertCircle className="w-3 h-3 text-amber-400" />
    Not connected yet
  </span>
);

const EmptyProjectsWithGitHub: React.FC<{
  github: GitHubStatus | null;
  onClaimNewProject: () => void;
  onClaimWithRepo: (fullName: string) => void;
  onConnectGitHub: () => void;
}> = ({ github, onClaimNewProject, onClaimWithRepo, onConnectGitHub }) => {
  const [repos, setRepos] = useState<GitHubRepository[]>([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (github?.connected) {
      setLoading(true);
      fetchGitHubRepositories()
        .then(setRepos)
        .catch(() => setRepos([]))
        .finally(() => setLoading(false));
    }
  }, [github?.connected]);

  if (!github?.connected) {
    return (
      <div className="bg-zinc-950 border border-zinc-800 rounded-2xl p-12 text-center space-y-5 shadow-xl">
        <div className="w-14 h-14 rounded-2xl bg-indigo-600/10 border border-indigo-500/20 flex items-center justify-center text-indigo-400 mx-auto">
          <FolderLock className="w-7 h-7" />
        </div>
        <div className="max-w-md mx-auto space-y-2">
          <h2 className="text-xl font-bold text-zinc-100">No projects yet</h2>
          <p className="text-xs text-zinc-400 leading-relaxed">
            Claiming a project records it, with your own statement of its purpose, in a tamper-evident event log.
          </p>
        </div>
        <div className="flex flex-wrap justify-center gap-3 pt-2">
          {github && !github.connected && (
            <button
              onClick={onConnectGitHub}
              className="bg-zinc-900 hover:bg-zinc-800 text-zinc-200 border border-zinc-700 text-xs font-semibold px-4 py-2.5 rounded-xl flex items-center gap-2 transition-colors"
            >
              <span>Connect GitHub Organization</span>
            </button>
          )}
          <button
            onClick={onClaimNewProject}
            className="bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold px-5 py-2.5 rounded-xl flex items-center gap-2 transition-colors"
          >
            <Plus className="w-4 h-4" />
            <span>Claim Your First Project</span>
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="bg-zinc-950 border border-zinc-800 rounded-2xl p-6 shadow-xl space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-zinc-800 pb-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-indigo-600/20 border border-indigo-500/30 flex items-center justify-center text-indigo-400">
              <FolderLock className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-lg font-semibold text-zinc-100">Your GitHub Repositories</h2>
              <p className="text-xs text-zinc-400">
                Connected to GitHub as <span className="text-indigo-400 font-medium">@{github.account_login}</span>. Choose a repository below to claim and bring under Custody Core protection:
              </p>
            </div>
          </div>
          <button
            onClick={onClaimNewProject}
            className="bg-zinc-900 hover:bg-zinc-800 text-zinc-300 border border-zinc-700 text-xs font-medium px-3.5 py-2 rounded-xl flex items-center gap-1.5 self-start sm:self-auto transition-colors"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Custom Project</span>
          </button>
        </div>

        {loading ? (
          <div className="flex items-center justify-center py-12 gap-2 text-xs text-zinc-400 font-mono">
            <Loader2 className="w-4 h-4 animate-spin text-indigo-400" />
            <span>Loading repositories from GitHub...</span>
          </div>
        ) : repos.length === 0 ? (
          <div className="text-center py-8 space-y-2">
            <p className="text-xs text-zinc-400">No repositories are shared with the GitHub App yet.</p>
            <button
              onClick={onConnectGitHub}
              className="text-xs text-indigo-400 hover:text-indigo-300 font-medium"
            >
              Update repository permissions on GitHub
            </button>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-1">
            {repos.map((r) => (
              <div
                key={r.id}
                className="bg-zinc-900/60 border border-zinc-800 hover:border-zinc-700 rounded-xl p-4 flex flex-col justify-between gap-3 transition-colors"
              >
                <div className="space-y-1.5">
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-xs font-semibold text-zinc-100 font-mono truncate">{r.full_name}</span>
                    <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded-full bg-zinc-800 text-zinc-400">
                      {r.private ? 'Private' : 'Public'}
                    </span>
                  </div>
                  {r.description && (
                    <p className="text-xs text-zinc-400 line-clamp-2">{r.description}</p>
                  )}
                </div>
                <div className="flex justify-end pt-1">
                  <button
                    onClick={() => onClaimWithRepo(r.full_name)}
                    className="bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold px-3 py-1.5 rounded-lg flex items-center gap-1.5 transition-colors"
                  >
                    <Plus className="w-3.5 h-3.5" />
                    <span>Claim & Protect</span>
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

export const ProjectHomeView: React.FC<ProjectHomeViewProps> = ({
  project,
  events,
  eventsError,
  onOpenNewDoor,
  onClaimNewProject,
  onClaimWithRepo,
  onSelectTab,
  github,
  doors,
  doorsError,
  onConnectGitHub,
  onAddRepositories,
  onCheckLock,
  onSelectDoor
}) => {
  if (!project) {
    return (
      <EmptyProjectsWithGitHub
        github={github}
        onClaimNewProject={onClaimNewProject}
        onClaimWithRepo={onClaimWithRepo || onClaimNewProject}
        onConnectGitHub={onConnectGitHub}
      />
    );
  }

  const recentEvents = events.slice(-5).reverse();

  return (
    <div className="space-y-6">
      <div className="bg-zinc-950 border border-zinc-800 rounded-2xl p-6 shadow-xl flex flex-col md:flex-row md:items-center justify-between gap-5">
        <div className="space-y-1.5">
          <h1 className="text-xl font-bold text-white tracking-tight">{project.name}</h1>
          <div className="text-sm text-zinc-300">
            Recorded on {new Date(project.created_at).toLocaleDateString()}. {events.length} event{events.length === 1 ? '' : 's'} in the log.
          </div>
          <p className="text-xs text-zinc-400 italic max-w-2xl pt-1">"{project.purpose}"</p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          <button
            onClick={onOpenNewDoor}
            className="bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold px-4 py-2.5 rounded-xl flex items-center gap-2 transition-colors"
          >
            <DoorOpen className="w-4 h-4" />
            <span>Open a Door</span>
          </button>
          <button
            onClick={onClaimNewProject}
            className="bg-zinc-900 hover:bg-zinc-800 text-zinc-300 border border-zinc-700 text-xs font-medium px-3.5 py-2.5 rounded-xl flex items-center gap-1.5 transition-colors"
          >
            <Plus className="w-4 h-4 text-zinc-400" />
            <span>Claim Another</span>
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="bg-zinc-950 border border-zinc-800 rounded-2xl p-5 space-y-2">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-zinc-400 flex items-center gap-1.5">
            <FolderLock className="w-3.5 h-3.5 text-indigo-400" />
            Code Home
          </h3>
          {github?.connected ? (
            <p className="text-xs text-zinc-400">
              GitHub connected: <span className="text-zinc-200">{github.account_login}</span>. Developers reach these repositories only through
              Custody Core's gateway. Locked means: on GitHub, nobody but Custody Core can delete or force-push the default branch, and
              forking is off where GitHub allows it.
            </p>
          ) : github && !github.configured ? (
            <>
              <NotConnected />
              <p className="text-xs text-zinc-400">The GitHub App is not set up on this server (see docs/GITHUB_APP_SETUP.md).</p>
            </>
          ) : (
            <>
              <NotConnected />
              <button onClick={onConnectGitHub} className="block text-xs text-indigo-400 hover:text-indigo-300 font-medium">
                Connect your GitHub organization
              </button>
            </>
          )}
          {project.repositories.length > 0 && (
            <ul className="pt-2 text-[11px] font-mono text-zinc-300 space-y-1.5">
              {project.repositories.map((repo) => (
                <LockLine key={repo.id} repo={repo} canCheck={!!github?.connected} onCheck={onCheckLock} />
              ))}
            </ul>
          )}
          {github?.connected && <AddRepositories project={project} onAdd={onAddRepositories} />}
        </div>

        <div className="bg-zinc-950 border border-zinc-800 rounded-2xl p-5 space-y-2">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-zinc-400 flex items-center gap-1.5">
            <DoorOpen className="w-3.5 h-3.5 text-emerald-400" />
            Doors
          </h3>
          {doorsError ? (
            <p className="text-xs text-rose-300">{doorsError}</p>
          ) : doors.length === 0 ? (
            <p className="text-xs text-zinc-400">Narrow, temporary access for an outside developer, through the git gateway. No doors yet.</p>
          ) : (
            <ul className="text-xs space-y-1">
              {doors.map((d) => (
                <li key={d.id}>
                  <button onClick={() => onSelectDoor(d.id)} className="w-full flex justify-between text-left hover:bg-zinc-900 rounded px-1 py-0.5">
                    <span className="text-zinc-200 truncate">{d.developer_email} · {d.job_description}</span>
                    <span className={d.status === 'open' ? 'text-emerald-400' : 'text-zinc-500'}>{d.status}</span>
                  </button>
                </li>
              ))}
            </ul>
          )}
          <p className="text-[11px] text-zinc-500">Sandboxed developer workspaces: not connected yet.</p>
        </div>
      </div>

      <div className="bg-zinc-950 border border-zinc-800 rounded-2xl p-5 space-y-4 shadow-xl">
        <div className="flex items-center justify-between border-b border-zinc-800 pb-3">
          <h3 className="font-semibold text-xs uppercase tracking-wider text-zinc-200 flex items-center gap-2">
            <Database className="w-3.5 h-3.5 text-emerald-400" />
            Latest events (from the server's event log)
          </h3>
          <button
            onClick={() => onSelectTab('activity')}
            className="text-xs text-indigo-400 hover:text-indigo-300 flex items-center gap-1 font-medium"
          >
            <span>View and verify the full record</span>
            <ArrowRight className="w-3 h-3" />
          </button>
        </div>

        {eventsError ? (
          <div className="text-xs text-rose-300">{eventsError}</div>
        ) : recentEvents.length === 0 ? (
          <div className="text-xs text-zinc-500">No events recorded for this project yet.</div>
        ) : (
          <div className="divide-y divide-zinc-800/80">
            {recentEvents.map((evt) => (
              <div key={evt.seq} className="py-2.5 flex items-center justify-between text-xs">
                <div className="flex items-center gap-2.5">
                  <span className="font-mono text-zinc-500 text-[11px]">#{evt.seq}</span>
                  <span className="font-mono font-medium text-zinc-200">{evt.action}</span>
                </div>
                <div className="flex items-center gap-3">
                  <span className="font-mono text-[10px] text-zinc-500">{new Date(evt.timestamp).toLocaleString()}</span>
                  <span className="text-[10px] font-mono text-zinc-400">hash {formatHash(evt.hash, 6, 4)}</span>
                </div>
              </div>
            ))}
          </div>
        )}
        <p className="text-[11px] text-zinc-500">
          Open the Event Chain tab and press "Check This Record" to have the server recompute every hash.
        </p>
      </div>
    </div>
  );
};
