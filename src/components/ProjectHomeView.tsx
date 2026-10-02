import React from 'react';
import { FolderLock, DoorOpen, Plus, ArrowRight, AlertCircle, Database } from 'lucide-react';
import { Project, CustodyEvent } from '../types/custody';
import { formatHash } from '../utils/crypto';

interface ProjectHomeViewProps {
  project?: Project | null;
  events: CustodyEvent[];
  eventsError?: string | null;
  onOpenNewDoor: () => void;
  onClaimNewProject: () => void;
  onSelectTab: (tab: string) => void;
}

const NotConnected: React.FC = () => (
  <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full bg-amber-950/60 border border-amber-800/80 text-amber-300 text-[11px] font-mono font-medium">
    <AlertCircle className="w-3 h-3 text-amber-400" />
    Not connected yet
  </span>
);

export const ProjectHomeView: React.FC<ProjectHomeViewProps> = ({
  project,
  events,
  eventsError,
  onOpenNewDoor,
  onClaimNewProject,
  onSelectTab
}) => {
  if (!project) {
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
        <div className="flex justify-center gap-3 pt-2">
          <button
            onClick={onClaimNewProject}
            className="bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold px-5 py-3 rounded-xl flex items-center gap-2 transition-colors"
          >
            <Plus className="w-4 h-4" />
            <span>Claim Your First Project</span>
          </button>
        </div>
      </div>
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
          <NotConnected />
          <p className="text-xs text-zinc-400">
            Private repositories in your own GitHub organization, locked against forking and force-pushes.
          </p>
          {project.repositories.length > 0 && (
            <ul className="pt-2 text-[11px] font-mono text-zinc-300 space-y-0.5">
              {project.repositories.map((repo) => (
                <li key={repo.id}>
                  {repo.full_name} <span className="text-zinc-500">(recorded name only, lock not verified)</span>
                </li>
              ))}
            </ul>
          )}
        </div>

        <div className="bg-zinc-950 border border-zinc-800 rounded-2xl p-5 space-y-2">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-zinc-400 flex items-center gap-1.5">
            <DoorOpen className="w-3.5 h-3.5 text-emerald-400" />
            Doors & Developer Workspaces
          </h3>
          <NotConnected />
          <p className="text-xs text-zinc-400">
            Narrow, temporary, signed access for an outside developer. No doors exist.
          </p>
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
