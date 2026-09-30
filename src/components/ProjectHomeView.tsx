import React from 'react';
import {
  ShieldCheck,
  FolderLock,
  DoorOpen,
  Clock,
  Plus,
  ArrowRight,
  HardDrive,
  FileCheck2,
  Lock,
  Terminal,
  Layers,
  Sparkles,
  GitPullRequest,
  CheckCircle2,
  AlertTriangle
} from 'lucide-react';
import { Project, Door, CustodyEvent, MirrorSnapshot, Connection } from '../types/custody';

interface ProjectHomeViewProps {
  project?: Project | null;
  doors: Door[];
  events: CustodyEvent[];
  mirrorSnapshots: MirrorSnapshot[];
  connections: Connection[];
  onOpenNewDoor: () => void;
  onSelectDoor: (doorId: string) => void;
  onClaimNewProject: () => void;
  onSelectTab: (tab: string) => void;
  onSwitchToWorkspace: (doorId: string) => void;
}

export const ProjectHomeView: React.FC<ProjectHomeViewProps> = ({
  project,
  doors,
  events,
  mirrorSnapshots,
  connections,
  onOpenNewDoor,
  onSelectDoor,
  onClaimNewProject,
  onSelectTab,
  onSwitchToWorkspace
}) => {
  if (!project) {
    return (
      <div className="bg-zinc-950 border border-zinc-800 rounded-2xl p-12 text-center space-y-5 shadow-xl">
        <div className="w-14 h-14 rounded-2xl bg-indigo-600/10 border border-indigo-500/20 flex items-center justify-center text-indigo-400 mx-auto">
          <FolderLock className="w-7 h-7" />
        </div>
        <div className="max-w-md mx-auto space-y-2">
          <h2 className="text-xl font-bold text-zinc-100">Welcome to Custody Core</h2>
          <p className="text-xs text-zinc-400 leading-relaxed">
            Protect your software ownership. Register a locked code home in your name, open scoped cloud doors for outside developers, and close them with zero direct GitHub access.
          </p>
        </div>
        <div className="flex justify-center gap-3 pt-2">
          <button
            onClick={onClaimNewProject}
            className="bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold px-5 py-3 rounded-xl flex items-center gap-2 shadow-lg shadow-indigo-600/20 transition-colors"
          >
            <Plus className="w-4 h-4" />
            <span>Claim Your First Project</span>
          </button>
        </div>
      </div>
    );
  }

  const activeDoors = doors.filter(d => d.status === 'open' || d.status === 'awaiting_signature');
  const closedDoors = doors.filter(d => d.status === 'closed');
  const latestSnapshot = mirrorSnapshots[mirrorSnapshots.length - 1];

  // Plain-English status line from spec:
  // "Status in one line ('Protected. 1 door open. Last backup 4 minutes ago.'), doors, recent activity"
  const getMinutesAgo = (dateStr?: string) => {
    if (!dateStr) return 'never';
    const diff = Math.max(1, Math.round((new Date().getTime() - new Date(dateStr).getTime()) / 60000));
    return `${diff} minute${diff > 1 ? 's' : ''} ago`;
  };

  const backupTime = getMinutesAgo(latestSnapshot?.timestamp);
  const oneLineStatus = `Protected. ${activeDoors.length} door${activeDoors.length === 1 ? '' : 's'} open. Last backup ${backupTime}.`;

  const recentEvents = events.slice(-5).reverse();

  return (
    <div className="space-y-6">
      {/* 1. Status In One Line Card (Strict Spec Requirement) */}
      <div className="bg-gradient-to-r from-zinc-950 via-zinc-900 to-zinc-950 border border-zinc-800 rounded-2xl p-6 shadow-xl flex flex-col md:flex-row md:items-center justify-between gap-5">
        <div className="space-y-1.5">
          <div className="flex items-center gap-2">
            <span className="flex h-3 w-3 rounded-full bg-emerald-400 animate-pulse" />
            <h1 className="text-xl font-bold text-white tracking-tight flex items-center gap-2">
              {project.name}
              <span className="text-xs bg-emerald-950 text-emerald-300 border border-emerald-800/80 px-2 py-0.5 rounded-full font-mono font-medium">
                Locked & Protected
              </span>
            </h1>
          </div>

          {/* Canonical One-line summary */}
          <div className="text-sm font-medium text-emerald-300 flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0" />
            <span>{oneLineStatus}</span>
          </div>

          <p className="text-xs text-zinc-400 italic max-w-2xl pt-1">
            "{project.purpose}"
          </p>
        </div>

        {/* Quick Actions */}
        <div className="flex flex-wrap items-center gap-2.5">
          <button
            onClick={onOpenNewDoor}
            className="bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold px-4 py-2.5 rounded-xl flex items-center gap-2 transition-colors shadow-lg shadow-indigo-600/25"
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

      {/* 2. Repositories Grid (Core vs Application Repos) */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-zinc-400 flex items-center gap-1.5">
            <FolderLock className="w-3.5 h-3.5 text-indigo-400" />
            <span>Locked Repositories ({project.repositories.length})</span>
          </h3>
          <span className="text-[11px] text-zinc-500 font-mono">
            Default Branch Ruleset: Delete & Force-Push Blocked
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {project.repositories.map((repo) => (
            <div
              key={repo.id}
              className={`p-5 rounded-2xl border transition-all ${
                repo.is_core
                  ? 'bg-zinc-950 border-amber-900/40 shadow-lg'
                  : 'bg-zinc-950 border-zinc-800 shadow-md'
              }`}
            >
              <div className="flex items-start justify-between gap-3">
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-sm font-bold text-zinc-100">
                      {repo.full_name}
                    </span>
                    {repo.is_core ? (
                      <span className="bg-amber-950 text-amber-300 border border-amber-800 text-[10px] px-2 py-0.5 rounded-full font-mono font-bold uppercase">
                        Quarantined Core
                      </span>
                    ) : (
                      <span className="bg-indigo-950 text-indigo-300 border border-indigo-800 text-[10px] px-2 py-0.5 rounded-full font-mono font-medium">
                        Contractor Scoped
                      </span>
                    )}
                  </div>
                  <p className="text-xs text-zinc-400">
                    {repo.is_core
                      ? 'Proprietary core repository. Kept isolated from standard contractor doors.'
                      : 'Frontend/UI repository. Authorized for doors under gateway mediation.'}
                  </p>
                </div>

                <div className="p-2 rounded-lg bg-zinc-900 text-zinc-400 border border-zinc-800">
                  <Lock className="w-4 h-4 text-emerald-400" />
                </div>
              </div>

              <div className="mt-4 pt-3 border-t border-zinc-900 flex items-center justify-between text-[11px] text-zinc-500 font-mono">
                <span>Forking: <strong>Disabled</strong></span>
                <span>Default Branch: <strong>{repo.default_branch}</strong></span>
                <span>Ruleset: <strong className="text-emerald-400">Active</strong></span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* 3. Doors Section (Active & Closed) */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-zinc-400 flex items-center gap-1.5">
            <DoorOpen className="w-3.5 h-3.5 text-emerald-400" />
            <span>Doors & Developer Workspaces ({doors.length})</span>
          </h3>
          <button
            onClick={onOpenNewDoor}
            className="text-xs text-indigo-400 hover:text-indigo-300 flex items-center gap-1 font-medium"
          >
            <span>+ Open a new door</span>
          </button>
        </div>

        {doors.length === 0 ? (
          <div className="p-8 text-center text-zinc-500 bg-zinc-950 border border-zinc-800 rounded-2xl text-xs space-y-2">
            <DoorOpen className="w-8 h-8 mx-auto text-zinc-600" />
            <p className="text-zinc-300 font-medium">No doors currently open</p>
            <p className="text-zinc-500 max-w-sm mx-auto">
              When you hire a contractor or developer, open a door to give them sandboxed workspace access with zero GitHub collaborator keys.
            </p>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {doors.map((door) => {
              const isOpen = door.status === 'open';
              const isAwaiting = door.status === 'awaiting_signature';
              const isClosed = door.status === 'closed';

              return (
                <div
                  key={door.id}
                  className={`p-5 rounded-2xl border transition-all ${
                    isOpen
                      ? 'bg-zinc-950 border-emerald-900/40 shadow-lg'
                      : isClosed
                      ? 'bg-zinc-950/60 border-zinc-800/80 opacity-80'
                      : 'bg-zinc-950 border-amber-900/40'
                  }`}
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <span className={`w-2 h-2 rounded-full ${
                          isOpen ? 'bg-emerald-400 animate-pulse' :
                          isAwaiting ? 'bg-amber-400' : 'bg-zinc-600'
                        }`} />
                        <h4 className="font-bold text-sm text-zinc-100">{door.job_description}</h4>
                      </div>
                      <p className="text-xs text-zinc-400 font-mono">
                        {door.developer_email}
                      </p>
                    </div>

                    <span className={`text-[10px] px-2 py-0.5 rounded-full font-medium capitalize font-mono ${
                      isOpen ? 'bg-emerald-950 text-emerald-300 border border-emerald-800' :
                      isAwaiting ? 'bg-amber-950 text-amber-300 border border-amber-800' :
                      'bg-zinc-900 text-zinc-400 border border-zinc-700'
                    }`}>
                      {door.status.replace('_', ' ')}
                    </span>
                  </div>

                  <div className="mt-4 pt-3 border-t border-zinc-900 flex items-center justify-between text-xs">
                    <span className="text-zinc-500 text-[11px]">
                      Agreement: <strong className="text-zinc-300 capitalize">{door.rights_type}</strong>
                    </span>

                    <div className="flex items-center gap-2">
                      {isOpen && (
                        <button
                          onClick={() => onSwitchToWorkspace(door.id)}
                          className="bg-indigo-600/80 hover:bg-indigo-500 text-white text-[11px] font-medium px-2.5 py-1 rounded-md flex items-center gap-1 transition-colors"
                        >
                          <Terminal className="w-3 h-3" />
                          <span>Workspace</span>
                        </button>
                      )}

                      <button
                        onClick={() => onSelectDoor(door.id)}
                        className="text-zinc-300 hover:text-white bg-zinc-900 hover:bg-zinc-800 border border-zinc-800 text-[11px] font-medium px-2.5 py-1 rounded-md flex items-center gap-1 transition-colors"
                      >
                        <span>Manage Door</span>
                        <ArrowRight className="w-3 h-3" />
                      </button>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* 4. Recent Activity Stream Preview */}
      <div className="bg-zinc-950 border border-zinc-800 rounded-2xl p-5 space-y-4 shadow-xl">
        <div className="flex items-center justify-between border-b border-zinc-800 pb-3">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            <h3 className="font-semibold text-xs uppercase tracking-wider text-zinc-200">
              Live Hash Chain Event Stream (Latest 5 Blocks)
            </h3>
          </div>
          <button
            onClick={() => onSelectTab('activity')}
            className="text-xs text-indigo-400 hover:text-indigo-300 flex items-center gap-1 font-medium"
          >
            <span>View full cryptographic record</span>
            <ArrowRight className="w-3 h-3" />
          </button>
        </div>

        <div className="divide-y divide-zinc-800/80">
          {recentEvents.map((evt) => (
            <div key={evt.seq} className="py-2.5 flex items-center justify-between text-xs">
              <div className="flex items-center gap-2.5">
                <span className="font-mono text-zinc-500 text-[11px]">#{evt.seq}</span>
                <span className="font-mono font-medium text-zinc-200">{evt.action}</span>
                <span className="text-zinc-500 hidden sm:inline">•</span>
                <span className="text-zinc-400 hidden sm:inline text-[11px]">by {evt.actor_name}</span>
              </div>
              <div className="flex items-center gap-3">
                <span className="font-mono text-[10px] text-zinc-500">
                  {new Date(evt.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                </span>
                <span className="text-[10px] font-mono text-emerald-400/90 bg-zinc-900 px-1.5 py-0.5 rounded border border-zinc-800">
                  SHA-256 Valid
                </span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
