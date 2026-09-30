import React from 'react';
import {
  FolderGit2,
  AlertCircle,
  ShieldCheck,
  HardDrive,
  GitBranch
} from 'lucide-react';
import { Door, Project, Workspace } from '../types/custody';

interface DeveloperWorkspaceProps {
  door: Door;
  project: Project;
  workspace?: Workspace;
  onGitPush?: (params: {
    branch: string;
    commitMessage: string;
    files: Array<{ path: string; content: string }>;
    hasSecretLeak: boolean;
  }) => Promise<{ success: boolean; message: string; eventLogged?: boolean }>;
  onCloseDoorRequested?: () => void;
}

export const DeveloperWorkspace: React.FC<DeveloperWorkspaceProps> = ({
  door,
  project
}) => {
  return (
    <div className="bg-zinc-950 border border-zinc-800 rounded-2xl overflow-hidden shadow-2xl flex flex-col">
      {/* Top Bar */}
      <div className="px-6 py-4 bg-zinc-900 border-b border-zinc-800 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-xl bg-amber-500/10 border border-amber-500/20 flex items-center justify-center text-amber-400">
            <FolderGit2 className="w-4 h-4" />
          </div>
          <div>
            <h3 className="text-sm font-semibold text-zinc-100">Developer Workspace & Git Push</h3>
            <p className="text-xs text-zinc-400">Project: {project.name} • Door: {door.job_description}</p>
          </div>
        </div>

        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-amber-950/60 border border-amber-800/80 text-amber-300 text-xs font-mono font-medium">
          <AlertCircle className="w-3.5 h-3.5 text-amber-400" />
          <span>Not connected yet</span>
        </div>
      </div>

      {/* Main Body */}
      <div className="p-10 space-y-8 max-w-2xl mx-auto text-center">
        <div className="space-y-3">
          <h4 className="text-base font-semibold text-zinc-100">Git Push Integration</h4>
          <p className="text-sm text-zinc-300 leading-relaxed">
            Git push will route commits through the custody gateway to scan for secrets, enforce branch restrictions, and mirror snapshots to creator storage.
          </p>
        </div>

        {/* Planned Architecture Overview (No fake executions, strictly what it will do) */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 text-left pt-2">
          <div className="bg-zinc-900/60 border border-zinc-800/80 rounded-xl p-4 space-y-2">
            <div className="flex items-center gap-2 text-indigo-400 text-xs font-semibold">
              <ShieldCheck className="w-4 h-4" />
              <span>Secret Scanning</span>
            </div>
            <p className="text-xs text-zinc-400 leading-relaxed">
              Pre-receive hook scans every commit for high-entropy tokens and API keys before accepting.
            </p>
          </div>

          <div className="bg-zinc-900/60 border border-zinc-800/80 rounded-xl p-4 space-y-2">
            <div className="flex items-center gap-2 text-emerald-400 text-xs font-semibold">
              <GitBranch className="w-4 h-4" />
              <span>Branch Isolation</span>
            </div>
            <p className="text-xs text-zinc-400 leading-relaxed">
              Pushes are restricted exclusively to door-scoped branches to protect production branches.
            </p>
          </div>

          <div className="bg-zinc-900/60 border border-zinc-800/80 rounded-xl p-4 space-y-2">
            <div className="flex items-center gap-2 text-cyan-400 text-xs font-semibold">
              <HardDrive className="w-4 h-4" />
              <span>Mirror Snapshots</span>
            </div>
            <p className="text-xs text-zinc-400 leading-relaxed">
              Every verified push is bundled and backed up directly to creator-owned cloud storage.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};
