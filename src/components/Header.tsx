import React, { useEffect, useState } from 'react';
import {
  Shield,
  Key,
  FolderLock,
  HardDrive,
  Activity,
  Terminal,
  FileCheck,
  CheckCircle2,
  AlertTriangle,
  Sparkles,
  Database
} from 'lucide-react';
import { RoleMode, Connection } from '../types/custody';

interface HeaderProps {
  currentTab: string;
  onSelectTab: (tab: string) => void;
  roleMode: RoleMode;
  onSelectRoleMode: (mode: RoleMode) => void;
  connections: Connection[];
  codeHome: import('../utils/api').CodeHomeStatus | null;
  onOpenSetup: () => void;
  userEmail: string;
  onSignOut: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  currentTab,
  onSelectTab,
  roleMode,
  onSelectRoleMode,
  connections,
  codeHome,
  onOpenSetup,
  userEmail,
  onSignOut
}) => {
  const [dbStatus, setDbStatus] = useState<'checking' | 'connected' | 'not_connected'>('checking');

  useEffect(() => {
    fetch('/api/v1/health')
      .then(res => res.json())
      .then(data => {
        if (data?.database?.status === 'connected') {
          setDbStatus('connected');
        } else {
          setDbStatus('not_connected');
        }
      })
      .catch(() => {
        setDbStatus('not_connected');
      });
  }, []);

  // The code home as the server reports it (GET /api/v1/github/connection).
  const ghInst = codeHome?.installation ?? null;
  const s3Conn = connections.find(c => (c.kind === 'storage_s3' || c.kind === 'storage_drive') && c.status === 'connected');

  return (
    <header className="border-b border-zinc-800 bg-zinc-950 text-zinc-100 sticky top-0 z-40 backdrop-blur-md bg-opacity-95">
      {/* Top Banner: Real Service Status */}
      <div className="bg-gradient-to-r from-zinc-900 via-zinc-900 to-zinc-950 px-4 py-1.5 border-b border-zinc-800/80 flex items-center justify-between text-xs">
        <div className="flex items-center gap-2">
          <span className={`flex h-2 w-2 rounded-full ${dbStatus === 'connected' ? 'bg-emerald-400' : dbStatus === 'checking' ? 'bg-zinc-500' : 'bg-amber-400'}`} />
          <span className="font-mono text-zinc-400">Custody Core</span>
          <span className="text-zinc-600">|</span>
          <span className="text-zinc-300">Phase 1: Custody Core</span>
          <span className="rounded bg-indigo-950/80 border border-indigo-700/60 px-1.5 py-0.5 text-[10px] font-medium text-indigo-300">
            Milestone 3 Active
          </span>
        </div>

        <div className="flex items-center gap-3 text-[11px] text-zinc-400">
          <div className="flex items-center gap-1.5">
            <Database className="w-3 h-3 text-emerald-400" />
            <span>Database: {dbStatus === 'connected' ? (
              <strong className="text-emerald-400">PostgreSQL Connected</strong>
            ) : (
              <span className="text-amber-400 font-medium">Not connected yet (Set DATABASE_URL)</span>
            )}</span>
          </div>
          <span className="text-zinc-700">•</span>
          <div className="flex items-center gap-1.5">
            <FolderLock className="w-3 h-3 text-zinc-400" />
            <span>Code home: {ghInst?.status === 'active' ? (
              <strong className="text-zinc-200">Connected ({ghInst.organization})</strong>
            ) : ghInst ? (
              <strong className="text-rose-400">Connection broken</strong>
            ) : codeHome && !codeHome.configured ? (
              <span className="text-zinc-500">Not connected yet (GitHub App not set up on the server)</span>
            ) : (
              <span className="text-zinc-500">Not connected yet</span>
            )}</span>
          </div>
          <span className="text-zinc-700">•</span>
          <div className="flex items-center gap-1.5">
            <HardDrive className="w-3 h-3 text-zinc-400" />
            <span>Backup Storage: {s3Conn ? (
              <strong className="text-zinc-200">Connected</strong>
            ) : (
              <span className="text-zinc-500">Not connected yet</span>
            )}</span>
          </div>
        </div>
      </div>

      {/* Main Navigation Bar */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
        <div className="flex items-center gap-6">
          <div className="flex items-center gap-2.5 cursor-pointer" onClick={() => onSelectTab('dashboard')}>
            <div className="h-9 w-9 rounded-lg bg-gradient-to-br from-indigo-500 to-indigo-700 flex items-center justify-center shadow-lg shadow-indigo-500/20 border border-indigo-400/30">
              <Shield className="w-5 h-5 text-white" />
            </div>
            <div>
              <div className="text-base font-bold tracking-tight text-white flex items-center gap-2">
                Custody Core
                <span className="text-[10px] font-mono uppercase tracking-widest bg-zinc-800 text-zinc-300 px-1.5 py-0.5 rounded border border-zinc-700">
                  Phase 1
                </span>
              </div>
              <p className="text-[11px] text-zinc-400 leading-none">Creator-Owned Code Custody & Git Gateway</p>
            </div>
          </div>

          {/* Primary View Switcher */}
          <nav className="hidden md:flex items-center gap-1 bg-zinc-900/90 p-1 rounded-lg border border-zinc-800 text-xs">
            <button
              onClick={() => {
                onSelectRoleMode('creator');
                onSelectTab('dashboard');
              }}
              className={`px-3 py-1.5 rounded-md font-medium transition-all ${
                currentTab === 'dashboard'
                  ? 'bg-zinc-800 text-white shadow-sm'
                  : 'text-zinc-400 hover:text-zinc-200'
              }`}
            >
              Project Home
            </button>
            <button
              onClick={() => {
                onSelectRoleMode('developer');
                onSelectTab('workspace');
              }}
              className={`px-3 py-1.5 rounded-md font-medium transition-all flex items-center gap-1.5 ${
                currentTab === 'workspace'
                  ? 'bg-indigo-600 text-white shadow-sm'
                  : 'text-zinc-400 hover:text-zinc-200'
              }`}
            >
              <Terminal className="w-3.5 h-3.5" />
              Developer Workspace
              <span className="text-[10px] text-zinc-400 bg-zinc-800/80 px-1.5 py-0.2 rounded border border-zinc-700">
                Not connected yet
              </span>
            </button>
            <button
              onClick={() => onSelectTab('activity')}
              className={`px-3 py-1.5 rounded-md font-medium transition-all flex items-center gap-1.5 ${
                currentTab === 'activity'
                  ? 'bg-zinc-800 text-white shadow-sm'
                  : 'text-zinc-400 hover:text-zinc-200'
              }`}
            >
              <Activity className="w-3.5 h-3.5 text-emerald-400" />
              Event Chain & Verification (Server)
            </button>
            <button
              onClick={() => onSelectTab('backup')}
              className={`px-3 py-1.5 rounded-md font-medium transition-all flex items-center gap-1.5 ${
                currentTab === 'backup'
                  ? 'bg-zinc-800 text-white shadow-sm'
                  : 'text-zinc-400 hover:text-zinc-200'
              }`}
            >
              <HardDrive className="w-3.5 h-3.5 text-cyan-400" />
              Mirror & Export
            </button>
            <button
              onClick={() => onSelectTab('acceptance')}
              className={`px-3 py-1.5 rounded-md font-medium transition-all flex items-center gap-1.5 ${
                currentTab === 'acceptance'
                  ? 'bg-zinc-800 text-white shadow-sm'
                  : 'text-zinc-400 hover:text-zinc-200'
              }`}
            >
              <FileCheck className="w-3.5 h-3.5 text-amber-400" />
              Demo Scenarios (Spec Ref)
            </button>
          </nav>
        </div>

        {/* Right Action Tools */}
        <div className="flex items-center gap-3">
          <button
            onClick={onOpenSetup}
            className="hidden sm:inline-flex items-center gap-1.5 text-xs text-zinc-300 bg-zinc-900 hover:bg-zinc-800 border border-zinc-700/80 px-3 py-1.5 rounded-lg transition-colors font-medium"
            title="Setup guide for Supabase, GitHub App, and Storage"
          >
            <Sparkles className="w-3.5 h-3.5 text-amber-400" />
            Setup Guide
          </button>

          <span className="hidden md:inline text-xs text-zinc-400 max-w-[14rem] truncate" title={userEmail}>
            {userEmail}
          </span>
          <button
            onClick={onSignOut}
            className="inline-flex items-center gap-1 text-xs text-zinc-300 hover:text-white bg-zinc-900 hover:bg-zinc-800 border border-zinc-700/80 px-3 py-1.5 rounded-lg transition-colors font-medium"
          >
            Sign out
          </button>

        </div>
      </div>
    </header>
  );
};
