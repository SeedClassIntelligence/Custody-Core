import React, { useState } from 'react';
import { FolderLock, Loader2, CheckCircle2, XCircle, Upload } from 'lucide-react';
import { CustodyEvent, Project } from '../types/custody';
import { CodeHomeStatus, createCodeHomeRepositories } from '../utils/api';
import { SettingsList } from './CodeHomePanel';

/** What GitHub reported for each repository, read from the project's own event log. */
function repositoryRecords(events: CustodyEvent[]) {
  return events.filter((e) => e.action === 'repository.created').map((e) => e.payload as any);
}

export function rulesLine(ruleset: any): { ok: boolean; text: string } {
  if (ruleset?.applied) return { ok: true, text: 'Branch rules: active (no deletion, no force-push, changes only through Custody Core)' };
  if (ruleset?.refused?.needs_paid_plan) return { ok: false, text: 'Branch rules: needs GitHub Team, not active' };
  if (ruleset?.refused) return { ok: false, text: `Branch rules: not active (GitHub said: ${ruleset.refused.message})` };
  return { ok: false, text: 'Branch rules: not active (GitHub did not confirm them)' };
}

/** Choosing the repositories: a separate core repository, and optionally existing code as a zip. */
export const RepositoryOptions: React.FC<{
  splitCore: boolean;
  onSplitCore: (v: boolean) => void;
  zip: File | null;
  onZip: (f: File | null) => void;
  disabled?: boolean;
}> = ({ splitCore, onSplitCore, zip, onZip, disabled }) => (
  <div className="space-y-2 text-xs text-zinc-300">
    <label className="flex items-start gap-2">
      <input type="checkbox" checked={splitCore} disabled={disabled} onChange={(e) => onSplitCore(e.target.checked)} className="mt-0.5" />
      <span>Also create a separate <span className="text-zinc-100">core</span> repository (for the part of the code you keep closest).</span>
    </label>
    <label className="block">
      <span className="flex items-center gap-1.5 text-zinc-400">
        <Upload className="w-3.5 h-3.5" /> Existing code (optional): a .zip of your project folder. Leave empty to start with an empty repository.
      </span>
      <input
        type="file"
        accept=".zip,application/zip"
        disabled={disabled}
        onChange={(e) => onZip(e.target.files?.[0] ?? null)}
        className="mt-1 text-[11px] text-zinc-400"
        data-testid="zip-input"
      />
      {zip && <span className="block text-[11px] text-zinc-500">{zip.name} ({Math.ceil(zip.size / 1024)} KB)</span>}
    </label>
  </div>
);

export const RepositoriesCard: React.FC<{
  project: Project;
  events: CustodyEvent[];
  codeHome: CodeHomeStatus | null;
  onCreated: () => void;
}> = ({ project, events, codeHome, onCreated }) => {
  const [splitCore, setSplitCore] = useState(false);
  const [zip, setZip] = useState<File | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const records = repositoryRecords(events);
  const failures = events.filter((e) => e.action === 'repository.creation_failed');
  const connected = codeHome?.installation?.status === 'active';

  const create = async () => {
    setBusy(true);
    setError(null);
    try {
      await createCodeHomeRepositories(project.id, { splitCore, zip });
      onCreated();
    } catch (e: any) {
      setError(e.message);
      onCreated(); // a failure is recorded too
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="bg-zinc-950 border border-zinc-800 rounded-2xl p-5 space-y-3" data-testid="repositories-card">
      <h3 className="text-xs font-semibold uppercase tracking-wider text-zinc-400 flex items-center gap-1.5">
        <FolderLock className="w-3.5 h-3.5 text-indigo-400" />
        Repositories
      </h3>

      {records.length === 0 && (
        <>
          {!connected ? (
            <p className="text-xs text-zinc-400">
              <span className="text-amber-300 font-medium">Not connected yet:</span> connect your code home (above) to create this project's private
              repositories.
            </p>
          ) : (
            <div className="space-y-3">
              <p className="text-xs text-zinc-400">
                Create this project's private repositories in <span className="font-mono text-zinc-200">{codeHome!.installation!.organization}</span>.
              </p>
              <RepositoryOptions splitCore={splitCore} onSplitCore={setSplitCore} zip={zip} onZip={setZip} disabled={busy} />
              <button
                onClick={create}
                disabled={busy}
                className="bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white font-medium px-4 py-2 rounded-lg text-xs flex items-center gap-2"
              >
                {busy && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
                {busy ? 'Creating on GitHub...' : 'Create repositories'}
              </button>
            </div>
          )}
        </>
      )}

      {error && <div className="p-3 rounded-lg text-xs border bg-rose-950/50 border-rose-800 text-rose-200">{error}</div>}

      {records.map((r) => {
        const rules = rulesLine(r.ruleset);
        return (
          <div key={r.full_name} className="border border-zinc-800 rounded-xl p-3 space-y-2" data-testid="repository-record">
            <div className="flex items-center justify-between gap-2">
              <a href={r.html_url} target="_blank" rel="noreferrer" className="font-mono text-xs text-indigo-300 hover:text-indigo-200">
                {r.full_name}
              </a>
              <span className="text-[10px] uppercase tracking-wider text-zinc-500">{r.role === 'core' ? 'core' : 'main'}</span>
            </div>
            <p className="text-[11px] text-zinc-500">As GitHub reported after creating it:</p>
            <SettingsList settings={r.settings} />
            <div className="flex items-center gap-2 text-[11px]">
              {rules.ok ? <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" /> : <XCircle className="w-3.5 h-3.5 text-amber-400" />}
              <span className={rules.ok ? 'text-zinc-200' : 'text-amber-300'} data-testid="branch-rules">
                {rules.text}
              </span>
            </div>
            {r.initial_commit && (
              <div className="text-[11px] text-zinc-400">
                First commit: {r.initial_commit.files} files,{' '}
                {r.initial_commit.matches ? (
                  <span className="text-zinc-200">GitHub reports commit {String(r.initial_commit.reported_sha).slice(0, 12)}</span>
                ) : (
                  <span className="text-rose-300">GitHub does not report the pushed commit</span>
                )}
              </div>
            )}
          </div>
        );
      })}

      {failures.map((f) => (
        <div key={f.seq} className="text-[11px] text-rose-300">
          GitHub did not create {(f.payload as any).name}: {(f.payload as any).error?.message}
        </div>
      ))}
    </div>
  );
};
