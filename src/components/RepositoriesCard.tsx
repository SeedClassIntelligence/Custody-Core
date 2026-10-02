import React, { useState } from 'react';
import { FolderLock, Loader2, CheckCircle2, XCircle, Upload } from 'lucide-react';
import { CustodyEvent, Project } from '../types/custody';
import { CodeHomeStatus, createCodeHomeRepositories, finishRepositoryLock } from '../utils/api';
import { SettingsList } from './CodeHomePanel';

const CHANGE_TEXT: Record<string, string> = {
  'repository.no_longer_visible_on_github': 'GitHub no longer shows this repository to Custody Core (deleted, moved, or access removed)',
  'repository.visible_again_on_github': 'GitHub shows this repository to Custody Core again',
  'repository.transferred_on_github': 'GitHub reports this repository is now under another account',
  'repository.publicized_on_github': 'GitHub reports this repository was made public',
  'repository.privatized_on_github': 'GitHub reports this repository is private again',
  'repository.renamed_on_github': 'GitHub reports this repository was renamed',
  'repository.archived_on_github': 'GitHub reports this repository was archived',
  'repository.unarchived_on_github': 'GitHub reports this repository was unarchived'
};

/**
 * Each repository as the project's own event log describes it: what GitHub reported when it was created or last
 * checked, and every change GitHub has reported since.
 */
function repositoryRecords(events: CustodyEvent[]) {
  const byRepo = new Map<string, { id: string; latest: any; checkedAt: string; checked: boolean; initialCommit: any; changes: CustodyEvent[] }>();
  for (const e of events) {
    if (e.subject_type !== 'repository') continue;
    const p = e.payload as any;
    if (e.action === 'repository.created' || e.action === 'repository.lock_checked') {
      const prev = byRepo.get(e.subject_id);
      byRepo.set(e.subject_id, {
        id: e.subject_id,
        latest: p,
        checkedAt: e.timestamp,
        checked: e.action === 'repository.lock_checked',
        initialCommit: p.initial_commit ?? prev?.initialCommit ?? null,
        changes: prev?.changes ?? []
      });
    } else if (e.action.endsWith('_on_github')) {
      byRepo.get(e.subject_id)?.changes.push(e);
    }
  }
  return [...byRepo.values()];
}

/**
 * Something the creator can fix by checking again: an unfinished step, a setting GitHub did not confirm, code
 * that did not arrive, or branch rules refused for a reason other than the plan. Branch rules a free plan cannot
 * have are not fixable here, so no button pretends otherwise.
 */
function fixable(r: any, ic: any): boolean {
  return (
    !!r.incomplete ||
    (r.settings ?? []).length === 0 ||
    (r.settings ?? []).some((x: any) => !x.applied) ||
    (ic && !ic.matches) ||
    (!r.ruleset?.applied && !r.ruleset?.refused?.needs_paid_plan)
  );
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
  const repos = repositoryRecords(events);
  const records = repos.map((r) => r.latest);
  const recordedNames = new Set(records.map((r) => String(r.full_name).split('/')[1]));
  const [relocking, setRelocking] = useState<string | null>(null);
  const [retryZip, setRetryZip] = useState<File | null>(null);
  const relock = async (repoId: string, zip: File | null) => {
    setRelocking(repoId);
    setError(null);
    try {
      await finishRepositoryLock(project.id, repoId, zip);
    } catch (e: any) {
      setError(e.message);
    } finally {
      setRelocking(null);
      setRetryZip(null);
      onCreated();
    }
  };
  // A failure stays on screen only while that repository still does not exist.
  const failures = events.filter((e) => e.action === 'repository.creation_failed' && !recordedNames.has(String((e.payload as any).name)));
  const connected = codeHome?.installation?.status === 'active';
  const hasMain = records.some((r) => r.role === 'main');
  const coreMissing = hasMain && !records.some((r) => r.role === 'core') && failures.some((f) => (f.payload as any).role === 'core');

  const create = async (finishCore = false) => {
    setBusy(true);
    setError(null);
    try {
      await createCodeHomeRepositories(project.id, finishCore ? { splitCore: true, zip: null } : { splitCore, zip });
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
                onClick={() => void create()}
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

      {connected && coreMissing && (
        <div className="space-y-2 border border-amber-800/60 rounded-xl p-3 text-xs text-amber-200" data-testid="finish-claim">
          <p>The core repository was not created. You can finish the claim now.</p>
          <button
            onClick={() => void create(true)}
            disabled={busy}
            className="bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white font-medium px-4 py-2 rounded-lg text-xs flex items-center gap-2"
          >
            {busy && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
            Finish creating the core repository
          </button>
        </div>
      )}

      {repos.map((repo) => {
        const r = repo.latest;
        const rules = rulesLine(r.ruleset);
        // Whether GitHub's latest report about visibility says it is gone.
        const visibility = repo.changes.filter((c) => c.action === 'repository.no_longer_visible_on_github' || c.action === 'repository.visible_again_on_github').pop();
        const gone = visibility?.action === 'repository.no_longer_visible_on_github';
        // A change GitHub reported after the last check means the settings shown may be out of date.
        const changedSinceCheck = repo.changes.some((c) => c.timestamp > repo.checkedAt);
        const ic = repo.initialCommit;
        const needsCode = r.role === 'main' && ic && !ic.pushed;
        return (
          <div key={repo.id} className="border border-zinc-800 rounded-xl p-3 space-y-2" data-testid="repository-record">
            <div className="flex items-center justify-between gap-2">
              <a href={r.html_url} target="_blank" rel="noreferrer" className="font-mono text-xs text-indigo-300 hover:text-indigo-200">
                {r.full_name}
              </a>
              <span className="text-[10px] uppercase tracking-wider text-zinc-500">{r.role === 'core' ? 'core' : 'main'}</span>
            </div>
            {repo.changes.map((c) => (
              <div key={c.seq} className="text-[11px] text-rose-300 font-medium" data-testid="github-change">
                {CHANGE_TEXT[c.action] ?? c.action}
                {c.action === 'repository.renamed_on_github' || c.action === 'repository.transferred_on_github' ? ` (now ${(c.payload as any).github_reports?.full_name})` : ''},{' '}
                {new Date(c.timestamp).toLocaleString()}.
              </div>
            ))}
            {!gone && (
              <>
                <p className="text-[11px] text-zinc-500">
                  {repo.checked ? `As GitHub reported when checked again on ${new Date(repo.checkedAt).toLocaleString()}:` : 'As GitHub reported after creating it:'}
                </p>
                <SettingsList settings={r.settings} />
                <div className="flex items-center gap-2 text-[11px]">
                  {rules.ok ? <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" /> : <XCircle className="w-3.5 h-3.5 text-amber-400" />}
                  <span className={rules.ok ? 'text-zinc-200' : 'text-amber-300'} data-testid="branch-rules">
                    {rules.text}
                  </span>
                </div>
              </>
            )}
            {ic && (
              <div className="text-[11px] text-zinc-400">
                {ic.matches ? (
                  <>
                    First commit: {ic.reported_files} files, <span className="text-zinc-200">GitHub reports commit {String(ic.reported_sha).slice(0, 12)}</span>
                  </>
                ) : ic.pushed ? (
                  <span className="text-rose-300">
                    First commit: {ic.files_uploaded} files uploaded, but GitHub reports {ic.reported_files ?? 'no'} files{ic.reported_sha ? '' : ' and no commit'}.
                  </span>
                ) : (
                  <span className="text-rose-300">The uploaded code was not pushed: {ic.error}</span>
                )}
              </div>
            )}
            {r.incomplete && <div className="text-[11px] text-rose-300">Created on GitHub, but not finished: {r.incomplete}</div>}
            {connected && !gone && (
              <div className="space-y-2 pt-1" data-testid={(!r.fully_locked && fixable(r, ic)) || changedSinceCheck ? 'finish-lock' : 'check-again'}>
                {needsCode && (
                  <label className="block text-[11px] text-zinc-400">
                    Upload the code again (.zip):
                    <input type="file" accept=".zip,application/zip" onChange={(e) => setRetryZip(e.target.files?.[0] ?? null)} className="block mt-1 text-[11px]" />
                  </label>
                )}
                <button
                  onClick={() => void relock(repo.id, needsCode ? retryZip : null)}
                  disabled={relocking !== null}
                  className="bg-zinc-800 hover:bg-zinc-700 disabled:opacity-50 text-zinc-100 font-medium px-3 py-1.5 rounded-lg text-[11px] flex items-center gap-2"
                >
                  {relocking === repo.id && <Loader2 className="w-3 h-3 animate-spin" />}
                  {(!r.fully_locked && fixable(r, ic)) || changedSinceCheck ? 'Check again with GitHub and finish locking' : 'Check again with GitHub'}
                </button>
              </div>
            )}
          </div>
        );
      })}

      {failures.map((f) => (
        <div key={f.seq} className="text-[11px] text-rose-300">
          GitHub did not create {(f.payload as any).name}: {(f.payload as any).error?.message}
          {(f.payload as any).error?.details ? ` (${(f.payload as any).error.details.join('; ')})` : ''}
        </div>
      ))}
    </div>
  );
};
