import React, { useState } from 'react';
import { DoorOpen, X, Copy, Check, AlertTriangle } from 'lucide-react';
import { Project } from '../types/custody';
import { createDoor, openDoor, ServerDoor } from '../utils/api';

interface OpenDoorModalProps {
  isOpen: boolean;
  onClose: () => void;
  project: Project;
  githubConnected: boolean;
  onDoorOpened: (door: ServerDoor) => void;
}

const RIGHTS = [
  { value: 'contribute', label: 'Contribute (work for hire)' },
  { value: 'license', label: 'License' },
  { value: 'transfer', label: 'Transfer' },
  { value: 'maintain', label: 'Maintain' }
];

function CopyLine({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="flex items-center gap-2 bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2">
      <code className="flex-1 text-[11px] font-mono text-zinc-200 break-all">{text}</code>
      <button
        type="button"
        onClick={() => {
          void navigator.clipboard?.writeText(text);
          setCopied(true);
          setTimeout(() => setCopied(false), 1500);
        }}
        className="text-zinc-400 hover:text-zinc-100 shrink-0"
        title="Copy"
      >
        {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
      </button>
    </div>
  );
}

/** Creates a door and opens it. The credential is shown once, here, and never again. */
export const OpenDoorModal: React.FC<OpenDoorModalProps> = ({ isOpen, onClose, project, githubConnected, onDoorOpened }) => {
  const [email, setEmail] = useState('');
  const [job, setJob] = useState('');
  const [rights, setRights] = useState('contribute');
  const [days, setDays] = useState(14);
  const [access, setAccess] = useState<Record<string, '' | 'read' | 'write'>>({});
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<{ door: ServerDoor; token: string } | null>(null);

  if (!isOpen) return null;

  const close = () => {
    setResult(null);
    setError(null);
    setEmail('');
    setJob('');
    setAccess({});
    onClose();
  };

  const chosen = Object.entries(access).filter(([, a]) => a) as Array<[string, 'read' | 'write']>;

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    if (chosen.length === 0) return setError('Choose at least one repository.');
    setBusy(true);
    try {
      const door = await createDoor(project.id, {
        developer_email: email.trim(),
        job_description: job.trim(),
        rights_type: rights,
        expires_at: new Date(Date.now() + days * 86400_000).toISOString(),
        repositories: chosen.map(([repository_id, a]) => ({ repository_id, access: a }))
      });
      const opened = await openDoor(project.id, door.id);
      setResult({ door: opened.door, token: opened.credential.token });
      onDoorOpened(opened.door);
    } catch (err: any) {
      setError(err.message || 'The door could not be opened.');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
      <div className="bg-zinc-900 border border-zinc-700/80 rounded-2xl max-w-2xl w-full shadow-2xl overflow-hidden flex flex-col max-h-[92vh]">
        <div className="px-6 py-5 border-b border-zinc-800 bg-zinc-950 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-amber-500/10 border border-amber-500/20 flex items-center justify-center text-amber-400">
              <DoorOpen className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-lg font-semibold text-zinc-100">Open a Door</h2>
              <p className="text-xs text-zinc-400">Project: {project.name}</p>
            </div>
          </div>
          <button onClick={close} className="text-zinc-400 hover:text-zinc-200 p-1.5 rounded-lg hover:bg-zinc-800">
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="p-6 overflow-y-auto space-y-5 text-sm">
          {result ? (
            <div className="space-y-4">
              <div className="flex items-start gap-2 p-3 rounded-lg bg-amber-950/40 border border-amber-800/70 text-amber-200 text-xs">
                <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
                <span>
                  This credential is shown <strong>once</strong>. Send it to {result.door.developer_email} privately (not in the same
                  message as the addresses below). Custody Core keeps only a fingerprint of it. Closing the door ends it immediately.
                </span>
              </div>
              <div className="space-y-1.5">
                <div className="text-xs text-zinc-400">Credential (git asks for a password: use this; any user name works)</div>
                <CopyLine text={result.token} />
              </div>
              <div className="space-y-1.5">
                <div className="text-xs text-zinc-400">Clone through Custody Core (not GitHub):</div>
                {result.door.remotes.map((r) => (
                  <CopyLine key={r.url} text={`git clone ${r.url}`} />
                ))}
              </div>
              <div className="space-y-1.5">
                <div className="text-xs text-zinc-400">Pushes are accepted only to branches under the door's prefix, after a secret scan:</div>
                <CopyLine text={`git push origin HEAD:${result.door.branch_prefix}my-change`} />
              </div>
              <p className="text-xs text-zinc-500">
                Access ends {new Date(result.door.expires_at).toLocaleString()} (the gateway refuses it from then on). Developer signing and sandboxed workspaces are not connected yet:
                the developer uses their own machine with this credential.
              </p>
              <div className="flex justify-end">
                <button onClick={close} className="bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold px-4 py-2.5 rounded-xl">
                  I have saved the credential
                </button>
              </div>
            </div>
          ) : !githubConnected ? (
            <p className="text-zinc-300 text-sm">Connect GitHub first (top bar). The gateway reaches your repositories through it.</p>
          ) : project.repositories.length === 0 ? (
            <p className="text-zinc-300 text-sm">Add at least one GitHub repository to this project first (Code Home on the project page).</p>
          ) : (
            <form onSubmit={submit} className="space-y-4">
              <label className="block space-y-1">
                <span className="text-xs text-zinc-400">Developer's email</span>
                <input
                  type="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="w-full bg-zinc-950 border border-zinc-700 rounded-lg px-3 py-2 text-zinc-100 text-sm"
                />
              </label>
              <label className="block space-y-1">
                <span className="text-xs text-zinc-400">What they are hired to do</span>
                <textarea
                  required
                  value={job}
                  onChange={(e) => setJob(e.target.value)}
                  rows={3}
                  maxLength={5000}
                  className="w-full bg-zinc-950 border border-zinc-700 rounded-lg px-3 py-2 text-zinc-100 text-sm"
                />
              </label>
              <div className="grid grid-cols-2 gap-3">
                <label className="block space-y-1">
                  <span className="text-xs text-zinc-400">Rights</span>
                  <select value={rights} onChange={(e) => setRights(e.target.value)} className="w-full bg-zinc-950 border border-zinc-700 rounded-lg px-3 py-2 text-zinc-100 text-sm">
                    {RIGHTS.map((r) => (
                      <option key={r.value} value={r.value}>
                        {r.label}
                      </option>
                    ))}
                  </select>
                </label>
                <label className="block space-y-1">
                  <span className="text-xs text-zinc-400">Access ends after (days)</span>
                  <input
                    type="number"
                    min={1}
                    max={365}
                    value={days}
                    onChange={(e) => setDays(Math.max(1, Math.min(365, Number(e.target.value) || 1)))}
                    className="w-full bg-zinc-950 border border-zinc-700 rounded-lg px-3 py-2 text-zinc-100 text-sm"
                  />
                </label>
              </div>
              <div className="space-y-1.5">
                <span className="text-xs text-zinc-400">Repositories</span>
                {project.repositories.map((repo) => (
                  <div key={repo.id} className="flex items-center justify-between bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2">
                    <span className="font-mono text-xs text-zinc-200">{repo.full_name}</span>
                    <select
                      value={access[repo.id] ?? ''}
                      onChange={(e) => setAccess({ ...access, [repo.id]: e.target.value as '' | 'read' | 'write' })}
                      className="bg-zinc-900 border border-zinc-700 rounded px-2 py-1 text-xs text-zinc-200"
                    >
                      <option value="">No access</option>
                      <option value="read">Read</option>
                      <option value="write">Read and push to door branches</option>
                    </select>
                  </div>
                ))}
              </div>
              {error && <div className="text-xs text-rose-300 bg-rose-950/40 border border-rose-800 rounded-lg p-3">{error}</div>}
              <div className="flex justify-end gap-2">
                <button type="button" onClick={close} className="text-zinc-300 text-xs px-4 py-2.5">
                  Cancel
                </button>
                <button disabled={busy} className="bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white text-xs font-semibold px-4 py-2.5 rounded-xl">
                  {busy ? 'Opening...' : 'Open the door'}
                </button>
              </div>
            </form>
          )}
        </div>
      </div>
    </div>
  );
};
