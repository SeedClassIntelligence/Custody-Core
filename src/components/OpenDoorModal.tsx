import React, { useState } from 'react';
import { DoorOpen, X, Copy, Check, AlertTriangle } from 'lucide-react';
import { Project } from '../types/custody';
import { createDoor, inviteDeveloper, ServerDoor } from '../utils/api';

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

/** Creates a door and invites the developer. The door opens when they sign; the credential goes to them, not here. */
export const OpenDoorModal: React.FC<OpenDoorModalProps> = ({ isOpen, onClose, project, githubConnected, onDoorOpened }) => {
  const [email, setEmail] = useState('');
  const [job, setJob] = useState('');
  const [rights, setRights] = useState('contribute');
  const [days, setDays] = useState(14);
  const [access, setAccess] = useState<Record<string, '' | 'read' | 'write'>>({});
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<{ door: ServerDoor; link: string; linkExpires: string } | null>(null);

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
      const invited = await inviteDeveloper(project.id, door.id);
      setResult({ door: invited.door, link: invited.invite.url, linkExpires: invited.invite.expires_at });
      onDoorOpened(invited.door);
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
                  This invitation link is shown <strong>once</strong>. Send it to {result.door.developer_email}. It works only for an account
                  with that email address, until {new Date(result.linkExpires).toLocaleString()}. Custody Core does not send emails yet.
                </span>
              </div>
              <CopyLine text={result.link} />
              <ol className="text-xs text-zinc-300 space-y-1 list-decimal list-inside">
                <li>They open the link, create an account with that address, confirm the email and set up an authenticator app.</li>
                <li>They read the agreement and sign it with a key made on their own device.</li>
                <li>The door opens, and they get their own git credential. You never see it.</li>
              </ol>
              <p className="text-xs text-zinc-500">
                You can send a new link from the door's page (the old one stops working). The agreement stays the same.
              </p>
              <div className="flex justify-end">
                <button onClick={close} className="bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold px-4 py-2.5 rounded-xl">
                  Done
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
                  <span className="text-xs text-zinc-400">Closes by itself after (days)</span>
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
                  {busy ? 'Creating...' : 'Create and invite'}
                </button>
              </div>
            </form>
          )}
        </div>
      </div>
    </div>
  );
};
