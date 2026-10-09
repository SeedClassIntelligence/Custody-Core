import React, { useState } from 'react';
import { DoorClosed, AlertCircle } from 'lucide-react';
import { Project } from '../types/custody';
import { ServerDoor } from '../utils/api';

interface DoorDetailsViewProps {
  door: ServerDoor;
  doors: ServerDoor[];
  project: Project;
  onSelectDoor: (doorId: string) => void;
  onCloseDoor: (doorId: string) => Promise<void>;
}

const STATUS_STYLE: Record<string, string> = {
  open: 'bg-emerald-950/60 border-emerald-800 text-emerald-300',
  draft: 'bg-zinc-800 border-zinc-700 text-zinc-300',
  closed: 'bg-zinc-900 border-zinc-700 text-zinc-500'
};

/** What is stored about a door, from the server. Closing it revokes the gateway credential at once. */
export const DoorDetailsView: React.FC<DoorDetailsViewProps> = ({ door, doors, project, onSelectDoor, onCloseDoor }) => {
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const expired = door.status === 'open' && new Date(door.expires_at).getTime() <= Date.now();

  const close = async () => {
    setBusy(true);
    setError(null);
    try {
      await onCloseDoor(door.id);
      setConfirming(false);
    } catch (err: any) {
      setError(err.message || 'The door could not be closed.');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-4">
      {doors.length > 1 && (
        <div className="flex flex-wrap gap-2">
          {doors.map((d) => (
            <button
              key={d.id}
              onClick={() => onSelectDoor(d.id)}
              className={`text-xs px-3 py-1.5 rounded-lg border ${d.id === door.id ? 'bg-zinc-800 border-zinc-600 text-white' : 'bg-zinc-950 border-zinc-800 text-zinc-400'}`}
            >
              {d.developer_email} · {d.status}
            </button>
          ))}
        </div>
      )}

      <div className="bg-zinc-950 border border-zinc-800 rounded-2xl p-6 space-y-6">
        <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4 border-b border-zinc-800/80 pb-5">
          <div className="space-y-1">
            <h3 className="text-lg font-bold text-zinc-100">{door.job_description}</h3>
            <p className="text-xs text-zinc-400">
              Project {project.name} · Developer {door.developer_email} · Rights: {door.rights_type}
            </p>
            <span className={`inline-block text-[11px] font-mono px-2 py-0.5 rounded-full border ${STATUS_STYLE[door.status] ?? STATUS_STYLE.draft}`}>
              {expired ? 'open (expired: the gateway refuses it)' : door.status}
            </span>
          </div>
          {door.status !== 'closed' && (
            <div className="flex flex-col items-end gap-2">
              {!confirming ? (
                <button
                  onClick={() => setConfirming(true)}
                  className="bg-rose-900/40 hover:bg-rose-900/70 text-rose-200 border border-rose-800 text-xs font-medium px-3.5 py-2 rounded-lg flex items-center gap-1.5"
                >
                  <DoorClosed className="w-3.5 h-3.5" />
                  Close the door
                </button>
              ) : (
                <div className="text-xs text-zinc-300 space-y-2 text-right max-w-xs">
                  <p>The developer's next git request will be refused, and the gateway's copies of these repositories are deleted. This cannot be undone.</p>
                  <div className="flex justify-end gap-2">
                    <button onClick={() => setConfirming(false)} className="text-zinc-400 px-3 py-1.5">
                      Cancel
                    </button>
                    <button
                      disabled={busy}
                      onClick={close}
                      className="bg-rose-700 hover:bg-rose-600 disabled:opacity-50 text-white font-semibold px-3 py-1.5 rounded-lg"
                    >
                      {busy ? 'Closing...' : 'Close it now'}
                    </button>
                  </div>
                </div>
              )}
              {error && <div className="text-xs text-rose-300">{error}</div>}
            </div>
          )}
        </div>

        <div className="grid md:grid-cols-2 gap-6 text-xs">
          <div className="space-y-2">
            <h4 className="font-semibold uppercase tracking-wider text-zinc-400">Repositories</h4>
            {door.repositories.map((r) => (
              <div key={r.repository_id} className="flex justify-between font-mono text-zinc-200">
                <span>{r.full_name}</span>
                <span className="text-zinc-500">{r.access === 'write' ? `read, push to ${door.branch_prefix}*` : 'read only'}</span>
              </div>
            ))}
          </div>
          <div className="space-y-2">
            <h4 className="font-semibold uppercase tracking-wider text-zinc-400">Access</h4>
            <div className="text-zinc-300">Opened: {door.opens_at ? new Date(door.opens_at).toLocaleString() : 'not yet'}</div>
            <div className="text-zinc-300">Access ends: {new Date(door.expires_at).toLocaleString()}</div>
            {door.closed_at && <div className="text-zinc-300">Closed: {new Date(door.closed_at).toLocaleString()}</div>}
            <div className="text-zinc-300">
              Credential:{' '}
              {door.credential
                ? `active, last used ${door.credential.last_used_at ? new Date(door.credential.last_used_at).toLocaleString() : 'never'}`
                : door.status === 'closed'
                  ? 'revoked'
                  : 'none'}
            </div>
          </div>
        </div>

        {door.remotes.length > 0 && (
          <div className="space-y-1.5 text-xs">
            <h4 className="font-semibold uppercase tracking-wider text-zinc-400">Gateway addresses</h4>
            {door.remotes.map((r) => (
              <code key={r.url} className="block font-mono text-[11px] text-zinc-300 bg-zinc-900 border border-zinc-800 rounded px-2 py-1 break-all">
                {r.url}
              </code>
            ))}
          </div>
        )}

        <div className="flex items-start gap-2 text-xs text-zinc-400 border-t border-zinc-800/80 pt-4">
          <AlertCircle className="w-3.5 h-3.5 text-amber-400 shrink-0 mt-0.5" />
          <span>
            Not connected yet: developer signing of the agreement, sandboxed workspaces, closing automatically at expiry (the gateway already
            refuses an expired door), and a backup snapshot on close. Every fetch, push and refused push is in the Event Chain.
          </span>
        </div>
      </div>
    </div>
  );
};
