import React from 'react';
import { DoorClosed, AlertCircle, FileCheck2 } from 'lucide-react';
import { Door, Project } from '../types/custody';

interface DoorDetailsViewProps {
  door: Door;
  project: Project;
  onCloseDoor: (doorId: string) => Promise<void>;
  onOpenInviteModal?: (door: Door) => void;
}

/** Shows only what is stored about the door. Every action here is "Not connected yet". */
export const DoorDetailsView: React.FC<DoorDetailsViewProps> = ({ door, project, onCloseDoor, onOpenInviteModal }) => {
  return (
    <div className="bg-zinc-950 border border-zinc-800 rounded-2xl p-6 space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-zinc-800/80 pb-5">
        <div>
          <h3 className="text-lg font-bold text-zinc-100">{door.job_description}</h3>
          <p className="text-xs text-zinc-400 mt-1">
            Project {project.name} • Developer {door.developer_email} • Status{' '}
            <span className="capitalize">{door.status.replace('_', ' ')}</span>
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {onOpenInviteModal && (
            <button
              onClick={() => onOpenInviteModal(door)}
              className="bg-zinc-800 hover:bg-zinc-700 text-zinc-200 border border-zinc-700 text-xs font-medium px-3.5 py-2 rounded-lg flex items-center gap-1.5 transition-colors"
            >
              <FileCheck2 className="w-3.5 h-3.5" />
              <span>Developer signing: Not connected yet</span>
            </button>
          )}
          <button
            onClick={() => onCloseDoor(door.id)}
            className="bg-zinc-800 hover:bg-zinc-700 text-zinc-200 border border-zinc-700 text-xs font-medium px-3.5 py-2 rounded-lg flex items-center gap-1.5 transition-colors"
          >
            <DoorClosed className="w-3.5 h-3.5" />
            <span>Close the door: Not connected yet</span>
          </button>
        </div>
      </div>

      <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-amber-950/60 border border-amber-800/80 text-amber-300 text-xs font-mono font-medium">
        <AlertCircle className="w-3.5 h-3.5 text-amber-400" />
        <span>Not connected yet</span>
      </div>
      <p className="text-sm text-zinc-300 leading-relaxed max-w-2xl">
        Doors will give a developer narrow, temporary, signed access, and closing one will end that access, revoke credentials and
        destroy the workspace. Until that is built, this screen shows no access state, time left or activity.
      </p>
    </div>
  );
};
