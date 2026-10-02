import React from 'react';
import { Shield, AlertCircle, X, DoorClosed, HardDrive, KeyRound, Trash2 } from 'lucide-react';
import { ClosingReport } from '../types/custody';

interface ClosingReportModalProps {
  isOpen: boolean;
  onClose: () => void;
  report?: ClosingReport | null;
  doorId?: string;
  developerEmail?: string;
}

export const ClosingReportModal: React.FC<ClosingReportModalProps> = ({
  isOpen,
  onClose,
  report,
  doorId,
  developerEmail
}) => {
  if (!isOpen) return null;

  const targetDoorId = report?.door_id || doorId || '';
  const targetEmail = report?.developer_email || developerEmail || '';

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/85 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="bg-zinc-900 border border-zinc-700/80 rounded-2xl max-w-xl w-full shadow-2xl overflow-hidden flex flex-col">
        {/* Header */}
        <div className="px-6 py-5 border-b border-zinc-800 bg-zinc-950 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-amber-500/10 border border-amber-500/20 flex items-center justify-center text-amber-400">
              <DoorClosed className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-lg font-semibold text-zinc-100">Close the Door</h2>
              {targetDoorId && <p className="text-xs text-zinc-400">Door #{targetDoorId.substring(0, 8)} • {targetEmail}</p>}
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-zinc-400 hover:text-zinc-200 p-1.5 rounded-lg hover:bg-zinc-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Honest Not Connected Body */}
        <div className="p-8 space-y-6 text-center">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-amber-950/60 border border-amber-800/80 text-amber-300 text-xs font-mono font-medium">
            <AlertCircle className="w-3.5 h-3.5 text-amber-400" />
            <span>Not connected yet</span>
          </div>

          <p className="text-sm text-zinc-300 leading-relaxed max-w-md mx-auto">
            Closing a door will revoke developer gateway credentials, snapshot preserved work to creator storage, and destroy the developer workspace.
          </p>

          {/* Planned workflow overview (what will happen once connected, no fake claims) */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-left pt-2">
            <div className="bg-zinc-950 border border-zinc-800 rounded-xl p-3.5 space-y-1.5">
              <div className="flex items-center gap-2 text-amber-400 text-xs font-semibold">
                <KeyRound className="w-3.5 h-3.5" />
                <span>Access Revocation</span>
              </div>
              <p className="text-[11px] text-zinc-400 leading-snug">
                Git gateway token and secrets access revoked at the proxy layer.
              </p>
            </div>

            <div className="bg-zinc-950 border border-zinc-800 rounded-xl p-3.5 space-y-1.5">
              <div className="flex items-center gap-2 text-cyan-400 text-xs font-semibold">
                <HardDrive className="w-3.5 h-3.5" />
                <span>Work Preserved</span>
              </div>
              <p className="text-[11px] text-zinc-400 leading-snug">
                Final git bundle snapshot written directly to creator-owned storage.
              </p>
            </div>

            <div className="bg-zinc-950 border border-zinc-800 rounded-xl p-3.5 space-y-1.5">
              <div className="flex items-center gap-2 text-rose-400 text-xs font-semibold">
                <Trash2 className="w-3.5 h-3.5" />
                <span>Teardown</span>
              </div>
              <p className="text-[11px] text-zinc-400 leading-snug">
                Sandboxed container and persistent volumes deleted cleanly.
              </p>
            </div>
          </div>

          <div className="pt-2">
            <button
              onClick={onClose}
              className="bg-zinc-800 hover:bg-zinc-700 text-zinc-200 text-xs font-medium px-5 py-2.5 rounded-xl border border-zinc-700 transition-colors"
            >
              Close
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
