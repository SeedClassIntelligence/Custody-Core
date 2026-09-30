import React from 'react';
import { FileCheck2, AlertCircle, X } from 'lucide-react';
import { Door } from '../types/custody';

interface DeveloperInviteModalProps {
  isOpen: boolean;
  onClose: () => void;
  door: Door;
  onCompleteOnboarding?: (data: {
    signingPublicKey: string;
    signatureName: string;
  }) => Promise<void>;
}

export const DeveloperInviteModal: React.FC<DeveloperInviteModalProps> = ({
  isOpen,
  onClose,
  door
}) => {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="bg-zinc-900 border border-zinc-700/80 rounded-2xl max-w-lg w-full shadow-2xl overflow-hidden flex flex-col">
        {/* Header */}
        <div className="px-6 py-5 border-b border-zinc-800 bg-zinc-950 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-amber-500/10 border border-amber-500/20 flex items-center justify-center text-amber-400">
              <FileCheck2 className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-lg font-semibold text-zinc-100">Agreement Signing</h2>
              <p className="text-xs text-zinc-400">Door #{door.id.substring(0, 8)}: {door.job_description}</p>
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
            Agreement signing will allow the developer to review and legally sign the contributor agreement before entering the workspace.
          </p>

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
