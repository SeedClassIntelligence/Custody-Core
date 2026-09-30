import React, { useState } from 'react';
import {
  FolderPlus,
  ShieldAlert,
  Lock,
  Layers,
  Sparkles,
  Info,
  X,
  FileCode2,
  CheckCircle2,
  Loader2
} from 'lucide-react';
import { Project, Repository } from '../types/custody';

interface ClaimProjectModalProps {
  isOpen: boolean;
  onClose: () => void;
  onClaimProject: (data: {
    name: string;
    purpose: string;
    splitCore: boolean;
    coreRepoName?: string;
    appRepoName?: string;
  }) => Promise<void>;
  orgName: string;
}

export const ClaimProjectModal: React.FC<ClaimProjectModalProps> = ({
  isOpen,
  onClose,
  onClaimProject,
  orgName
}) => {
  const [name, setName] = useState('');
  const [purpose, setPurpose] = useState('');
  const [splitCore, setSplitCore] = useState(true);
  const [coreRepoName, setCoreRepoName] = useState('core');
  const [appRepoName, setAppRepoName] = useState('ui');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [currentStepText, setCurrentStepText] = useState('');

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim() || !purpose.trim()) return;

    setIsSubmitting(true);
    setCurrentStepText('Provisioning private repositories in your GitHub org...');

    try {
      await onClaimProject({
        name,
        purpose,
        splitCore,
        coreRepoName: splitCore ? coreRepoName : undefined,
        appRepoName
      });
      setIsSubmitting(false);
      onClose();
    } catch (err) {
      console.error(err);
      setIsSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="bg-zinc-900 border border-zinc-700/80 rounded-2xl max-w-xl w-full shadow-2xl overflow-hidden flex flex-col max-h-[92vh]">
        {/* Header */}
        <div className="px-6 py-5 border-b border-zinc-800 bg-zinc-950 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-indigo-600/20 border border-indigo-500/30 flex items-center justify-center text-indigo-400">
              <FolderPlus className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-lg font-semibold text-zinc-100">Claim a Project</h2>
              <p className="text-xs text-zinc-400">Create a locked code home registered in your own name.</p>
            </div>
          </div>
          {!isSubmitting && (
            <button
              onClick={onClose}
              className="text-zinc-400 hover:text-zinc-200 p-1.5 rounded-lg hover:bg-zinc-800 transition-colors"
            >
              <X className="w-5 h-5" />
            </button>
          )}
        </div>

        {/* Form Body */}
        <form onSubmit={handleSubmit} className="p-6 overflow-y-auto space-y-5 text-sm text-zinc-300 flex-1">
          {/* Project Name */}
          <div>
            <label className="block text-xs font-semibold text-zinc-200 mb-1">
              Project Name <span className="text-rose-400">*</span>
            </label>
            <input
              type="text"
              required
              disabled={isSubmitting}
              value={name}
              onChange={(e) => {
                setName(e.target.value);
                const slug = e.target.value.toLowerCase().replace(/[^a-z0-9]/g, '-');
                if (slug) {
                  setCoreRepoName(`${slug}-core`);
                  setAppRepoName(`${slug}-ui`);
                }
              }}
              placeholder="e.g. Aether Engine, Solstice Protocol"
              className="w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 text-xs text-zinc-100 focus:outline-none focus:border-indigo-500"
            />
          </div>

          {/* Purpose in Creator's Words */}
          <div>
            <div className="flex items-center justify-between mb-1">
              <label className="text-xs font-semibold text-zinc-200">
                Purpose (in your own words) <span className="text-rose-400">*</span>
              </label>
              <span className="text-[10px] text-zinc-400">Recorded for future Guardian AI review</span>
            </div>
            <textarea
              required
              disabled={isSubmitting}
              rows={3}
              value={purpose}
              onChange={(e) => setPurpose(e.target.value)}
              placeholder="Describe what this software does and your vision. This human intent is permanently stored in the hash-chain to protect your rights."
              className="w-full bg-zinc-950 border border-zinc-800 rounded-lg p-3 text-xs text-zinc-100 focus:outline-none focus:border-indigo-500 resize-none leading-relaxed"
            />
          </div>

          {/* Core Separation: Architectural Question */}
          <div className="bg-zinc-950 border border-zinc-800 rounded-xl p-4 space-y-3">
            <div className="flex items-start justify-between gap-3">
              <div className="flex items-center gap-2">
                <Layers className="w-4 h-4 text-amber-400 shrink-0" />
                <span className="font-semibold text-xs text-zinc-100">
                  Is there a part that should stay separate as a private Core?
                </span>
              </div>
              <input
                type="checkbox"
                id="splitCore"
                checked={splitCore}
                disabled={isSubmitting}
                onChange={(e) => setSplitCore(e.target.checked)}
                className="w-4 h-4 rounded text-indigo-600 bg-zinc-900 border-zinc-700 focus:ring-0 cursor-pointer mt-0.5"
              />
            </div>

            <p className="text-xs text-zinc-400 leading-relaxed">
              Access is scoped by repository, not by folder. By keeping your secret algorithmic core or proprietary DSP in a separate repository, you can safely open a door for a contractor without exposing your foundational intellectual property.
            </p>

            {splitCore ? (
              <div className="grid grid-cols-2 gap-3 pt-2 border-t border-zinc-800/80 text-xs">
                <div className="bg-zinc-900/90 border border-amber-900/30 p-2.5 rounded-lg space-y-1">
                  <div className="font-medium text-amber-400 flex items-center gap-1.5 text-[11px]">
                    <Lock className="w-3 h-3" />
                    Locked Core Repository
                  </div>
                  <div className="font-mono text-zinc-200 text-[11px] truncate">
                    {orgName}/{coreRepoName || 'core'}
                  </div>
                  <p className="text-[10px] text-zinc-400">Strictly quarantined. Never opened for general contracting.</p>
                </div>

                <div className="bg-zinc-900/90 border border-indigo-900/30 p-2.5 rounded-lg space-y-1">
                  <div className="font-medium text-indigo-400 flex items-center gap-1.5 text-[11px]">
                    <FileCode2 className="w-3 h-3" />
                    Workspace App Repository
                  </div>
                  <div className="font-mono text-zinc-200 text-[11px] truncate">
                    {orgName}/{appRepoName || 'ui'}
                  </div>
                  <p className="text-[10px] text-zinc-400">Scoped for doors, contractor tasks, and UI rendering.</p>
                </div>
              </div>
            ) : (
              <div className="text-[11px] text-zinc-400 bg-zinc-900 p-2 rounded border border-zinc-800">
                Single monolithic repository will be created: <code className="text-zinc-200">{orgName}/{appRepoName}</code>
              </div>
            )}
          </div>

          {/* Automated Platform Protections Notice */}
          <div className="bg-indigo-950/20 border border-indigo-900/40 rounded-xl p-3 flex items-start gap-2.5 text-xs text-indigo-300">
            <CheckCircle2 className="w-4 h-4 text-indigo-400 shrink-0 mt-0.5" />
            <div>
              <span className="font-medium text-indigo-200">What happens when you claim:</span>
              <p className="text-[11px] text-indigo-300/80 mt-0.5">
                The platform creates your private repositories in <strong>{orgName}</strong>, locks forking, applies branch protection rulesets against deletions/force-pushes, and registers the initial backup snapshot in your S3 mirror.
              </p>
            </div>
          </div>

          {/* Submission / Status */}
          {isSubmitting && (
            <div className="bg-zinc-950 border border-zinc-800 p-3 rounded-lg flex items-center gap-3 text-xs text-zinc-300">
              <Loader2 className="w-4 h-4 text-indigo-400 animate-spin shrink-0" />
              <span>{currentStepText}</span>
            </div>
          )}

          <div className="pt-2 flex justify-end gap-2">
            <button
              type="button"
              disabled={isSubmitting}
              onClick={onClose}
              className="px-4 py-2 text-xs font-medium text-zinc-400 hover:text-zinc-200 bg-zinc-900 hover:bg-zinc-800 rounded-lg transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isSubmitting || !name.trim() || !purpose.trim()}
              className="bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white font-medium px-5 py-2 rounded-lg text-xs flex items-center gap-2 transition-colors shadow-lg shadow-indigo-600/20"
            >
              <Lock className="w-3.5 h-3.5" />
              <span>Claim & Lock Project</span>
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
