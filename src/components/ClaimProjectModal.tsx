import React, { useState } from 'react';
import { FolderPlus, X, Loader2, AlertCircle } from 'lucide-react';

interface ClaimProjectModalProps {
  isOpen: boolean;
  onClose: () => void;
  onClaimProject: (data: { name: string; purpose: string }) => Promise<void>;
}

export const ClaimProjectModal: React.FC<ClaimProjectModalProps> = ({ isOpen, onClose, onClaimProject }) => {
  const [name, setName] = useState('');
  const [purpose, setPurpose] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim() || !purpose.trim()) return;

    setIsSubmitting(true);
    setError(null);
    try {
      await onClaimProject({ name: name.trim(), purpose: purpose.trim() });
      setName('');
      setPurpose('');
      onClose();
    } catch (err: any) {
      setError(err.message || 'The project could not be recorded.');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="bg-zinc-900 border border-zinc-700/80 rounded-2xl max-w-xl w-full shadow-2xl overflow-hidden flex flex-col max-h-[92vh]">
        <div className="px-6 py-5 border-b border-zinc-800 bg-zinc-950 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-indigo-600/20 border border-indigo-500/30 flex items-center justify-center text-indigo-400">
              <FolderPlus className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-lg font-semibold text-zinc-100">Claim a Project</h2>
              <p className="text-xs text-zinc-400">Record your project and its purpose in the permanent event log.</p>
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

        <form onSubmit={handleSubmit} className="p-6 overflow-y-auto space-y-5 text-sm text-zinc-300 flex-1">
          <div>
            <label className="block text-xs font-semibold text-zinc-200 mb-1">
              Project Name <span className="text-rose-400">*</span>
            </label>
            <input
              type="text"
              required
              disabled={isSubmitting}
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="The name you call this project"
              className="w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 text-xs text-zinc-100 focus:outline-none focus:border-indigo-500"
            />
          </div>

          <div>
            <label className="block text-xs font-semibold text-zinc-200 mb-1">
              Purpose (in your own words) <span className="text-rose-400">*</span>
            </label>
            <textarea
              required
              disabled={isSubmitting}
              rows={3}
              value={purpose}
              onChange={(e) => setPurpose(e.target.value)}
              placeholder="What this software does and why you are building it."
              className="w-full bg-zinc-950 border border-zinc-800 rounded-lg p-3 text-xs text-zinc-100 focus:outline-none focus:border-indigo-500 resize-none leading-relaxed"
            />
          </div>

          <div className="bg-amber-950/30 border border-amber-800/40 rounded-xl p-3 flex items-start gap-2.5 text-xs text-amber-300">
            <AlertCircle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
            <p className="text-[11px] text-amber-300/90">
              <span className="font-semibold text-amber-200">Not connected yet:</span> creating new GitHub repositories. After claiming, add your existing repositories from GitHub on the project page; each one is locked when added.
              For now, claiming records your project name and purpose in the event log, and nothing else.
            </p>
          </div>

          {error && (
            <div className="bg-rose-950/50 border border-rose-800 p-3 rounded-lg text-xs text-rose-200">
              {error}
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
              className="bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white font-medium px-5 py-2 rounded-lg text-xs flex items-center gap-2 transition-colors"
            >
              {isSubmitting && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
              <span>{isSubmitting ? 'Recording...' : 'Record Project'}</span>
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
