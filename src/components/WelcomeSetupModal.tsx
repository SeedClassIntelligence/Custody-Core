import React, { useState } from 'react';
import { Github, HardDrive, ShieldCheck, AlertCircle, X, Sparkles } from 'lucide-react';

interface WelcomeSetupModalProps {
  isOpen: boolean;
  onClose: () => void;
}

const STEPS = [
  {
    id: 1,
    label: '1. Sign in & MFA',
    icon: ShieldCheck,
    title: 'Sign in with required multifactor authentication',
    body: 'You will sign in and confirm an authenticator-app code before you can see any project.'
  },
  {
    id: 2,
    label: '2. Code Home',
    icon: Github,
    title: 'Connect your GitHub organization',
    body: 'Your code will live in a private GitHub organization you own, locked down by the platform so developers never touch it.'
  },
  {
    id: 3,
    label: '3. Backup Mirror',
    icon: HardDrive,
    title: 'Connect your backup storage',
    body: 'Snapshots of your code will be copied into storage that you own, so your archive survives even if GitHub does not.'
  }
];

export const WelcomeSetupModal: React.FC<WelcomeSetupModalProps> = ({ isOpen, onClose }) => {
  const [activeStep, setActiveStep] = useState<number>(1);
  if (!isOpen) return null;

  const step = STEPS.find((s) => s.id === activeStep)!;
  const StepIcon = step.icon;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="bg-zinc-900 border border-zinc-700/80 rounded-2xl max-w-2xl w-full shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
        <div className="px-6 py-5 border-b border-zinc-800 bg-zinc-950 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-indigo-600/20 border border-indigo-500/30 flex items-center justify-center text-indigo-400">
              <Sparkles className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-lg font-semibold text-zinc-100">Setup Guide</h2>
              <p className="text-xs text-zinc-400">The three things you will connect. None of them are connected yet.</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-zinc-400 hover:text-zinc-200 p-1.5 rounded-lg hover:bg-zinc-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="grid grid-cols-3 border-b border-zinc-800 text-xs">
          {STEPS.map((s) => (
            <button
              key={s.id}
              onClick={() => setActiveStep(s.id)}
              className={`py-3 px-4 font-medium border-b-2 transition-all ${
                activeStep === s.id
                  ? 'border-indigo-500 text-indigo-400 bg-zinc-800/40'
                  : 'border-transparent text-zinc-400 hover:text-zinc-200'
              }`}
            >
              {s.label}
            </button>
          ))}
        </div>

        <div className="p-8 space-y-6 text-center">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-amber-950/60 border border-amber-800/80 text-amber-300 text-xs font-mono font-medium">
            <AlertCircle className="w-3.5 h-3.5 text-amber-400" />
            <span>Not connected yet</span>
          </div>
          <div className="flex items-center justify-center gap-2 text-zinc-100">
            <StepIcon className="w-5 h-5 text-indigo-400" />
            <h3 className="font-semibold">{step.title}</h3>
          </div>
          <p className="text-sm text-zinc-300 leading-relaxed max-w-md mx-auto">{step.body}</p>
        </div>

        <div className="px-6 py-4 border-t border-zinc-800 bg-zinc-950 flex justify-end text-xs">
          <button onClick={onClose} className="text-zinc-300 hover:text-white font-medium">
            Close Guide
          </button>
        </div>
      </div>
    </div>
  );
};
