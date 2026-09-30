import React, { useState } from 'react';
import {
  ShieldCheck,
  Github,
  HardDrive,
  CheckCircle2,
  Lock,
  ArrowRight,
  ExternalLink,
  Info,
  X,
  Sparkles
} from 'lucide-react';
import { Connection } from '../types/custody';

interface WelcomeSetupModalProps {
  isOpen: boolean;
  onClose: () => void;
  connections: Connection[];
  onConnectGitHub: (orgName: string) => void;
  onConnectStorage: (kind: 'storage_s3' | 'storage_drive', destination: string) => void;
}

export const WelcomeSetupModal: React.FC<WelcomeSetupModalProps> = ({
  isOpen,
  onClose,
  connections,
  onConnectGitHub,
  onConnectStorage
}) => {
  const [activeStep, setActiveStep] = useState<number>(1);
  const [githubOrgInput, setGithubOrgInput] = useState('darnell-ventures-code');
  const [storageInput, setStorageInput] = useState('s3://darnell-custody-vault-us-east-1');
  const [isProcessing, setIsProcessing] = useState(false);

  if (!isOpen) return null;

  const ghConn = connections.find(c => c.kind === 'github');
  const s3Conn = connections.find(c => c.kind === 'storage_s3' || c.kind === 'storage_drive');

  const handleGitHubConnect = () => {
    setIsProcessing(true);
    setTimeout(() => {
      onConnectGitHub(githubOrgInput);
      setIsProcessing(false);
      setActiveStep(3);
    }, 600);
  };

  const handleStorageConnect = () => {
    setIsProcessing(true);
    setTimeout(() => {
      onConnectStorage('storage_s3', storageInput);
      setIsProcessing(false);
      onClose();
    }, 600);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="bg-zinc-900 border border-zinc-700/80 rounded-2xl max-w-2xl w-full shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
        {/* Header */}
        <div className="px-6 py-5 border-b border-zinc-800 bg-zinc-950 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-indigo-600/20 border border-indigo-500/30 flex items-center justify-center text-indigo-400">
              <Sparkles className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-lg font-semibold text-zinc-100">Welcome to Custody Core</h2>
              <p className="text-xs text-zinc-400">Set up your code home in 3 simple steps. You own everything.</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-zinc-400 hover:text-zinc-200 p-1.5 rounded-lg hover:bg-zinc-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Stepper Navigation */}
        <div className="grid grid-cols-3 border-b border-zinc-800 text-xs">
          <button
            onClick={() => setActiveStep(1)}
            className={`py-3 px-4 font-medium flex items-center justify-center gap-2 border-b-2 transition-all ${
              activeStep === 1
                ? 'border-indigo-500 text-indigo-400 bg-zinc-800/40'
                : 'border-transparent text-zinc-400 hover:text-zinc-200'
            }`}
          >
            <span className="w-5 h-5 rounded-full bg-emerald-500/20 text-emerald-400 border border-emerald-500/40 flex items-center justify-center text-[10px] font-bold">
              ✓
            </span>
            <span>1. Account MFA</span>
          </button>

          <button
            onClick={() => setActiveStep(2)}
            className={`py-3 px-4 font-medium flex items-center justify-center gap-2 border-b-2 transition-all ${
              activeStep === 2
                ? 'border-indigo-500 text-indigo-400 bg-zinc-800/40'
                : 'border-transparent text-zinc-400 hover:text-zinc-200'
            }`}
          >
            <span className={`w-5 h-5 rounded-full flex items-center justify-center text-[10px] font-bold ${
              ghConn?.status === 'locked' || ghConn?.status === 'connected'
                ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40'
                : 'bg-zinc-800 text-zinc-400'
            }`}>
              {ghConn?.status === 'locked' ? '✓' : '2'}
            </span>
            <span>2. Code Home</span>
          </button>

          <button
            onClick={() => setActiveStep(3)}
            className={`py-3 px-4 font-medium flex items-center justify-center gap-2 border-b-2 transition-all ${
              activeStep === 3
                ? 'border-indigo-500 text-indigo-400 bg-zinc-800/40'
                : 'border-transparent text-zinc-400 hover:text-zinc-200'
            }`}
          >
            <span className={`w-5 h-5 rounded-full flex items-center justify-center text-[10px] font-bold ${
              s3Conn?.status === 'connected'
                ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40'
                : 'bg-zinc-800 text-zinc-400'
            }`}>
              {s3Conn?.status === 'connected' ? '✓' : '3'}
            </span>
            <span>3. Backup Mirror</span>
          </button>
        </div>

        {/* Content Body */}
        <div className="p-6 overflow-y-auto space-y-6 flex-1 text-sm text-zinc-300">
          {activeStep === 1 && (
            <div className="space-y-4">
              <div className="flex items-start gap-3 bg-emerald-950/30 border border-emerald-800/40 rounded-xl p-4">
                <CheckCircle2 className="w-5 h-5 text-emerald-400 mt-0.5 shrink-0" />
                <div>
                  <h4 className="font-semibold text-emerald-200">Account Security Active</h4>
                  <p className="text-xs text-emerald-300/80 mt-1">
                    Your creator account is bound to your hardware passkey (WebAuthn / FIDO2) and Ory Kratos multifactor session.
                    Every sensitive action—claiming a project, opening a door, or accepting work—requires this hardware cryptographic verification.
                  </p>
                </div>
              </div>

              <div className="border border-zinc-800 bg-zinc-950 p-4 rounded-xl space-y-3">
                <div className="text-xs font-mono uppercase text-zinc-400 tracking-wider">Identity Details</div>
                <div className="grid grid-cols-2 gap-3 text-xs">
                  <div>
                    <span className="text-zinc-400">Identity ID:</span>
                    <p className="font-mono text-zinc-200">kratos_usr_darnell_jernigan</p>
                  </div>
                  <div>
                    <span className="text-zinc-400">Seed Signature Identity:</span>
                    <p className="font-mono text-emerald-400 font-semibold">ssc_8921a4f0b2</p>
                  </div>
                  <div>
                    <span className="text-zinc-400">Passkey Type:</span>
                    <p className="text-zinc-200">Apple TouchID / YubiKey Hardware Token</p>
                  </div>
                  <div>
                    <span className="text-zinc-400">MFA Policy:</span>
                    <p className="text-zinc-200">Strict Step-Up (Required everywhere)</p>
                  </div>
                </div>
              </div>

              <div className="pt-2 flex justify-end">
                <button
                  onClick={() => setActiveStep(2)}
                  className="bg-indigo-600 hover:bg-indigo-500 text-white font-medium px-4 py-2 rounded-lg flex items-center gap-2 text-xs transition-colors"
                >
                  <span>Continue to Code Home</span>
                  <ArrowRight className="w-4 h-4" />
                </button>
              </div>
            </div>
          )}

          {activeStep === 2 && (
            <div className="space-y-4">
              <div className="bg-zinc-950 border border-zinc-800 p-4 rounded-xl space-y-3">
                <div className="flex items-center gap-2 text-indigo-400">
                  <Github className="w-5 h-5" />
                  <h3 className="font-semibold text-zinc-100">Connect Your Code Home</h3>
                </div>
                <p className="text-xs text-zinc-300 leading-relaxed">
                  Your code lives in a <strong>free private GitHub organization that you own</strong>.
                  Developers will never touch this organization or get access to it.
                  Instead, the platform's GitHub App manages repositories in your name and locks them down completely.
                </p>

                <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-3 text-xs space-y-2 text-zinc-400">
                  <div className="font-semibold text-zinc-200 flex items-center gap-1.5">
                    <Lock className="w-3.5 h-3.5 text-amber-400" />
                    Automated Platform Protections Applied:
                  </div>
                  <ul className="list-disc pl-5 space-y-1 text-[11px]">
                    <li>Base member permissions set to <strong>none</strong></li>
                    <li>Members cannot create new repositories</li>
                    <li>Forking of private repositories is strictly <strong>disabled</strong></li>
                    <li>Default branch locked against deletions and force-pushes</li>
                    <li>Only the platform GitHub App can bypass branch protections when you accept work</li>
                  </ul>
                </div>
              </div>

              <div>
                <label className="block text-xs font-medium text-zinc-300 mb-1">
                  Your GitHub Organization Name
                </label>
                <div className="flex gap-2">
                  <input
                    type="text"
                    value={githubOrgInput}
                    onChange={(e) => setGithubOrgInput(e.target.value)}
                    className="flex-1 bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 text-xs text-zinc-100 focus:outline-none focus:border-indigo-500 font-mono"
                    placeholder="e.g. my-studio-code"
                  />
                  <button
                    onClick={handleGitHubConnect}
                    disabled={isProcessing}
                    className="bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white font-medium px-4 py-2 rounded-lg text-xs flex items-center gap-1.5 transition-colors"
                  >
                    {isProcessing ? 'Locking Org Defaults...' : 'Connect & Lock Down'}
                  </button>
                </div>
                <p className="text-[11px] text-zinc-400 mt-1 flex items-center gap-1">
                  <Info className="w-3 h-3" />
                  Credentials are encrypted in Infisical; no raw tokens are saved in the database.
                </p>
              </div>

              {ghConn?.status === 'locked' && (
                <div className="p-3 bg-emerald-950/40 border border-emerald-800/40 rounded-lg flex items-center justify-between text-xs text-emerald-300">
                  <div className="flex items-center gap-2">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                    <span>Organization <strong>{ghConn.external_account}</strong> connected and locked.</span>
                  </div>
                  <button
                    onClick={() => setActiveStep(3)}
                    className="text-white bg-emerald-700/80 hover:bg-emerald-600 px-3 py-1 rounded text-[11px] font-medium"
                  >
                    Next Step
                  </button>
                </div>
              )}
            </div>
          )}

          {activeStep === 3 && (
            <div className="space-y-4">
              <div className="bg-zinc-950 border border-zinc-800 p-4 rounded-xl space-y-3">
                <div className="flex items-center gap-2 text-cyan-400">
                  <HardDrive className="w-5 h-5" />
                  <h3 className="font-semibold text-zinc-100">Connect Your Backup Storage</h3>
                </div>
                <p className="text-xs text-zinc-300 leading-relaxed">
                  <strong>You own the mirror.</strong> Every commit pushed by a developer is bundled and copied
                  instantly into your private cloud storage bucket (AWS S3-compatible or Google Drive) with full versioning enabled.
                  Even if GitHub is deleted or goes offline, your archive is always safe in your hands.
                </p>

                <div className="grid grid-cols-2 gap-2 text-xs">
                  <div className="p-3 bg-zinc-900 border border-zinc-800 rounded-lg space-y-1">
                    <div className="font-semibold text-zinc-200">S3-Compatible Bucket</div>
                    <p className="text-[11px] text-zinc-400">
                      Direct object storage with hardware versioning enabled so no write can ever overwrite prior work.
                    </p>
                  </div>
                  <div className="p-3 bg-zinc-900 border border-zinc-800 rounded-lg space-y-1">
                    <div className="font-semibold text-zinc-200">Google Drive</div>
                    <p className="text-[11px] text-zinc-400">
                      Scoped strictly to <code className="text-zinc-300">drive.file</code> so the platform only sees files it created.
                    </p>
                  </div>
                </div>
              </div>

              <div>
                <label className="block text-xs font-medium text-zinc-300 mb-1">
                  Storage Bucket URI or Google Drive Path
                </label>
                <div className="flex gap-2">
                  <input
                    type="text"
                    value={storageInput}
                    onChange={(e) => setStorageInput(e.target.value)}
                    className="flex-1 bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 text-xs text-zinc-100 focus:outline-none focus:border-cyan-500 font-mono"
                    placeholder="s3://my-custody-vault"
                  />
                  <button
                    onClick={handleStorageConnect}
                    disabled={isProcessing}
                    className="bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white font-medium px-4 py-2 rounded-lg text-xs flex items-center gap-1.5 transition-colors"
                  >
                    {isProcessing ? 'Verifying Bucket...' : 'Save & Enable Mirror'}
                  </button>
                </div>
                <p className="text-[11px] text-zinc-400 mt-1">
                  Versioning must be enabled on your bucket so accidental deletes can never remove a snapshot.
                </p>
              </div>

              {s3Conn?.status === 'connected' && (
                <div className="p-3 bg-emerald-950/40 border border-emerald-800/40 rounded-lg flex items-center justify-between text-xs text-emerald-300">
                  <div className="flex items-center gap-2">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                    <span>Backup destination <strong>{s3Conn.external_account}</strong> connected.</span>
                  </div>
                  <button
                    onClick={onClose}
                    className="text-white bg-indigo-600 hover:bg-indigo-500 px-3 py-1 rounded text-[11px] font-medium"
                  >
                    Complete Setup
                  </button>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-4 border-t border-zinc-800 bg-zinc-950 flex items-center justify-between text-xs text-zinc-400">
          <div className="flex items-center gap-2">
            <Lock className="w-3.5 h-3.5 text-zinc-400" />
            <span>Encrypted with Infisical Universal Auth & Ory Kratos</span>
          </div>
          <button
            onClick={onClose}
            className="text-zinc-300 hover:text-white font-medium"
          >
            Close Guide
          </button>
        </div>
      </div>
    </div>
  );
};
