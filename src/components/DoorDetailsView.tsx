import React, { useState } from 'react';
import {
  DoorClosed,
  DoorOpen,
  Clock,
  User,
  ShieldCheck,
  CheckCircle2,
  XCircle,
  GitPullRequest,
  AlertTriangle,
  ChevronDown,
  ChevronUp,
  FileCheck2,
  Calendar,
  Terminal,
  ExternalLink,
  Flame,
  ArrowRight,
  Loader2
} from 'lucide-react';
import { Door, Project, CustodyEvent } from '../types/custody';

interface DoorDetailsViewProps {
  door: Door;
  project: Project;
  events: CustodyEvent[];
  onAcceptWork: (doorId: string) => Promise<void>;
  onExtendDoor: (doorId: string, additionalDays: number) => Promise<void>;
  onCloseDoor: (doorId: string) => Promise<void>;
  onSwitchToWorkspace: (doorId: string) => void;
  onOpenInviteModal?: (door: Door) => void;
}

export const DoorDetailsView: React.FC<DoorDetailsViewProps> = ({
  door,
  project,
  events,
  onAcceptWork,
  onExtendDoor,
  onCloseDoor,
  onSwitchToWorkspace,
  onOpenInviteModal
}) => {
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [isAccepting, setIsAccepting] = useState(false);
  const [isClosing, setIsClosing] = useState(false);
  const [isExtending, setIsExtending] = useState(false);

  // Filter events relevant to this door
  const doorEvents = events.filter(e =>
    e.subject_id === door.id ||
    e.payload?.door_id === door.id ||
    (e.action.startsWith('git.') && e.payload?.door_id === door.id)
  );

  // Time calculation
  const expiresDate = new Date(door.expires_at);
  const nowDate = new Date();
  const diffHours = Math.max(0, Math.round((expiresDate.getTime() - nowDate.getTime()) / (1000 * 3600)));
  const diffDays = Math.floor(diffHours / 24);
  const remHours = diffHours % 24;

  const isOpen = door.status === 'open';
  const isAwaitingSig = door.status === 'awaiting_signature';
  const isClosed = door.status === 'closed';

  const handleAccept = async () => {
    setIsAccepting(true);
    try {
      await onAcceptWork(door.id);
    } finally {
      setIsAccepting(false);
    }
  };

  const handleClose = async () => {
    setIsClosing(true);
    try {
      await onCloseDoor(door.id);
    } finally {
      setIsClosing(false);
    }
  };

  const handleExtend = async (days: number) => {
    setIsExtending(true);
    try {
      await onExtendDoor(door.id, days);
    } finally {
      setIsExtending(false);
    }
  };

  return (
    <div className="bg-zinc-950 border border-zinc-800 rounded-2xl p-6 space-y-6">
      {/* Top Banner: Status & Plain English Summary */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-zinc-800/80 pb-5">
        <div>
          <div className="flex items-center gap-2.5">
            <span className={`w-3 h-3 rounded-full ${
              isOpen ? 'bg-emerald-400 animate-pulse' :
              isAwaitingSig ? 'bg-amber-400' : 'bg-zinc-600'
            }`} />
            <h3 className="text-lg font-bold text-zinc-100">{door.job_description}</h3>
            <span className={`text-xs px-2 py-0.5 rounded-full font-medium capitalize ${
              isOpen ? 'bg-emerald-950 text-emerald-300 border border-emerald-800' :
              isAwaitingSig ? 'bg-amber-950 text-amber-300 border border-amber-800' :
              'bg-zinc-900 text-zinc-400 border border-zinc-700'
            }`}>
              {door.status.replace('_', ' ')}
            </span>
          </div>
          <p className="text-xs text-zinc-400 mt-1">
            Door access for <strong className="text-zinc-200">{door.developer_email}</strong> • Agreement: <span className="capitalize text-indigo-400">{door.rights_type}</span>
          </p>
        </div>

        {/* Action Controls */}
        <div className="flex flex-wrap items-center gap-2">
          {isAwaitingSig && onOpenInviteModal && (
            <button
              onClick={() => onOpenInviteModal(door)}
              className="bg-amber-600 hover:bg-amber-500 text-white text-xs font-medium px-3.5 py-2 rounded-lg flex items-center gap-1.5 transition-colors"
            >
              <FileCheck2 className="w-3.5 h-3.5" />
              <span>Simulate Developer Sign</span>
            </button>
          )}

          {isOpen && (
            <>
              <button
                onClick={() => onSwitchToWorkspace(door.id)}
                className="bg-indigo-600/90 hover:bg-indigo-500 text-white text-xs font-medium px-3.5 py-2 rounded-lg flex items-center gap-1.5 transition-colors shadow-sm"
              >
                <Terminal className="w-3.5 h-3.5" />
                <span>Open Developer Workspace</span>
              </button>

              <button
                onClick={handleAccept}
                disabled={isAccepting}
                className="bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white text-xs font-medium px-3.5 py-2 rounded-lg flex items-center gap-1.5 transition-colors shadow-sm"
                title="Opens PR from door branch and merges to default branch"
              >
                {isAccepting ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <GitPullRequest className="w-3.5 h-3.5" />}
                <span>Accept this work</span>
              </button>

              <button
                onClick={() => handleExtend(7)}
                disabled={isExtending}
                className="bg-zinc-800 hover:bg-zinc-700 text-zinc-200 border border-zinc-700 text-xs font-medium px-3 py-2 rounded-lg flex items-center gap-1.5 transition-colors"
                title="Add 7 days to the expiration date"
              >
                <Calendar className="w-3.5 h-3.5 text-zinc-400" />
                <span>+7 Days</span>
              </button>

              <button
                onClick={handleClose}
                disabled={isClosing}
                className="bg-rose-950 hover:bg-rose-900 border border-rose-800 text-rose-200 text-xs font-medium px-3.5 py-2 rounded-lg flex items-center gap-1.5 transition-colors"
                title="Close the door"
              >
                {isClosing ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <DoorClosed className="w-3.5 h-3.5" />}
                <span>Close the door</span>
              </button>
            </>
          )}
        </div>
      </div>

      {/* Grid of Door Metrics in Plain Language */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        {/* Metric 1: Time Left */}
        <div className="bg-zinc-900/80 border border-zinc-800/80 rounded-xl p-4 space-y-1">
          <div className="flex items-center gap-2 text-zinc-400 text-xs font-medium">
            <Clock className="w-3.5 h-3.5 text-indigo-400" />
            <span>Time Left</span>
          </div>
          {isOpen ? (
            <div className="text-xl font-bold text-zinc-100">
              {diffDays > 0 ? `${diffDays} days, ${remHours} hrs` : `${diffHours} hours remaining`}
            </div>
          ) : (
            <div className="text-xl font-bold text-zinc-400">
              {isClosed ? 'Door Closed' : 'Awaiting Developer'}
            </div>
          )}
          <span className="text-[11px] text-zinc-500 block">
            {isOpen ? `Closes automatically on ${expiresDate.toLocaleDateString()}` : 'No active timer'}
          </span>
        </div>

        {/* Metric 2: Developer & Security */}
        <div className="bg-zinc-900/80 border border-zinc-800/80 rounded-xl p-4 space-y-1">
          <div className="flex items-center gap-2 text-zinc-400 text-xs font-medium">
            <User className="w-3.5 h-3.5 text-amber-400" />
            <span>Developer Account</span>
          </div>
          <div className="text-sm font-semibold text-zinc-200 truncate">
            {door.developer_email}
          </div>
          <div className="flex items-center gap-1.5 text-[11px] text-emerald-400">
            <ShieldCheck className="w-3.5 h-3.5" />
            <span>MFA & Signing Key Registered</span>
          </div>
        </div>

        {/* Metric 3: Custody Isolation */}
        <div className="bg-zinc-900/80 border border-zinc-800/80 rounded-xl p-4 space-y-1">
          <div className="flex items-center gap-2 text-zinc-400 text-xs font-medium">
            <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
            <span>Custody Isolation</span>
          </div>
          <div className="text-sm font-semibold text-emerald-300">
            Git Gateway Proxy Active
          </div>
          <span className="text-[11px] text-zinc-500 block">
            0 direct GitHub credentials issued
          </span>
        </div>
      </div>

      {/* Plain Language Live Activity Feed */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <h4 className="text-xs font-semibold uppercase tracking-wider text-zinc-400">
            Live Activity Feed (Plain Language)
          </h4>
          <span className="text-[11px] text-zinc-500">From append-only tamper-evident log</span>
        </div>

        <div className="border border-zinc-800 rounded-xl divide-y divide-zinc-800/60 overflow-hidden bg-zinc-900/40">
          {doorEvents.length === 0 ? (
            <div className="p-4 text-xs text-zinc-500 text-center">No activity recorded for this door yet.</div>
          ) : (
            doorEvents.map((evt) => {
              // Format plain language message based on event
              let plainTitle: string = evt.action;
              let plainDesc = '';
              let badgeColor = 'bg-zinc-800 text-zinc-300';

              if (evt.action === 'door.created') {
                plainTitle = 'Door Created';
                plainDesc = `Invited ${evt.payload?.developer_email || 'developer'} with ${evt.payload?.rights_type || 'contribute'} agreement.`;
                badgeColor = 'bg-indigo-950 text-indigo-300 border border-indigo-800';
              } else if (evt.action === 'agreement.signed') {
                plainTitle = 'Agreement Signed by Developer';
                plainDesc = 'Developer completed passkey authentication and signed the agreement. PDF stored in creator backup storage.';
                badgeColor = 'bg-emerald-950 text-emerald-300 border border-emerald-800';
              } else if (evt.action === 'door.opened') {
                plainTitle = 'Door Opened & Workspace Ready';
                plainDesc = 'Coder cloud workspace provisioned with remote pointing to Git Gateway. Egress rules active.';
                badgeColor = 'bg-emerald-950 text-emerald-300 border border-emerald-800';
              } else if (evt.action === 'git.fetch') {
                plainTitle = 'Developer Checked Out Code';
                plainDesc = `Developer loaded project files into cloud workspace through gateway proxy.`;
              } else if (evt.action === 'git.push') {
                plainTitle = 'Developer Pushed New Work';
                plainDesc = `Pushed commits: "${evt.payload?.commit_message || 'work updates'}". Secret scanner passed. Mirrored to S3.`;
                badgeColor = 'bg-indigo-950 text-indigo-300 border border-indigo-800';
              } else if (evt.action === 'git.push_rejected') {
                plainTitle = 'Push Rejected by Secret Scanner';
                plainDesc = `Attempted push was blocked before touching GitHub because high-entropy API keys were detected.`;
                badgeColor = 'bg-rose-950 text-rose-300 border border-rose-800';
              } else if (evt.action === 'door.work_accepted') {
                plainTitle = 'Work Accepted & Merged';
                plainDesc = `Platform opened a pull request from the door branch and merged it into the main repository.`;
                badgeColor = 'bg-emerald-950 text-emerald-300 border border-emerald-800';
              } else if (evt.action === 'door.closed') {
                plainTitle = 'Door Closed & Access Revoked';
                plainDesc = `Credentials revoked at the Git Gateway, final mirror written, workspace deleted.`;
                badgeColor = 'bg-rose-950 text-rose-300 border border-rose-800';
              }

              return (
                <div key={evt.seq} className="p-3.5 flex items-start justify-between gap-3 text-xs">
                  <div className="space-y-0.5">
                    <div className="flex items-center gap-2">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-medium ${badgeColor}`}>
                        {plainTitle}
                      </span>
                      <span className="text-[11px] text-zinc-500 font-mono">
                        {new Date(evt.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                      </span>
                    </div>
                    <p className="text-zinc-300 text-xs leading-relaxed pt-1">{plainDesc}</p>
                  </div>
                  <span className="text-[10px] font-mono text-zinc-500 shrink-0">
                    Event #{evt.seq}
                  </span>
                </div>
              );
            })
          )}
        </div>
      </div>

      {/* Advanced Details Toggle (Strict Requirement from Spec) */}
      <div className="pt-2 border-t border-zinc-800/80">
        <button
          onClick={() => setShowAdvanced(!showAdvanced)}
          className="flex items-center gap-1.5 text-xs text-zinc-400 hover:text-zinc-200 transition-colors"
        >
          {showAdvanced ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
          <span>{showAdvanced ? 'Hide Advanced Details' : 'Show Advanced Details (Branches, Tokens, Namespaces)'}</span>
        </button>

        {showAdvanced && (
          <div className="mt-3 p-4 bg-zinc-900/90 border border-zinc-800 rounded-xl space-y-3 text-xs font-mono text-zinc-300 animate-in fade-in duration-150">
            <div className="text-[10px] uppercase text-zinc-500 font-bold tracking-wider">Internal Technical Parameters</div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-[11px]">
              <div>
                <span className="text-zinc-500 block">Door Branch Prefix:</span>
                <span className="text-indigo-400 font-semibold">{door.branch_prefix}/*</span>
              </div>
              <div>
                <span className="text-zinc-500 block">Gateway Authorize Endpoint:</span>
                <span className="text-zinc-300">POST /internal/gateway/authorize</span>
              </div>
              <div>
                <span className="text-zinc-500 block">Kubernetes Namespace:</span>
                <span className="text-zinc-300">door-ns-{door.id}</span>
              </div>
              <div>
                <span className="text-zinc-500 block">Agreement Document Ref:</span>
                <span className="text-zinc-300">{door.agreement_id || 'tmpl_contribute_v1'}</span>
              </div>
              <div>
                <span className="text-zinc-500 block">Signature Fingerprint:</span>
                <span className="text-emerald-400 truncate block">{door.agreement_signature_hash || 'SHA256:d6b9f1e8a2c4...'}</span>
              </div>
              <div>
                <span className="text-zinc-500 block">Infisical Machine Identity:</span>
                <span className="text-zinc-300">infisical://auth/door-{door.id.substring(0, 8)}</span>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
