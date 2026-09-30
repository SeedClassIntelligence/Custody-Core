import React, { useState } from 'react';
import {
  FileCheck2,
  CheckCircle2,
  AlertTriangle,
  Terminal,
  ChevronDown,
  ChevronUp,
  ShieldCheck,
  BookOpen
} from 'lucide-react';
import { AcceptanceTestResult } from '../types/custody';

const SPEC_SCENARIOS: AcceptanceTestResult[] = [
  {
    id: 1,
    name: 'Zero-GitHub Creator Lifecycle',
    description: 'A creator completes setup, claims a project, and opens a door without visiting GitHub after the one-time connection.',
    status: 'idle',
    log: [
      'Spec Requirement: Zero visits to github.com after one-time app connection.',
      'Verification path: Creator runs entirely through Custody Core dashboard and Git Gateway.'
    ]
  },
  {
    id: 2,
    name: 'GitHub Direct Access Prohibition',
    description: 'A developer cannot clone, fetch or push using GitHub directly; they hold no GitHub access or credentials to the organization.',
    status: 'idle',
    log: [
      'Spec Requirement: Developers never receive direct access to GitHub repository.',
      'Verification path: Git remote points to platform-managed Git Gateway.'
    ]
  },
  {
    id: 3,
    name: 'Branch Prefix Policy Enforcement',
    description: 'A push to any branch outside door/<door-id>/* is strictly refused by the platform Git Gateway.',
    status: 'idle',
    log: [
      'Spec Requirement: Pre-receive hook verifies ref matches authorized door prefix.',
      'Verification path: Tested against unapproved refs and main.'
    ]
  },
  {
    id: 4,
    name: 'Pre-Receive Secret Scanner (Gitleaks)',
    description: 'A push containing a test API key is refused by the pre-receive hook before it can reach GitHub.',
    status: 'idle',
    log: [
      'Spec Requirement: Gitleaks AST pre-receive scan halts push on entropy match.',
      'Verification path: Emits git.push_rejected event into project hash chain.'
    ]
  },
  {
    id: 5,
    name: 'Workspace Network Egress Sandbox (Cilium)',
    description: 'From the workspace, git push to any outside server fails, and outbound web requests to unapproved domains fail.',
    status: 'idle',
    log: [
      'Spec Requirement: Strict Cilium egress network policies on Coder Kubernetes pod.'
    ]
  },
  {
    id: 6,
    name: 'Instant Gateway Revocation (< 5s)',
    description: 'Within 5 seconds of Close the door, the workspace\'s next git request is refused with 403 Forbidden.',
    status: 'idle',
    log: [
      'Spec Requirement: Immediate credential revocation and door state transition in gateway cache.'
    ]
  },
  {
    id: 7,
    name: 'Zero-Residual Workspace Teardown & Preservation',
    description: 'Closing the door deletes the Kubernetes namespace, wipes volumes, revokes Infisical identities, and takes a final mirror snapshot.',
    status: 'idle',
    log: [
      'Spec Requirement: Ephemeral workspace fully destroyed; git bundle written to creator backup.'
    ]
  },
  {
    id: 8,
    name: 'Door Expiration Automation (Temporal)',
    description: 'When expires_at is reached, the door closes automatically without creator intervention.',
    status: 'idle',
    log: [
      'Spec Requirement: Temporal workflow timer triggers automated door closure.'
    ]
  },
  {
    id: 9,
    name: 'Temporal Workflow Rollback Guarantee',
    description: 'If a step in Open Door or Close Door fails mid-execution, compensating activities cleanly roll back partial state.',
    status: 'idle',
    log: [
      'Spec Requirement: Sagas guarantee zero orphaned machine identities or credentials.'
    ]
  },
  {
    id: 10,
    name: 'Append-Only Database Rule & Tamper-Evident Hash Chain',
    description: 'Direct SQL UPDATE or DELETE is rejected by DB trigger, and any forced data modification is caught by "Check this record".',
    status: 'idle',
    log: [
      'Spec Requirement: PostgreSQL BEFORE UPDATE OR DELETE trigger on event table.',
      'Verification path: Tested with real SQL in tests/schema_and_tenant.test.ts and tests/hashchain.test.ts.'
    ]
  },
  {
    id: 11,
    name: 'GitHub Ruleset Branch Protection (Non-App Reject)',
    description: 'Deleting the default branch or force-pushing to it through the GitHub API with a non-app identity fails.',
    status: 'idle',
    log: [
      'Spec Requirement: Repository locked ruleset configured upon claiming project.'
    ]
  },
  {
    id: 12,
    name: 'Export Everything Manifest & Bundle Integrity',
    description: 'Export everything produces an archive whose manifest hashes match every file, and a repository restores from its bundle with git clone.',
    status: 'idle',
    log: [
      'Spec Requirement: SHA-256 integrity manifest and git bundle creation.'
    ]
  },
  {
    id: 13,
    name: 'Multi-Tenant Isolation Verification',
    description: 'A second creator\'s account cannot read or change the first creator\'s projects, doors or events.',
    status: 'idle',
    log: [
      'Spec Requirement: Row-level tenant scoping enforced across all database queries.',
      'Verification path: Tested in tests/schema_and_tenant.test.ts.'
    ]
  }
];

export const AcceptanceSuiteView: React.FC = () => {
  const [expandedId, setExpandedId] = useState<number | null>(null);

  return (
    <div className="space-y-6">
      {/* Honesty Banner Required by Specification */}
      <div className="bg-amber-950/40 border border-amber-800/80 rounded-2xl p-5 text-xs text-amber-200 space-y-2">
        <div className="flex items-center gap-2 font-bold text-amber-300 text-sm">
          <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0" />
          <span>Demo Scenarios (Specification Reference Only — Not a Test Runner)</span>
        </div>
        <p className="leading-relaxed text-amber-200/90">
          In strict accordance with the <strong>Honesty Rules</strong>, this screen is an informational design checklist of the 13 criteria from the Phase 1 Technical Specification. It does <strong>not</strong> simulate or invent passing tests.
        </p>
        <div className="pt-2 flex items-center gap-2 font-mono text-[11px] text-amber-300">
          <Terminal className="w-4 h-4 text-emerald-400" />
          <span>To run real automated tests with real assertions: execute <code className="bg-zinc-900 px-2 py-0.5 rounded text-emerald-400 border border-zinc-700">npm test</code> in the terminal.</span>
        </div>
      </div>

      {/* Overview Card */}
      <div className="bg-zinc-950 border border-zinc-800 rounded-2xl p-6 shadow-xl flex flex-col md:flex-row md:items-center justify-between gap-5">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <BookOpen className="w-4 h-4 text-indigo-400" />
            <h2 className="text-lg font-bold text-zinc-100">
              Phase 1 Gate Criteria Reference
            </h2>
          </div>
          <p className="text-xs text-zinc-400 leading-relaxed max-w-2xl">
            Each milestone implements and tests a specific subset of these 13 criteria. Milestone 1 implements the PostgreSQL append-only database rule (#10), multi-tenant isolation (#13), and the cryptographic event hash chain.
          </p>
        </div>
      </div>

      {/* Scenarios Reference List */}
      <div className="border border-zinc-800 rounded-2xl overflow-hidden bg-zinc-950 divide-y divide-zinc-800/80 shadow-xl">
        {SPEC_SCENARIOS.map((scenario) => {
          const isExpanded = expandedId === scenario.id;
          const isMilestone1 = scenario.id === 10 || scenario.id === 13;

          return (
            <div key={scenario.id} className="p-4 transition-colors hover:bg-zinc-900/30 text-xs">
              <div className="flex items-start justify-between gap-4">
                <div className="flex items-start gap-3 flex-1">
                  <div className="mt-0.5">
                    <span className="w-6 h-6 rounded-lg border border-zinc-700 bg-zinc-900 text-zinc-400 flex items-center justify-center text-[10px] font-mono font-bold">
                      #{scenario.id}
                    </span>
                  </div>

                  <div className="space-y-1 flex-1">
                    <div className="flex items-center gap-2">
                      <span className="font-semibold text-zinc-100">
                        {scenario.name}
                      </span>
                      {isMilestone1 ? (
                        <span className="bg-emerald-950 text-emerald-300 border border-emerald-800 px-2 py-0.2 rounded text-[10px] font-mono">
                          Covered in Milestone 1 Vitest
                        </span>
                      ) : (
                        <span className="bg-zinc-900 text-zinc-500 border border-zinc-800 px-2 py-0.2 rounded text-[10px] font-mono">
                          Scheduled for Later Milestone
                        </span>
                      )}
                    </div>
                    <p className="text-zinc-400 leading-relaxed">
                      {scenario.description}
                    </p>
                  </div>
                </div>

                <button
                  onClick={() => setExpandedId(isExpanded ? null : scenario.id)}
                  className="p-1 text-zinc-500 hover:text-zinc-300 rounded"
                >
                  {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                </button>
              </div>

              {isExpanded && (
                <div className="mt-3 pt-3 border-t border-zinc-800/80 pl-9 font-mono text-[11px] text-zinc-400 space-y-1">
                  {scenario.log.map((line, idx) => (
                    <div key={idx} className="flex items-center gap-2">
                      <span className="text-zinc-600">&bull;</span>
                      <span>{line}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};
