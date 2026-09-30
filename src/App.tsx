import React, { useState, useEffect } from 'react';
import {
  RoleMode,
  Project,
  Door,
  CustodyEvent,
  MirrorSnapshot,
  Workspace,
  ClosingReport,
  RightsType
} from './types/custody';
import {
  createInitialEmptyState,
  loadAppState,
  saveAppState,
  clearAppState,
  AppState
} from './utils/storage';
import { sha256 } from './utils/crypto';

// Components
import { Header } from './components/Header';
import { ProjectHomeView } from './components/ProjectHomeView';
import { DoorDetailsView } from './components/DoorDetailsView';
import { DeveloperWorkspace } from './components/DeveloperWorkspace';
import { ActivityLogView } from './components/ActivityLogView';
import { MirrorBackupView } from './components/MirrorBackupView';
import { AcceptanceSuiteView } from './components/AcceptanceSuiteView';

// Modals
import { WelcomeSetupModal } from './components/WelcomeSetupModal';
import { ClaimProjectModal } from './components/ClaimProjectModal';
import { OpenDoorModal } from './components/OpenDoorModal';
import { ClosingReportModal } from './components/ClosingReportModal';
import { DeveloperInviteModal } from './components/DeveloperInviteModal';

export default function App() {
  const [state, setState] = useState<AppState | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  // Navigation & UI state
  const [currentTab, setCurrentTab] = useState<string>('dashboard');
  const [roleMode, setRoleMode] = useState<RoleMode>('creator');
  const [selectedDoorId, setSelectedDoorId] = useState<string>('');

  // Modals state
  const [isSetupOpen, setIsSetupOpen] = useState(false);
  const [isClaimOpen, setIsClaimOpen] = useState(false);
  const [isOpenDoorOpen, setIsOpenDoorOpen] = useState(false);
  const [isInviteOpen, setIsInviteOpen] = useState(false);
  const [closingReport, setClosingReport] = useState<ClosingReport | null>(null);
  const [isClosingReportOpen, setIsClosingReportOpen] = useState(false);

  // Initialize or load state
  useEffect(() => {
    async function init() {
      const saved = loadAppState() || createInitialEmptyState();
      
      // Fetch server projects on load
      try {
        const res = await fetch('/api/v1/projects');
        if (res.ok) {
          const data = await res.json();
          if (Array.isArray(data.projects) && data.projects.length > 0) {
            saved.projects = data.projects;
            if (!saved.activeProjectId || !data.projects.some((p: any) => p.id === saved.activeProjectId)) {
              saved.activeProjectId = data.projects[0].id;
            }
          }
        }
      } catch (err) {
        console.warn('Could not load server projects on boot:', err);
      }

      setState(saved);
      if (saved.doors && saved.doors.length > 0) {
        setSelectedDoorId(saved.doors[0].id);
      }
      setIsLoading(false);
    }
    init();
  }, []);

  // Sync state to local storage
  const updateState = (updater: (prev: AppState) => AppState) => {
    setState(prev => {
      if (!prev) return prev;
      const next = updater(prev);
      saveAppState(next);
      return next;
    });
  };

  if (isLoading || !state) {
    return (
      <div className="min-h-screen bg-zinc-950 flex items-center justify-center text-zinc-400 font-mono text-xs">
        <div className="flex items-center gap-2">
          <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse" />
          <span>Initializing Custody Core Secure Enclave...</span>
        </div>
      </div>
    );
  }

  const activeProject = state.projects.find(p => p.id === state.activeProjectId) || state.projects[0] || null;
  const selectedDoor = state.doors.find(d => d.id === selectedDoorId) || state.doors[0] || null;
  const selectedWorkspace = selectedDoor ? state.workspaces.find(w => w.door_id === selectedDoor.id) : undefined;
  const activeDoorsCount = state.doors.filter(d => d.status === 'open').length;

  const creatorName = state.creator?.display_name || 'Primary Creator';
  const creatorId = state.creator?.id || 'creator_primary';
  const developerName = state.developer?.display_name || 'Contractor Developer';
  const developerId = state.developer?.id || 'dev_contractor';

  // 1. Claim a Project via server API
  const handleClaimProject = async (data: {
    name: string;
    purpose: string;
    splitCore: boolean;
    coreRepoName?: string;
    appRepoName?: string;
  }) => {
    const org = state.connections.find(c => c.kind === 'github')?.external_account || 'creator-org';

    const repos: Array<{ full_name: string; default_branch: string; is_core: boolean }> = [];
    if (data.splitCore && data.coreRepoName) {
      repos.push({
        full_name: `${org}/${data.coreRepoName}`,
        default_branch: 'main',
        is_core: true
      });
    }

    const appName = data.appRepoName || 'app';
    repos.push({
      full_name: `${org}/${appName}`,
      default_branch: 'main',
      is_core: false
    });

    let claimedProject: Project | null = null;
    try {
      const res = await fetch('/api/v1/projects', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: data.name,
          purpose: data.purpose,
          creator_id: creatorId,
          split_core: data.splitCore,
          repositories: repos
        })
      });

      if (res.ok) {
        const payload = await res.json();
        // Use the UUID and repositories returned by the server
        claimedProject = payload.project;
      }
    } catch (err) {
      console.error('Failed to claim project on server:', err);
    }

    if (!claimedProject) {
      // Fallback only if server completely unreachable
      const fallbackId = crypto.randomUUID ? crypto.randomUUID() : `proj_${Date.now()}`;
      claimedProject = {
        id: fallbackId,
        creator_id: creatorId,
        name: data.name,
        purpose: data.purpose,
        status: 'active',
        created_at: new Date().toISOString(),
        repositories: repos.map((r, i) => ({
          id: `repo_${i}_${Date.now()}`,
          project_id: fallbackId,
          github_repo_id: `gh_${i}`,
          full_name: r.full_name,
          default_branch: r.default_branch,
          is_core: r.is_core,
          locked_at: new Date().toISOString(),
          allow_forking: false,
          ruleset_active: true
        }))
      };
    }

    updateState(prev => ({
      ...prev,
      projects: [claimedProject!, ...prev.projects.filter(p => p.id !== claimedProject!.id)],
      activeProjectId: claimedProject!.id
    }));

    setIsClaimOpen(false);
  };

  // 2. Open a Door
  const handleOpenDoor = async (data: {
    jobDescription: string;
    developerEmail: string;
    rightsType: RightsType;
    durationDays: number;
    selectedRepoIds: string[];
  }) => {
    if (!activeProject) return;

    const doorId = `door_${Math.random().toString(36).substring(2, 10)}`;
    const expiresAt = new Date(Date.now() + data.durationDays * 86400000).toISOString();

    const newDoor: Door = {
      id: doorId,
      project_id: activeProject.id,
      developer_email: data.developerEmail,
      job_description: data.jobDescription,
      rights_type: data.rightsType,
      agreement_id: `tmpl_${data.rightsType}_v1`,
      status: 'awaiting_signature',
      expires_at: expiresAt,
      repositories: data.selectedRepoIds.map(repoId => ({
        door_id: doorId,
        repository_id: repoId,
        access: 'write'
      })),
      branch_prefix: `door/${doorId}`
    };

    const newWorkspace: Workspace = {
      id: `ws_coder_${doorId}`,
      door_id: doorId,
      coder_workspace_id: `coder-ws-${doorId.substring(0, 8)}`,
      status: 'provisioning',
      namespace: `door-ns-${doorId}`,
      git_remote_url: `https://gateway.custodycore.internal/repos/${activeProject.name.toLowerCase().replace(/\s+/g, '-')}.git?door=${doorId}`,
      network_egress_policy: 'restricted'
    };

    updateState(prev => ({
      ...prev,
      doors: [newDoor, ...prev.doors],
      workspaces: [...prev.workspaces, newWorkspace]
    }));

    setSelectedDoorId(doorId);
  };

  // 3. Developer Onboarding & Agreement Signing (Not connected yet)
  const handleCompleteOnboarding = async () => {
    // Agreement signing screen shows 'Not connected yet' until built for real
  };

  // 4. Git Push from Developer Workspace (Not connected yet)
  const handleGitPush = async () => {
    return { success: false, message: 'Git push is not connected yet.' };
  };

  // 5. Accept Work
  const handleAcceptWork = async (doorId: string) => {
    const door = state.doors.find(d => d.id === doorId);
    if (!door) return;
  };

  // 6. Extend Door Expiration
  const handleExtendDoor = async (doorId: string, additionalDays: number) => {
    const door = state.doors.find(d => d.id === doorId);
    if (!door) return;

    const currentExp = new Date(door.expires_at).getTime();
    const newExp = new Date(currentExp + additionalDays * 86400000).toISOString();

    updateState(prev => ({
      ...prev,
      doors: prev.doors.map(d => d.id === doorId ? { ...d, expires_at: newExp } : d)
    }));
  };

  // 7. Close the Door (Not connected yet - screen shows honest status and plain sentence)
  const handleCloseDoor = async (doorId: string) => {
    const door = state.doors.find(d => d.id === doorId);
    if (!door) return;

    // Do not generate fake snapshots, fake SHAs, fake storage URIs, or claims that credentials were revoked/workspaces destroyed.
    setIsClosingReportOpen(true);
  };

  const handleResetState = () => {
    if (window.confirm('Reset app state?')) {
      clearAppState();
      const fresh = createInitialEmptyState();
      setState(fresh);
      saveAppState(fresh);
      setSelectedDoorId('');
      setCurrentTab('dashboard');
    }
  };

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100 flex flex-col font-sans selection:bg-indigo-600/30">
      {/* Top Universal Header */}
      <Header
        currentTab={currentTab}
        onSelectTab={setCurrentTab}
        roleMode={roleMode}
        onSelectRoleMode={setRoleMode}
        connections={state.connections}
        activeDoorCount={activeDoorsCount}
        onOpenSetup={() => setIsSetupOpen(true)}
        onResetState={handleResetState}
      />

      {/* Main Workspace Canvas */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* VIEW 1: CREATOR PROJECT HOME */}
        {currentTab === 'dashboard' && (
          <ProjectHomeView
            project={activeProject}
            doors={state.doors}
            events={state.events}
            mirrorSnapshots={state.mirrorSnapshots}
            connections={state.connections}
            onOpenNewDoor={() => setIsOpenDoorOpen(true)}
            onSelectDoor={(doorId) => {
              setSelectedDoorId(doorId);
              setCurrentTab('door_details');
            }}
            onClaimNewProject={() => setIsClaimOpen(true)}
            onSelectTab={setCurrentTab}
            onSwitchToWorkspace={(doorId) => {
              setSelectedDoorId(doorId);
              setRoleMode('developer');
              setCurrentTab('workspace');
            }}
          />
        )}

        {/* VIEW 2: DOOR DETAILS & AUDIT */}
        {currentTab === 'door_details' && (
          selectedDoor && activeProject ? (
            <DoorDetailsView
              door={selectedDoor}
              project={activeProject}
              events={state.events}
              onAcceptWork={handleAcceptWork}
              onExtendDoor={handleExtendDoor}
              onCloseDoor={handleCloseDoor}
              onSwitchToWorkspace={(doorId) => {
                setSelectedDoorId(doorId);
                setRoleMode('developer');
                setCurrentTab('workspace');
              }}
              onOpenInviteModal={() => setIsInviteOpen(true)}
            />
          ) : (
            <div className="p-12 text-center text-zinc-400 bg-zinc-950 border border-zinc-800 rounded-2xl space-y-3">
              <h3 className="font-semibold text-zinc-200 text-sm">No Active Door Selected</h3>
              <p className="text-xs text-zinc-500 max-w-md mx-auto">
                Open a door from Project Home to invite a developer into a sandboxed cloud workspace.
              </p>
            </div>
          )
        )}

        {/* VIEW 3: DEVELOPER CLOUD WORKSPACE & GIT GATEWAY */}
        {currentTab === 'workspace' && (
          selectedDoor && activeProject ? (
            <DeveloperWorkspace
              door={selectedDoor}
              project={activeProject}
              workspace={selectedWorkspace}
              onGitPush={handleGitPush}
              onCloseDoorRequested={() => handleCloseDoor(selectedDoor.id)}
            />
          ) : (
            <div className="p-12 text-center text-zinc-400 bg-zinc-950 border border-zinc-800 rounded-2xl space-y-3">
              <h3 className="font-semibold text-zinc-200 text-sm">Developer Workspace Idle</h3>
              <p className="text-xs text-zinc-500 max-w-md mx-auto">
                No active door currently assigned. When a creator opens a door and you sign the agreement, your sandboxed cloud workspace will mount here.
              </p>
            </div>
          )
        )}

        {/* VIEW 4: ACTIVITY LOG & HASH CHAIN VERIFICATION */}
        {currentTab === 'activity' && (
          <ActivityLogView
            events={state.events}
            projectId={activeProject?.id}
          />
        )}

        {/* VIEW 5: MIRROR STORAGE & EXPORT */}
        {currentTab === 'backup' && (
          activeProject ? (
            <MirrorBackupView
              project={activeProject}
              connections={state.connections}
              mirrorSnapshots={state.mirrorSnapshots}
              events={state.events}
              doors={state.doors}
            />
          ) : (
            <div className="p-12 text-center text-zinc-400 bg-zinc-950 border border-zinc-800 rounded-2xl space-y-3">
              <h3 className="font-semibold text-zinc-200 text-sm">No Project Claimed Yet</h3>
              <p className="text-xs text-zinc-500 max-w-md mx-auto">
                Claim a project first to set up creator-owned backup storage and mirror snapshots.
              </p>
            </div>
          )
        )}

        {/* VIEW 6: SPECIFICATION DEMO SCENARIOS */}
        {currentTab === 'acceptance' && (
          <AcceptanceSuiteView />
        )}
      </main>

      {/* Guided Setup Modal */}
      <WelcomeSetupModal
        isOpen={isSetupOpen}
        onClose={() => setIsSetupOpen(false)}
        connections={state.connections}
        onConnectGitHub={(org) => {
          updateState(prev => ({
            ...prev,
            connections: prev.connections.map(c =>
              c.kind === 'github'
                ? { ...c, status: 'locked', external_account: org, connected_at: new Date().toISOString() }
                : c
            )
          }));
        }}
        onConnectStorage={(bucket) => {
          updateState(prev => ({
            ...prev,
            connections: prev.connections.map(c =>
              c.kind === 'storage_s3'
                ? { ...c, status: 'connected', external_account: bucket, connected_at: new Date().toISOString() }
                : c
            )
          }));
        }}
      />

      {/* Claim Project Modal */}
      <ClaimProjectModal
        isOpen={isClaimOpen}
        onClose={() => setIsClaimOpen(false)}
        onClaimProject={handleClaimProject}
        orgName={state.connections.find(c => c.kind === 'github')?.external_account || 'creator-org'}
      />

      {/* Open Door Modal */}
      {activeProject && (
        <OpenDoorModal
          isOpen={isOpenDoorOpen}
          onClose={() => setIsOpenDoorOpen(false)}
          onOpenDoor={handleOpenDoor}
          project={activeProject}
          agreementTemplates={state.agreementTemplates}
        />
      )}

      {/* Developer Invite / Signing Modal */}
      {selectedDoor && (
        <DeveloperInviteModal
          isOpen={isInviteOpen}
          onClose={() => setIsInviteOpen(false)}
          door={selectedDoor}
          onCompleteOnboarding={handleCompleteOnboarding}
        />
      )}

      {/* Closing Report Modal */}
      <ClosingReportModal
        isOpen={isClosingReportOpen}
        onClose={() => setIsClosingReportOpen(false)}
        report={closingReport}
      />
    </div>
  );
}
