import React, { useState, useEffect } from 'react';
import { createInitialEmptyState, purgeLegacyBrowserState, AppState } from './utils/storage';
import { fetchProjects, fetchProjectEvents, claimProject } from './utils/api';

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
import { RoleMode } from './types/custody';
import { AuthGate, AuthInfo } from './auth/AuthGate';

export default function App() {
  return <AuthGate>{(auth) => <Workspace auth={auth} />}</AuthGate>;
}

function Workspace({ auth }: { auth: AuthInfo }) {
  const [state, setState] = useState<AppState | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [eventsError, setEventsError] = useState<string | null>(null);

  // Navigation & UI state
  const [currentTab, setCurrentTab] = useState<string>('dashboard');
  const [roleMode, setRoleMode] = useState<RoleMode>('creator');
  const [selectedDoorId, setSelectedDoorId] = useState<string>('');

  // Modals state
  const [isSetupOpen, setIsSetupOpen] = useState(false);
  const [isClaimOpen, setIsClaimOpen] = useState(false);
  const [isOpenDoorOpen, setIsOpenDoorOpen] = useState(false);
  const [isInviteOpen, setIsInviteOpen] = useState(false);
  const [isClosingReportOpen, setIsClosingReportOpen] = useState(false);

  // Everything shown comes from the server. The browser keeps no copy.
  useEffect(() => {
    purgeLegacyBrowserState();
    async function init() {
      const initial = createInitialEmptyState();
      try {
        const { projects } = await fetchProjects();
        initial.projects = projects;
        initial.activeProjectId = projects[0]?.id ?? '';
      } catch (err: any) {
        setLoadError(err.message || 'Could not reach the server.');
      }
      setState(initial);
    }
    init();
  }, []);

  const activeProjectId = state?.activeProjectId;
  useEffect(() => {
    if (!activeProjectId) return;
    let cancelled = false;
    setEventsError(null);
    fetchProjectEvents(activeProjectId)
      .then((events) => {
        if (!cancelled) setState((prev) => (prev ? { ...prev, events } : prev));
      })
      .catch((err: any) => {
        if (!cancelled) setEventsError(err.message || 'Could not load the event log.');
      });
    return () => {
      cancelled = true;
    };
  }, [activeProjectId]);

  if (!state) {
    return (
      <div className="min-h-screen bg-zinc-950 flex items-center justify-center text-zinc-400 font-mono text-xs">
        Loading...
      </div>
    );
  }

  const activeProject = state.projects.find((p) => p.id === state.activeProjectId) || null;
  const selectedDoor = state.doors.find((d) => d.id === selectedDoorId) || state.doors[0] || null;
  const selectedWorkspace = selectedDoor ? state.workspaces.find((w) => w.door_id === selectedDoor.id) : undefined;

  // Claim a project: the server records it and its first event. A failure is shown, never papered over.
  const handleClaimProject = async (data: { name: string; purpose: string }) => {
    const project = await claimProject(data);
    setState((prev) =>
      prev
        ? {
            ...prev,
            projects: [project, ...prev.projects.filter((p) => p.id !== project.id)],
            activeProjectId: project.id
          }
        : prev
    );
  };

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100 flex flex-col font-sans selection:bg-indigo-600/30">
      <Header
        currentTab={currentTab}
        onSelectTab={setCurrentTab}
        roleMode={roleMode}
        onSelectRoleMode={setRoleMode}
        connections={state.connections}
        onOpenSetup={() => setIsSetupOpen(true)}
        userEmail={auth.email}
        onSignOut={() => void auth.signOut()}
      />

      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {loadError && (
          <div className="mb-6 p-4 bg-rose-950/50 border border-rose-800 rounded-xl text-xs text-rose-200">
            Projects could not be loaded: {loadError}
          </div>
        )}

        {currentTab === 'dashboard' && (
          <ProjectHomeView
            project={activeProject}
            events={state.events}
            eventsError={eventsError}
            onOpenNewDoor={() => setIsOpenDoorOpen(true)}
            onClaimNewProject={() => setIsClaimOpen(true)}
            onSelectTab={setCurrentTab}
          />
        )}

        {currentTab === 'door_details' &&
          (selectedDoor && activeProject ? (
            <DoorDetailsView
              door={selectedDoor}
              project={activeProject}
              onCloseDoor={async () => setIsClosingReportOpen(true)}
              onOpenInviteModal={() => setIsInviteOpen(true)}
            />
          ) : (
            <div className="p-12 text-center text-zinc-400 bg-zinc-950 border border-zinc-800 rounded-2xl space-y-3">
              <h3 className="font-semibold text-zinc-200 text-sm">Doors: Not connected yet</h3>
              <p className="text-xs text-zinc-500 max-w-md mx-auto">
                Doors will give an outside developer narrow, temporary, signed access. None exist.
              </p>
            </div>
          ))}

        {currentTab === 'workspace' &&
          (selectedDoor && activeProject ? (
            <DeveloperWorkspace
              door={selectedDoor}
              project={activeProject}
              workspace={selectedWorkspace}
              onCloseDoorRequested={() => setIsClosingReportOpen(true)}
            />
          ) : (
            <div className="p-12 text-center text-zinc-400 bg-zinc-950 border border-zinc-800 rounded-2xl space-y-3">
              <h3 className="font-semibold text-zinc-200 text-sm">Developer Workspace: Not connected yet</h3>
              <p className="text-xs text-zinc-500 max-w-md mx-auto">
                A developer's sandboxed workspace will appear here once a door is open. No door is open.
              </p>
            </div>
          ))}

        {currentTab === 'activity' && <ActivityLogView events={state.events} projectId={activeProject?.id} />}

        {currentTab === 'backup' &&
          (activeProject ? (
            <MirrorBackupView project={activeProject} />
          ) : (
            <div className="p-12 text-center text-zinc-400 bg-zinc-950 border border-zinc-800 rounded-2xl space-y-3">
              <h3 className="font-semibold text-zinc-200 text-sm">No Project Claimed Yet</h3>
              <p className="text-xs text-zinc-500 max-w-md mx-auto">Claim a project first to export its records.</p>
            </div>
          ))}

        {currentTab === 'acceptance' && <AcceptanceSuiteView />}
      </main>

      <WelcomeSetupModal isOpen={isSetupOpen} onClose={() => setIsSetupOpen(false)} />

      <ClaimProjectModal
        isOpen={isClaimOpen}
        onClose={() => setIsClaimOpen(false)}
        onClaimProject={handleClaimProject}
      />

      {activeProject && (
        <OpenDoorModal
          isOpen={isOpenDoorOpen}
          onClose={() => setIsOpenDoorOpen(false)}
          project={activeProject}
          agreementTemplates={state.agreementTemplates}
        />
      )}

      {selectedDoor && (
        <DeveloperInviteModal isOpen={isInviteOpen} onClose={() => setIsInviteOpen(false)} door={selectedDoor} />
      )}

      <ClosingReportModal isOpen={isClosingReportOpen} onClose={() => setIsClosingReportOpen(false)} report={null} />
    </div>
  );
}
