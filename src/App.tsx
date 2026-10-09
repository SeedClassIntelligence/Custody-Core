import React, { useState, useEffect } from 'react';
import { createInitialEmptyState, purgeLegacyBrowserState, AppState } from './utils/storage';
import {
  fetchProjects,
  fetchProjectEvents,
  claimProject,
  fetchGitHubStatus,
  startGitHubInstall,
  addRepositories,
  checkRepositoryLock,
  fetchDoors,
  closeDoor,
  GitHubStatus,
  ServerDoor
} from './utils/api';

// Components
import { Header } from './components/Header';
import { ProjectHomeView } from './components/ProjectHomeView';
import { DoorDetailsView } from './components/DoorDetailsView';
import { DeveloperDoorsView } from './components/DeveloperDoorsView';
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

const INVITE_KEY = 'custody-core.pending-invite';

/**
 * An invitation link (/?invite=...) is kept in this browser until it is handled, so it survives signing up,
 * confirming the email in another tab, and setting up the authenticator. It is removed from the address bar at once.
 */
function readPendingInvite(): string | null {
  try {
    const fromUrl = new URLSearchParams(window.location.search).get('invite');
    if (fromUrl) {
      localStorage.setItem(INVITE_KEY, fromUrl);
      const url = new URL(window.location.href);
      url.searchParams.delete('invite');
      window.history.replaceState(null, '', url.pathname + url.search);
    }
    return localStorage.getItem(INVITE_KEY);
  } catch {
    return null;
  }
}

// Read at page load, before the login screen: the link's parameter must be kept even if the person signs up first.
readPendingInvite();

function storedInvite(): string | null {
  try {
    return localStorage.getItem(INVITE_KEY);
  } catch {
    return null;
  }
}

function clearPendingInvite() {
  try {
    localStorage.removeItem(INVITE_KEY);
  } catch {
    // storage unavailable: nothing kept
  }
}

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
  const [github, setGithub] = useState<GitHubStatus | null>(null);
  const [githubNotice, setGithubNotice] = useState<{ ok: boolean; text: string } | null>(null);
  const [doors, setDoors] = useState<ServerDoor[]>([]);
  const [doorsError, setDoorsError] = useState<string | null>(null);
  const [pendingInvite, setPendingInvite] = useState<string | null>(() => storedInvite());

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

  // An invitation link opens the developer's view.
  useEffect(() => {
    if (pendingInvite) {
      setRoleMode('developer');
      setCurrentTab('workspace');
    }
  }, [pendingInvite]);

  // GitHub connection, and the result of coming back from GitHub's install page (/?github=...).
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const outcome = params.get('github');
    if (outcome) {
      const reasons: Record<string, string> = {
        start_again: 'The connection was not started from this browser, or took too long. Start again from Custody Core.',
        not_your_installation: 'GitHub says the account that installed the app cannot access that installation.',
        no_user_authorization: 'GitHub did not send back the sign-in step. The App must have "Request user authorization (OAuth) during installation" on.',
        github_refused: 'GitHub refused a request. Try again.',
        server_not_configured: 'The server is missing settings for the GitHub connection.'
      };
      setGithubNotice(
        outcome === 'connected'
          ? { ok: true, text: 'GitHub is connected.' }
          : outcome === 'requested'
            ? { ok: true, text: 'Installation requested. An owner of the GitHub organization must approve it, then connect again.' }
            : { ok: false, text: `GitHub was not connected. ${reasons[params.get('reason') ?? ''] ?? 'Try again.'}` }
      );
      window.history.replaceState(null, '', window.location.pathname);
    }
    fetchGitHubStatus()
      .then(setGithub)
      .catch(() => setGithub(null));
  }, []);

  const connectGitHub = async () => {
    try {
      window.location.href = await startGitHubInstall();
    } catch (err: any) {
      setGithubNotice({ ok: false, text: err.message || 'Could not start the GitHub connection.' });
    }
  };

  const activeProjectId = state?.activeProjectId;
  useEffect(() => {
    if (!activeProjectId) return;
    setDoorsError(null);
    fetchDoors(activeProjectId)
      .then(setDoors)
      .catch((err: any) => setDoorsError(err.message || 'Could not load doors.'));
  }, [activeProjectId]);

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
  const selectedServerDoor = doors.find((d) => d.id === selectedDoorId) || doors[0] || null;

  const reloadProjects = async () => {
    const { projects } = await fetchProjects();
    setState((prev) => (prev ? { ...prev, projects } : prev));
  };
  const reloadEvents = async () => {
    if (!activeProjectId) return;
    const events = await fetchProjectEvents(activeProjectId).catch(() => null);
    if (events) setState((prev) => (prev ? { ...prev, events } : prev));
  };
  const handleAddRepositories = async (names: string[]) => {
    if (!activeProjectId) return;
    await addRepositories(activeProjectId, names);
    await reloadProjects();
    await reloadEvents();
  };
  const handleCheckLock = async (repositoryId: string) => {
    if (!activeProjectId) return;
    await checkRepositoryLock(activeProjectId, repositoryId);
    await reloadProjects();
    await reloadEvents();
  };
  const handleDoorOpened = (door: ServerDoor) => {
    setDoors((prev) => [door, ...prev.filter((d) => d.id !== door.id)]);
    setSelectedDoorId(door.id);
    void reloadEvents();
  };
  const handleCloseDoor = async (doorId: string) => {
    if (!activeProjectId) return;
    const closed = await closeDoor(activeProjectId, doorId);
    setDoors((prev) => prev.map((d) => (d.id === closed.id ? closed : d)));
    await reloadEvents();
  };

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
        github={github}
        onConnectGitHub={connectGitHub}
        onOpenSetup={() => setIsSetupOpen(true)}
        userEmail={auth.email}
        onSignOut={() => void auth.signOut()}
      />

      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {githubNotice && (
          <div
            className={`mb-6 p-4 rounded-xl text-xs flex justify-between gap-4 border ${
              githubNotice.ok ? 'bg-emerald-950/40 border-emerald-800 text-emerald-200' : 'bg-rose-950/50 border-rose-800 text-rose-200'
            }`}
          >
            <span>{githubNotice.text}</span>
            <button onClick={() => setGithubNotice(null)} className="opacity-70 hover:opacity-100">
              Dismiss
            </button>
          </div>
        )}

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
            github={github}
            doors={doors}
            doorsError={doorsError}
            onConnectGitHub={connectGitHub}
            onAddRepositories={handleAddRepositories}
            onCheckLock={handleCheckLock}
            onSelectDoor={(id) => {
              setSelectedDoorId(id);
              setCurrentTab('door_details');
            }}
          />
        )}

        {currentTab === 'door_details' &&
          (selectedServerDoor && activeProject ? (
            <DoorDetailsView
              door={selectedServerDoor}
              doors={doors}
              project={activeProject}
              onSelectDoor={setSelectedDoorId}
              onCloseDoor={handleCloseDoor}
              onDoorChanged={(d) => {
                setDoors((prev) => prev.map((x) => (x.id === d.id ? d : x)));
                void reloadEvents();
              }}
            />
          ) : (
            <div className="p-12 text-center text-zinc-400 bg-zinc-950 border border-zinc-800 rounded-2xl space-y-3">
              <h3 className="font-semibold text-zinc-200 text-sm">No doors yet</h3>
              <p className="text-xs text-zinc-500 max-w-md mx-auto">
                Open a door from the project page to give a developer access through the git gateway.
              </p>
            </div>
          ))}

        {currentTab === 'workspace' && (
          <DeveloperDoorsView
            email={auth.email}
            pendingInvite={pendingInvite}
            onInviteHandled={() => {
              clearPendingInvite();
              setPendingInvite(null);
            }}
          />
        )}

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

      <WelcomeSetupModal isOpen={isSetupOpen} onClose={() => setIsSetupOpen(false)} githubConnected={!!github?.connected} />

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
          githubConnected={!!github?.connected}
          onDoorOpened={handleDoorOpened}
        />
      )}

      {selectedDoor && (
        <DeveloperInviteModal isOpen={isInviteOpen} onClose={() => setIsInviteOpen(false)} door={selectedDoor} />
      )}

      <ClosingReportModal isOpen={isClosingReportOpen} onClose={() => setIsClosingReportOpen(false)} report={null} />
    </div>
  );
}
