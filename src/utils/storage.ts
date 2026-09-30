import {
  Creator,
  Developer,
  Connection,
  Project,
  Door,
  CustodyEvent,
  MirrorSnapshot,
  AgreementTemplate,
  Workspace,
  LatencyMetric
} from '../types/custody';

const STORAGE_KEY = 'custody_core_state_v2_real';

export interface AppState {
  creator: Creator | null;
  developer: Developer | null;
  connections: Connection[];
  projects: Project[];
  activeProjectId: string;
  doors: Door[];
  workspaces: Workspace[];
  agreementTemplates: AgreementTemplate[];
  mirrorSnapshots: MirrorSnapshot[];
  events: CustodyEvent[];
  latencyMetrics: LatencyMetric[];
}

export function createInitialEmptyState(): AppState {
  return {
    creator: null,
    developer: null,
    connections: [
      {
        id: 'conn_github',
        creator_id: '',
        kind: 'github',
        external_account: '',
        status: 'unconnected',
        secret_ref: '',
        connected_at: ''
      },
      {
        id: 'conn_storage',
        creator_id: '',
        kind: 'storage_s3',
        external_account: '',
        status: 'unconnected',
        secret_ref: '',
        connected_at: ''
      }
    ],
    projects: [],
    activeProjectId: '',
    doors: [],
    workspaces: [],
    agreementTemplates: [],
    mirrorSnapshots: [],
    events: [],
    latencyMetrics: []
  };
}

export function loadAppState(): AppState | null {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    return JSON.parse(raw);
  } catch (err) {
    console.error('Failed to load app state from localStorage:', err);
    return null;
  }
}

export function saveAppState(state: AppState): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
  } catch (err) {
    console.error('Failed to save app state to localStorage:', err);
  }
}

export function clearAppState(): void {
  try {
    localStorage.removeItem(STORAGE_KEY);
    localStorage.removeItem('custody_core_state_v1'); // clear legacy fake state
  } catch (err) {
    console.error('Failed to clear app state:', err);
  }
}
