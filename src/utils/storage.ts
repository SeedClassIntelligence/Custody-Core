import { Connection, Project, Door, CustodyEvent, MirrorSnapshot, AgreementTemplate, Workspace } from '../types/custody';

/**
 * The browser keeps no copy of custody data. Everything shown comes from the server on each load.
 * Earlier builds saved demo data in localStorage; this removes it so it can never show up again.
 */
const LEGACY_KEYS = ['custody_core_state_v2_real', 'custody_core_state_v1'];

export function purgeLegacyBrowserState(): void {
  try {
    for (const key of LEGACY_KEYS) localStorage.removeItem(key);
  } catch {
    // storage unavailable: nothing to purge
  }
}

export interface AppState {
  connections: Connection[];
  projects: Project[];
  activeProjectId: string;
  doors: Door[];
  workspaces: Workspace[];
  agreementTemplates: AgreementTemplate[];
  mirrorSnapshots: MirrorSnapshot[];
  events: CustodyEvent[];
}

export function createInitialEmptyState(): AppState {
  return {
    // No integration exists yet, so every connection starts (and stays) unconnected.
    connections: [
      { id: 'github', creator_id: '', kind: 'github', external_account: '', status: 'unconnected', secret_ref: '', connected_at: '' },
      { id: 'storage', creator_id: '', kind: 'storage_s3', external_account: '', status: 'unconnected', secret_ref: '', connected_at: '' }
    ],
    projects: [],
    activeProjectId: '',
    doors: [],
    workspaces: [],
    agreementTemplates: [],
    mirrorSnapshots: [],
    events: []
  };
}
