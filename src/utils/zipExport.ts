import JSZip from 'jszip';
import { Project, CustodyEvent } from '../types/custody';
import { sha256 } from './crypto';

export interface ExportManifestFile {
  filename: string;
  sha256: string;
  size_bytes: number;
  description: string;
}

export interface ExportManifest {
  archive_version: string;
  project_name: string;
  project_id: string;
  creator_id: string;
  exported_at: string;
  total_events: number;
  /** How many events carry a Seed Signature id. Zero until Seed Signature is connected. */
  events_with_seed_signature: number;
  /** Git bundles are not produced yet, so none are included. */
  git_bundles_included: false;
  files: ExportManifestFile[];
}

async function describeFile(filename: string, content: string, description: string): Promise<ExportManifestFile> {
  return {
    filename,
    sha256: await sha256(content),
    size_bytes: new TextEncoder().encode(content).length,
    description
  };
}

/** Builds the export archive: event log, project record and a SHA-256 manifest of both. */
export async function generateExportZip(params: {
  project: Project;
  events: CustodyEvent[];
}): Promise<{ blob: Blob; manifest: ExportManifest; filename: string }> {
  const { project, events } = params;
  const zip = new JSZip();

  const eventsContent = JSON.stringify(events, null, 2);
  const projectContent = JSON.stringify(project, null, 2);
  zip.file('events-hashchain.json', eventsContent);
  zip.file('project-metadata.json', projectContent);

  const manifest: ExportManifest = {
    archive_version: '1',
    project_name: project.name,
    project_id: project.id,
    creator_id: project.creator_id,
    exported_at: new Date().toISOString(),
    total_events: events.length,
    events_with_seed_signature: events.filter((e) => e.seed_signature_id !== '').length,
    git_bundles_included: false,
    files: [
      await describeFile('events-hashchain.json', eventsContent, 'Append-only hash-chained event log for this project'),
      await describeFile('project-metadata.json', projectContent, 'Project record as stored by the server')
    ]
  };
  zip.file('MANIFEST.json', JSON.stringify(manifest, null, 2));

  const blob = await zip.generateAsync({ type: 'blob' });
  const slug = project.name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'project';
  const filename = `${slug}-custody-export-${manifest.exported_at.slice(0, 10)}.zip`;
  return { blob, manifest, filename };
}
