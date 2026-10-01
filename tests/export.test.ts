import { describe, it, expect } from 'vitest';
import JSZip from 'jszip';
import { createHash } from 'node:crypto';
import { generateExportZip } from '../src/utils/zipExport';
import type { CustodyEvent, Project } from '../src/types/custody';

const project: Project = {
  id: '11111111-1111-1111-1111-111111111111',
  creator_id: '22222222-2222-2222-2222-222222222222',
  name: 'Export Test Project',
  purpose: 'Checking the export contents',
  status: 'active',
  created_at: '2026-10-01T00:00:00.000Z',
  repositories: []
};

function event(seq: number, seedSignatureId = ''): CustodyEvent {
  return {
    seq,
    project_id: project.id,
    actor_type: 'creator',
    actor_id: project.creator_id,
    actor_name: project.creator_id,
    action: 'project.claimed',
    subject_type: 'project',
    subject_id: project.id,
    payload: { n: seq },
    prev_hash: '0'.repeat(64),
    hash: 'a'.repeat(64),
    seed_signature_id: seedSignatureId,
    timestamp: '2026-10-01T00:00:00.000Z'
  };
}

const sha = (text: string) => createHash('sha256').update(text, 'utf8').digest('hex');

async function open(blob: Blob) {
  return JSZip.loadAsync(await blob.arrayBuffer());
}

describe('Export archive', () => {
  it('contains only the event log, project record and manifest, with no git bundles', async () => {
    const { blob, manifest } = await generateExportZip({ project, events: [event(1), event(2)] });
    const zip = await open(blob);

    expect(Object.keys(zip.files).sort()).toEqual(['MANIFEST.json', 'events-hashchain.json', 'project-metadata.json']);
    expect(manifest.git_bundles_included).toBe(false);
    expect(manifest.files.map((f) => f.filename).some((n) => n.endsWith('.bundle'))).toBe(false);
  });

  it('manifest hashes and sizes match the real bytes of every file in the archive', async () => {
    const { blob } = await generateExportZip({ project, events: [event(1), event(2), event(3)] });
    const zip = await open(blob);
    const manifest = JSON.parse(await zip.file('MANIFEST.json')!.async('string'));

    expect(manifest.total_events).toBe(3);
    expect(manifest.files).toHaveLength(2);
    for (const entry of manifest.files) {
      const content = await zip.file(entry.filename)!.async('string');
      expect(entry.sha256).toBe(sha(content));
      expect(entry.size_bytes).toBe(Buffer.byteLength(content, 'utf8'));
    }
  });

  it('a manifest check fails if a file in the archive is altered afterwards', async () => {
    const { blob } = await generateExportZip({ project, events: [event(1)] });
    const zip = await open(blob);
    const manifest = JSON.parse(await zip.file('MANIFEST.json')!.async('string'));

    zip.file('events-hashchain.json', '[]');
    const altered = await zip.file('events-hashchain.json')!.async('string');
    const recorded = manifest.files.find((f: any) => f.filename === 'events-hashchain.json');
    expect(sha(altered)).not.toBe(recorded.sha256);
  });

  it('reports Seed Signature honestly: zero signed events when none carry a signature id', async () => {
    const unsigned = await generateExportZip({ project, events: [event(1), event(2)] });
    expect(unsigned.manifest.events_with_seed_signature).toBe(0);

    const partlySigned = await generateExportZip({ project, events: [event(1, 'sig_abc'), event(2)] });
    expect(partlySigned.manifest.events_with_seed_signature).toBe(1);
  });
});
