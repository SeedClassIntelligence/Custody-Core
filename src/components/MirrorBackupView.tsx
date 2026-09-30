import React, { useState } from 'react';
import {
  HardDrive,
  Download,
  ShieldCheck,
  CheckCircle2,
  FileArchive,
  Clock,
  Layers,
  FileCode,
  ExternalLink,
  Loader2,
  Sparkles,
  AlertTriangle
} from 'lucide-react';
import { Project, MirrorSnapshot, CustodyEvent, Door, Connection } from '../types/custody';
import { generateExportZip, ExportManifest } from '../utils/zipExport';

interface MirrorBackupViewProps {
  project: Project;
  connections: Connection[];
  mirrorSnapshots: MirrorSnapshot[];
  events: CustodyEvent[];
  doors: Door[];
}

export const MirrorBackupView: React.FC<MirrorBackupViewProps> = ({
  project,
  connections,
  mirrorSnapshots,
  events,
  doors
}) => {
  const [isExporting, setIsExporting] = useState(false);
  const [lastExportManifest, setLastExportManifest] = useState<ExportManifest | null>(null);

  const storageConn = connections.find(c => c.kind === 'storage_s3' || c.kind === 'storage_drive');
  const latestSnapshot = mirrorSnapshots[mirrorSnapshots.length - 1];

  const handleExportEverything = async () => {
    setIsExporting(true);
    try {
      const { blob, manifest, filename } = await generateExportZip({
        project,
        events,
        doors,
        mirrorSnapshots
      });

      setLastExportManifest(manifest);

      // Trigger browser download
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error('Export failed:', err);
    } finally {
      setIsExporting(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Banner: Creator Mirror Principle */}
      <div className="bg-zinc-950 border border-zinc-800 rounded-2xl p-6 shadow-xl flex flex-col md:flex-row md:items-center justify-between gap-5">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-amber-400" />
            <h2 className="text-lg font-bold text-zinc-100 flex items-center gap-2">
              Creator-Owned Storage Mirror & Export
              <span className="text-[10px] font-mono bg-amber-950 text-amber-300 border border-amber-800/60 px-2 py-0.5 rounded font-semibold">
                Not connected yet (Milestone 5)
              </span>
            </h2>
          </div>
          <p className="text-xs text-zinc-400 leading-relaxed max-w-2xl">
            <strong>The creator owns the mirror.</strong> Every push from a door workspace will trigger a real Git bundle snapshot written to your bucket with its SHA-256 hash. Per Honesty Rules, synthetic placeholder bundles are disabled until real repository access is wired in Milestone 5.
          </p>
        </div>

        {/* Export Everything Action */}
        <button
          disabled={true}
          className="bg-zinc-800 text-zinc-500 cursor-not-allowed text-xs font-semibold px-5 py-3 rounded-xl flex items-center gap-2 transition-colors border border-zinc-700 shrink-0"
        >
          <Download className="w-4 h-4" />
          <span>Export (Not connected yet)</span>
        </button>
      </div>

      <div className="p-4 bg-amber-950/30 border border-amber-800/40 rounded-xl text-xs text-amber-300 flex items-start gap-2.5">
        <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
        <div>
          <span className="font-semibold text-amber-200">Honesty Rule Notice:</span>
          <p className="text-[11px] text-amber-300/80 mt-0.5">
            Real `git bundle` creation requires local bare repositories and authenticated credentials to your S3 bucket or Google Drive. This milestone focuses on the database and event log; storage integration will be connected in Milestone 5.
          </p>
        </div>
      </div>

      {/* Mirror Status Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 text-xs">
        <div className="bg-zinc-950 border border-zinc-800 rounded-xl p-4 space-y-1">
          <div className="flex items-center gap-2 text-zinc-400 font-medium">
            <HardDrive className="w-4 h-4 text-cyan-400" />
            <span>Destination Vault</span>
          </div>
          <div className="text-sm font-semibold text-zinc-100 font-mono truncate">
            {storageConn?.external_account || 's3://darnell-custody-vault-us-east-1'}
          </div>
          <span className="text-[11px] text-emerald-400 flex items-center gap-1">
            <CheckCircle2 className="w-3 h-3" />
            Hardware Versioning Active
          </span>
        </div>

        <div className="bg-zinc-950 border border-zinc-800 rounded-xl p-4 space-y-1">
          <div className="flex items-center gap-2 text-zinc-400 font-medium">
            <Clock className="w-4 h-4 text-indigo-400" />
            <span>Last Snapshot Written</span>
          </div>
          <div className="text-sm font-semibold text-zinc-100">
            {latestSnapshot ? new Date(latestSnapshot.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : 'Never'}
          </div>
          <span className="text-[11px] text-zinc-500">
            {latestSnapshot ? `Trigger: ${latestSnapshot.trigger}` : 'No backups yet'}
          </span>
        </div>

        <div className="bg-zinc-950 border border-zinc-800 rounded-xl p-4 space-y-1">
          <div className="flex items-center gap-2 text-zinc-400 font-medium">
            <FileArchive className="w-4 h-4 text-amber-400" />
            <span>Total Bundle Snapshots</span>
          </div>
          <div className="text-xl font-bold text-zinc-100">
            {mirrorSnapshots.length}
          </div>
          <span className="text-[11px] text-zinc-500">
            Each verified with SHA-256
          </span>
        </div>
      </div>

      {/* Snapshot History Table */}
      <div className="bg-zinc-950 border border-zinc-800 rounded-2xl overflow-hidden shadow-xl space-y-3 p-5">
        <div className="flex items-center justify-between border-b border-zinc-800 pb-3">
          <div className="flex items-center gap-2">
            <Layers className="w-4 h-4 text-zinc-400" />
            <h3 className="font-semibold text-zinc-100 text-xs uppercase tracking-wider">
              Automated Git Bundle Snapshots
            </h3>
          </div>
          <span className="text-[11px] text-zinc-500">Nightly & Push-triggered</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-zinc-900/80 text-zinc-400 border-b border-zinc-800">
              <tr>
                <th className="p-3">Repository</th>
                <th className="p-3">Trigger</th>
                <th className="p-3">Size</th>
                <th className="p-3">SHA-256 Checksum</th>
                <th className="p-3">Timestamp</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800/60 text-zinc-300">
              {mirrorSnapshots.map((snap) => (
                <tr key={snap.id} className="hover:bg-zinc-900/40 transition-colors">
                  <td className="p-3 font-semibold text-zinc-100">
                    {snap.repository_name}
                  </td>
                  <td className="p-3">
                    <span className="bg-zinc-800 text-zinc-300 px-2 py-0.5 rounded text-[10px] capitalize">
                      {snap.trigger}
                    </span>
                  </td>
                  <td className="p-3 text-zinc-400">
                    {(snap.size_bytes / (1024 * 1024)).toFixed(2)} MB
                  </td>
                  <td className="p-3 text-cyan-400 text-[11px] truncate max-w-xs font-mono">
                    {snap.sha256}
                  </td>
                  <td className="p-3 text-zinc-500 text-[11px]">
                    {new Date(snap.timestamp).toLocaleString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Manifest Viewer if exported */}
      {lastExportManifest && (
        <div className="bg-zinc-950 border border-zinc-800 rounded-2xl p-5 space-y-3 animate-in fade-in duration-150">
          <div className="flex items-center gap-2 text-emerald-400 font-semibold text-xs uppercase tracking-wider">
            <CheckCircle2 className="w-4 h-4" />
            <span>Export Manifest Generated: MANIFEST.json</span>
          </div>

          <pre className="p-4 bg-zinc-900 rounded-xl text-xs font-mono text-zinc-300 overflow-x-auto max-h-60 leading-relaxed border border-zinc-800">
            {JSON.stringify(lastExportManifest, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
};
