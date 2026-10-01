import React, { useState } from 'react';
import { HardDrive, Download, Loader2, AlertTriangle } from 'lucide-react';
import { Project } from '../types/custody';
import { generateExportZip, ExportManifest } from '../utils/zipExport';
import { fetchProjectEvents } from '../utils/api';

interface MirrorBackupViewProps {
  project: Project;
}

export const MirrorBackupView: React.FC<MirrorBackupViewProps> = ({ project }) => {
  const [isExporting, setIsExporting] = useState(false);
  const [exportError, setExportError] = useState<string | null>(null);
  const [lastExportManifest, setLastExportManifest] = useState<ExportManifest | null>(null);

  const handleExport = async () => {
    setIsExporting(true);
    setExportError(null);
    try {
      // The event log comes from the server, never from the browser.
      const events = await fetchProjectEvents(project.id);
      const { blob, manifest, filename } = await generateExportZip({ project, events });
      setLastExportManifest(manifest);

      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err: any) {
      setExportError(err.message || 'The export could not be created.');
    } finally {
      setIsExporting(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="bg-zinc-950 border border-zinc-800 rounded-2xl p-6 shadow-xl flex flex-col md:flex-row md:items-center justify-between gap-5">
        <div className="space-y-1">
          <h2 className="text-lg font-bold text-zinc-100">Export Everything</h2>
          <p className="text-xs text-zinc-400 leading-relaxed max-w-2xl">
            Downloads your project record and its full event log, with a manifest listing the SHA-256 hash of each file.
            Code backups (git bundles) are not included because they are not connected yet.
          </p>
        </div>
        <button
          onClick={handleExport}
          disabled={isExporting}
          className="bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white text-xs font-semibold px-5 py-3 rounded-xl flex items-center gap-2 transition-colors shrink-0"
        >
          {isExporting ? <Loader2 className="w-4 h-4 animate-spin" /> : <Download className="w-4 h-4" />}
          <span>{isExporting ? 'Preparing...' : 'Export Records'}</span>
        </button>
      </div>

      {exportError && (
        <div className="p-4 bg-rose-950/50 border border-rose-800 rounded-xl text-xs text-rose-200">{exportError}</div>
      )}

      <div className="p-5 bg-amber-950/30 border border-amber-800/40 rounded-xl text-xs text-amber-300 flex items-start gap-3">
        <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
        <div className="space-y-1">
          <div className="flex items-center gap-2 font-semibold text-amber-200">
            <HardDrive className="w-4 h-4" />
            <span>Backup Mirror: Not connected yet</span>
          </div>
          <p className="text-[11px] text-amber-300/80">
            Backup snapshots will be written to storage that you own once repository access and storage are connected.
            No storage is connected and no snapshots exist.
          </p>
        </div>
      </div>

      {lastExportManifest && (
        <div className="bg-zinc-950 border border-zinc-800 rounded-2xl p-5 space-y-3">
          <div className="flex items-center gap-2 text-zinc-300 font-semibold text-xs uppercase tracking-wider">
            <span>Manifest included in the file you just downloaded</span>
          </div>
          <pre className="p-4 bg-zinc-900 rounded-xl text-xs font-mono text-zinc-300 overflow-x-auto max-h-60 leading-relaxed border border-zinc-800">
            {JSON.stringify(lastExportManifest, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
};
