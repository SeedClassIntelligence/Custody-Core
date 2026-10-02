import React, { useState, useEffect } from 'react';
import {
  ShieldCheck,
  CheckCircle2,
  AlertTriangle,
  Copy,
  Check,
  Search,
  RefreshCw,
  Flame,
  Lock,
  Database,
  Server,
  Terminal,
  ExternalLink,
  Code
} from 'lucide-react';
import { CustodyEvent } from '../types/custody';
import { formatHash } from '../utils/crypto';
import { mapServerEvent } from '../utils/api';

interface ActivityLogViewProps {
  events: CustodyEvent[];
  projectId?: string;
}

interface ServerVerifyResponse {
  valid: boolean;
  broken_at_seq: number | null;
  count: number;
}

export const ActivityLogView: React.FC<ActivityLogViewProps> = ({
  events: initialEvents,
  projectId
}) => {
  const [filterAction, setFilterAction] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [serverEvents, setServerEvents] = useState<CustodyEvent[]>([]);
  const [dbStatus, setDbStatus] = useState<'loading' | 'connected' | 'not_connected' | 'error'>('loading');
  const [dbError, setDbError] = useState<string | null>(null);
  const [selectedEvent, setSelectedEvent] = useState<CustodyEvent | null>(null);
  const [verificationResult, setVerificationResult] = useState<{
    isValid: boolean;
    brokenAtSeq: number | null;
    totalEvents: number;
    reason?: string;
    checkFailed?: boolean;
  } | null>(null);
  const [isVerifying, setIsVerifying] = useState(false);
  const [copiedHash, setCopiedHash] = useState<string | null>(null);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [eventsError, setEventsError] = useState<string | null>(null);

  // Check database health and fetch real events if available
  const fetchDbAndEvents = async () => {
    setIsRefreshing(true);
    try {
      const healthRes = await fetch('/api/v1/health');
      const healthData = await healthRes.json();
      if (healthData?.database?.status === 'connected') {
        setDbStatus('connected');
        setDbError(null);

        // Fetch real events for project
        setEventsError(null);
        setServerEvents([]);
        if (projectId) {
          const eventsRes = await fetch(`/api/v1/projects/${projectId}/events`);
          if (eventsRes.ok) {
            const data = await eventsRes.json();
            const loaded = (data.events || []).map(mapServerEvent);
            setServerEvents(loaded);
            if (loaded.length > 0) {
              setSelectedEvent(loaded[loaded.length - 1]);
            }
          } else {
            setEventsError(`The event log could not be loaded (server returned ${eventsRes.status}).`);
          }
        }
      } else {
        setDbStatus('not_connected');
        setDbError(healthData?.database?.error || null);
      }
    } catch (err: any) {
      setDbStatus('not_connected');
      setDbError(err.message || 'Failed to reach API server.');
    } finally {
      setIsRefreshing(false);
    }
  };

  useEffect(() => {
    fetchDbAndEvents();
  }, [projectId]);

  // Use real server events if connected, otherwise empty array (Honesty Rule: never show fake events)
  const displayEvents = dbStatus === 'connected' ? serverEvents : [];

  const handleVerify = async () => {
    setIsVerifying(true);
    try {
      if (dbStatus === 'connected' && projectId) {
        const res = await fetch(`/api/v1/projects/${projectId}/events/verify`);
        if (res.ok) {
          const data: ServerVerifyResponse = await res.json();
          setVerificationResult({
            isValid: data.valid,
            brokenAtSeq: data.broken_at_seq,
            totalEvents: data.count,
            reason: data.valid
              ? `The server recomputed ${data.count} event hash${data.count === 1 ? '' : 'es'} from the first event. Every hash matches its stored fields and links to the previous event. This does not include signatures, which are not connected yet.`
              : `Server detected invalid hash at sequence #${data.broken_at_seq}.`
          });
          return;
        }
      }

      // The server could not run the check. That says nothing about the record, so do not call it tampered.
      setVerificationResult({
        isValid: false,
        brokenAtSeq: null,
        totalEvents: displayEvents.length,
        checkFailed: true,
        reason: 'The server could not run the check, so this record has not been verified either way.'
      });
    } catch (err: any) {
      setVerificationResult({
        isValid: false,
        brokenAtSeq: null,
        totalEvents: 0,
        checkFailed: true,
        reason: err.message
      });
    } finally {
      setIsVerifying(false);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedHash(text);
    setTimeout(() => setCopiedHash(null), 1500);
  };

  const filteredEvents = displayEvents.filter(e => {
    const matchesAction = filterAction === 'all' || e.action === filterAction;
    const matchesQuery =
      e.action.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (e.actor_name && e.actor_name.toLowerCase().includes(searchQuery.toLowerCase())) ||
      JSON.stringify(e.payload).toLowerCase().includes(searchQuery.toLowerCase());
    return matchesAction && matchesQuery;
  });

  // 1. HONEST STATE: Database Not Connected Yet
  if (dbStatus === 'not_connected' || dbStatus === 'error') {
    return (
      <div className="space-y-6">
        {/* Header Banner */}
        <div className="bg-zinc-950 border border-zinc-800 rounded-2xl p-6 shadow-xl flex flex-col md:flex-row md:items-center justify-between gap-5">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-amber-400" />
              <h2 className="text-lg font-bold text-zinc-100 flex items-center gap-2">
                Append-Only Event Log
                <span className="text-[10px] font-mono bg-amber-950 text-amber-300 border border-amber-800/80 px-2 py-0.5 rounded font-semibold">
                  Database Required
                </span>
              </h2>
            </div>
            <p className="text-xs text-zinc-400 leading-relaxed max-w-2xl">
              Custody Core stores every action in an immutable, append-only PostgreSQL table with a database trigger rejecting updates and deletions.
              No events are shown until the database is connected.
            </p>
          </div>

          <div className="flex items-center gap-2 shrink-0">
            <button
              onClick={fetchDbAndEvents}
              disabled={isRefreshing}
              className="bg-zinc-900 hover:bg-zinc-800 text-zinc-300 border border-zinc-700 text-xs font-medium px-4 py-2.5 rounded-xl flex items-center gap-2 transition-colors"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isRefreshing ? 'animate-spin' : ''}`} />
              <span>{isRefreshing ? 'Checking...' : 'Check Connection'}</span>
            </button>
          </div>
        </div>

        {/* Clear Step-by-Step Setup Instructions */}
        <div className="bg-zinc-900/60 border border-amber-900/40 rounded-2xl p-6 space-y-5">
          <div className="flex items-start gap-3">
            <div className="w-10 h-10 rounded-xl bg-amber-500/10 border border-amber-500/20 flex items-center justify-center text-amber-400 shrink-0 mt-0.5">
              <Database className="w-5 h-5" />
            </div>
            <div className="space-y-1">
              <h3 className="text-base font-semibold text-zinc-100">
                Database Not Connected Yet
              </h3>
              <p className="text-xs text-zinc-400 leading-relaxed">
                To activate real event logging and server-side hash chain verification, connect a PostgreSQL database (hosted on Supabase or Neon).
              </p>
            </div>
          </div>

          <div className="bg-zinc-950 border border-zinc-800/80 rounded-xl p-5 space-y-4 text-xs">
            <div className="font-semibold text-zinc-200 flex items-center gap-2">
              <Terminal className="w-4 h-4 text-indigo-400" />
              <span>Supabase Connection Guide:</span>
            </div>

            <ol className="list-decimal list-inside space-y-2.5 text-zinc-300">
              <li>
                Create a new project at <a href="https://database.new" target="_blank" rel="noreferrer" className="text-indigo-400 underline font-mono">database.new</a> (Supabase).
              </li>
              <li>
                In your Supabase Dashboard, go to <strong>Project Settings</strong> &rarr; <strong>Database</strong> &rarr; <strong>Connection string</strong>.
              </li>
              <li>
                Select <strong>URI</strong> mode (use port <strong>5432</strong> or Transaction pooler on <strong>6543</strong>) and copy the connection string:
                <pre className="mt-1.5 p-2.5 bg-zinc-900 rounded-lg font-mono text-[11px] text-emerald-400 border border-zinc-800 overflow-x-auto select-all">
                  postgres://postgres:[YOUR-PASSWORD]@db.[PROJECT-REF].supabase.co:5432/postgres
                </pre>
              </li>
              <li>
                Add <code className="text-amber-300 font-mono">DATABASE_URL</code> to the server's environment or its <code className="text-zinc-300 font-mono">.env</code> file.
              </li>
              <li>
                On start, the server applies any new files in <code className="text-indigo-300 font-mono">server/migrations/</code>, creating the tables and the <code className="text-emerald-300 font-mono">trg_event_append_only</code> trigger.
              </li>
            </ol>
          </div>

          <div className="p-4 bg-zinc-950/70 border border-zinc-800 rounded-xl text-xs text-zinc-400 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Lock className="w-4 h-4 text-emerald-400" />
              <span>Migrations live in <code className="text-zinc-300 font-mono">/server/migrations/</code></span>
            </div>
            <span className="text-[11px] text-zinc-500 font-mono">Append-only trigger</span>
          </div>
        </div>
      </div>
    );
  }

  // 2. CONNECTED STATE: Real Events & Server Hash Chain
  return (
    <div className="space-y-6">
      {/* Top Banner: Verification Engine & Hash Chain Status */}
      <div className="bg-zinc-950 border border-zinc-800 rounded-2xl p-6 shadow-xl flex flex-col md:flex-row md:items-center justify-between gap-5">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-400" />
            <h2 className="text-lg font-bold text-zinc-100 flex items-center gap-2">
              Cryptographic Append-Only Event Log
              <span className="text-[10px] font-mono bg-zinc-800 text-emerald-400 border border-emerald-900/60 px-2 py-0.5 rounded font-semibold">
                PostgreSQL Live
              </span>
            </h2>
          </div>
          <p className="text-xs text-zinc-400 leading-relaxed max-w-2xl">
            Every custody action is linked into an immutable hash chain: <code className="text-zinc-300 font-mono">Hash(n) = SHA-256(all_fields + prev_hash)</code>.
            The hash covers every field (seq, action, timestamp, payload, prev_hash, project_id, actor_type, actor_id, subject_type, subject_id).
            Database triggers reject updates or deletions. Events carry an empty signature field ready for <strong>Seed Signature (Phase 2)</strong>.
          </p>
        </div>

        {/* Verification Controls */}
        <div className="flex flex-wrap items-center gap-2 shrink-0">
          <button
            onClick={fetchDbAndEvents}
            disabled={isRefreshing}
            className="bg-zinc-900 hover:bg-zinc-800 text-zinc-300 border border-zinc-700 text-xs font-medium px-3.5 py-2.5 rounded-xl flex items-center gap-1.5 transition-colors"
            title="Fetch fresh events from server API"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isRefreshing ? 'animate-spin' : ''}`} />
            <span>Sync</span>
          </button>

          <button
            onClick={handleVerify}
            disabled={isVerifying || displayEvents.length === 0}
            className="bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white text-xs font-semibold px-4 py-2.5 rounded-xl flex items-center gap-2 transition-colors shadow-lg shadow-emerald-600/20"
          >
            <ShieldCheck className="w-4 h-4" />
            <span>{isVerifying ? 'Verifying on Server...' : 'Check This Record'}</span>
          </button>
        </div>
      </div>

      {eventsError && (
        <div className="p-4 rounded-xl border bg-rose-950/50 border-rose-800 text-xs text-rose-200">{eventsError}</div>
      )}

      {/* Verification Result Banner */}
      {verificationResult && (
        <div
          className={`p-4 rounded-xl border flex items-start gap-3 text-xs animate-in fade-in duration-150 ${
            verificationResult.isValid
              ? 'bg-emerald-950/40 border-emerald-800 text-emerald-200'
              : verificationResult.checkFailed
              ? 'bg-amber-950/50 border-amber-700 text-amber-200'
              : 'bg-rose-950/60 border-rose-700 text-rose-200'
          }`}
        >
          {verificationResult.isValid ? (
            <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />
          ) : (
            <AlertTriangle className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
          )}

          <div className="space-y-1 flex-1">
            <div className="font-semibold text-sm flex items-center gap-2">
              {verificationResult.isValid ? (
                <>
                  <span>Hash chain verified</span>
                  <span className="text-[10px] bg-emerald-900/80 px-2 py-0.5 rounded text-emerald-300 font-mono">
                    {verificationResult.totalEvents} Blocks Checked
                  </span>
                  <span className="text-[10px] bg-indigo-900/80 px-2 py-0.5 rounded text-indigo-200 font-mono flex items-center gap-1">
                    <Server className="w-3 h-3" /> Server Recomputed
                  </span>
                </>
              ) : verificationResult.checkFailed ? (
                <span>Check could not run</span>
              ) : (
                <>
                  <span>Tamper Detected! Cryptographic Chain Compromised</span>
                  <span className="text-[10px] bg-rose-900 px-2 py-0.5 rounded text-rose-200 font-mono">
                    Break at Event #{verificationResult.brokenAtSeq}
                  </span>
                </>
              )}
            </div>
            <p className="text-[11px] opacity-90 leading-relaxed">
              {verificationResult.reason}
            </p>
          </div>
        </div>
      )}

      {/* Main View: Left List of Events, Right Canonical JSON Inspector */}
      {displayEvents.length === 0 ? (
        <div className="p-12 text-center text-zinc-400 bg-zinc-950 border border-zinc-800 rounded-2xl space-y-3">
          <Database className="w-10 h-10 mx-auto text-zinc-600" />
          <h3 className="font-semibold text-zinc-200 text-sm">No Events in Hash Chain Yet</h3>
          <p className="text-xs text-zinc-500 max-w-md mx-auto">
            This project starts clean. When you claim a project or open a door, the server inserts block #1 starting from 64 zeros and links every subsequent action in a transaction.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Left Column: Event List (7 cols) */}
          <div className="lg:col-span-7 space-y-3">
            {/* Filters Bar */}
            <div className="flex flex-col sm:flex-row gap-2 bg-zinc-950 p-3 rounded-xl border border-zinc-800">
              <div className="relative flex-1">
                <Search className="w-3.5 h-3.5 text-zinc-500 absolute left-3 top-2.5" />
                <input
                  type="text"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder="Search action, actor, or payload..."
                  className="w-full bg-zinc-900 border border-zinc-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-zinc-100 focus:outline-none focus:border-indigo-500"
                />
              </div>

              <select
                value={filterAction}
                onChange={(e) => setFilterAction(e.target.value)}
                className="bg-zinc-900 border border-zinc-800 rounded-lg px-3 py-1.5 text-xs text-zinc-200 focus:outline-none focus:border-indigo-500"
              >
                <option value="all">All Actions ({displayEvents.length})</option>
                <option value="project.claimed">project.claimed</option>
                <option value="repository.locked">repository.locked</option>
                <option value="door.created">door.created</option>
                <option value="agreement.signed">agreement.signed</option>
                <option value="door.opened">door.opened</option>
                <option value="git.fetch">git.fetch</option>
                <option value="git.push">git.push</option>
                <option value="git.push_rejected">git.push_rejected</option>
                <option value="door.work_accepted">door.work_accepted</option>
                <option value="door.closed">door.closed</option>
                <option value="mirror.written">mirror.written</option>
              </select>
            </div>

            {/* Events List */}
            <div className="border border-zinc-800 rounded-2xl overflow-hidden divide-y divide-zinc-800/80 bg-zinc-950">
              {filteredEvents.map((evt) => {
                const isSelected = selectedEvent?.seq === evt.seq;
                return (
                  <div
                    key={evt.seq}
                    onClick={() => setSelectedEvent(evt)}
                    className={`p-4 cursor-pointer transition-colors text-xs ${
                      isSelected
                        ? 'bg-zinc-900/90 border-l-4 border-indigo-500'
                        : 'hover:bg-zinc-900/40'
                    }`}
                  >
                    <div className="flex items-start justify-between gap-3">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-zinc-500 text-[11px] font-bold">
                          #{evt.seq}
                        </span>
                        <span className="font-mono font-semibold text-zinc-100">
                          {evt.action}
                        </span>
                      </div>

                      <span className="text-[10px] text-zinc-500 font-mono">
                        {new Date(evt.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                      </span>
                    </div>

                    <div className="mt-1.5 flex items-center justify-between text-[11px] text-zinc-400">
                      <span className="flex items-center gap-1.5">
                        <span className="text-zinc-500">Actor:</span>
                        <span className="text-zinc-300 capitalize">{evt.actor_name || evt.actor_id} ({evt.actor_type})</span>
                      </span>
                      <span className="font-mono text-zinc-500 text-[10px]">
                        hash: {formatHash(evt.hash, 6, 4)}
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Right Column: Canonical Block & Cryptographic Inspector (5 cols) */}
          <div className="lg:col-span-5 space-y-4">
            {selectedEvent ? (
              <div className="bg-zinc-950 border border-zinc-800 rounded-2xl p-5 space-y-4 sticky top-20 text-xs">
                <div className="flex items-center justify-between border-b border-zinc-800 pb-3">
                  <div className="flex items-center gap-2">
                    <Database className="w-4 h-4 text-indigo-400" />
                    <span className="font-bold text-zinc-100">Block #{selectedEvent.seq} Inspector</span>
                  </div>
                  <span className="font-mono text-[10px] text-zinc-400">
                    {selectedEvent.action}
                  </span>
                </div>

                {/* Hashes & Linkage */}
                <div className="space-y-2.5 bg-zinc-900/80 p-3.5 rounded-xl border border-zinc-800 font-mono text-[11px]">
                  <div>
                    <div className="flex items-center justify-between text-zinc-400 mb-0.5">
                      <span>Current Block SHA-256:</span>
                      <button
                        onClick={() => copyToClipboard(selectedEvent.hash)}
                        className="text-zinc-500 hover:text-zinc-300 flex items-center gap-1 text-[10px]"
                      >
                        {copiedHash === selectedEvent.hash ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      </button>
                    </div>
                    <div className="text-emerald-400 break-all font-semibold select-all">
                      {selectedEvent.hash}
                    </div>
                  </div>

                  <div className="pt-2 border-t border-zinc-800/80">
                    <div className="flex items-center justify-between text-zinc-400 mb-0.5">
                      <span>Previous Block Hash (prev_hash):</span>
                    </div>
                    <div className="text-zinc-400 break-all select-all text-[10px]">
                      {selectedEvent.prev_hash}
                    </div>
                  </div>

                  <div className="pt-2 border-t border-zinc-800/80">
                    <div className="flex items-center justify-between text-zinc-400 mb-0.5">
                      <span>Seed Signature Slot:</span>
                      <span className="text-[10px] text-amber-400 bg-amber-950/80 px-1.5 py-0.2 rounded border border-amber-800/60 font-medium">
                        Phase 1 (Reserved)
                      </span>
                    </div>
                    <div className="text-zinc-500 italic text-[10px]">
                      {selectedEvent.seed_signature_id || '"" (Ready for Phase 2 Seed Signature)'}
                    </div>
                  </div>
                </div>

                {/* Canonical Payload JSON */}
                <div className="space-y-1.5">
                  <div className="flex items-center justify-between text-zinc-400 font-medium">
                    <span>Payload</span>
                    <span className="text-[10px] text-zinc-500 font-mono">As stored</span>
                  </div>
                  <pre className="p-3 bg-zinc-900 border border-zinc-800 rounded-xl overflow-x-auto text-[11px] font-mono text-zinc-300 max-h-64 leading-relaxed">
                    {JSON.stringify(selectedEvent.payload, null, 2)}
                  </pre>
                </div>

                {/* Database Trigger Rules Notice */}
                <div className="p-3 bg-zinc-900/50 border border-zinc-800 rounded-xl text-[11px] text-zinc-400 space-y-1">
                  <div className="font-semibold text-zinc-300 flex items-center gap-1.5">
                    <Lock className="w-3.5 h-3.5 text-amber-400" />
                    PostgreSQL Append-Only Trigger
                  </div>
                  <p className="text-[10px] leading-relaxed">
                    The app's database role can add and read events but is not allowed to change or delete them.
                    The trigger <code className="text-indigo-300">trg_event_append_only</code> raises an exception on any <code className="text-rose-300">UPDATE</code> or <code className="text-rose-300">DELETE</code> attempt.
                  </p>
                </div>
              </div>
            ) : (
              <div className="p-8 text-center text-zinc-500 bg-zinc-950 border border-zinc-800 rounded-2xl text-xs">
                Select an event to inspect its cryptographic block and canonical JSON.
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
