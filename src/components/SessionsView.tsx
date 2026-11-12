import React, { useCallback, useEffect, useState } from 'react';
import { GitPullRequest, AlertTriangle, CheckCircle2, XCircle } from 'lucide-react';
import {
  WorkSession, EvidenceReport, Contribution, Attestation, Promotion, Authority,
  fetchWorkSessions, approveWorkSession, rejectWorkSession, fetchEvidence, fetchAttribution, fetchAttestations, deliverAttestation, attestationStatementToSign,
  fetchSessionPromotions, requestPromotion, approvePromotion, rejectPromotion, fetchAuthorities
} from '../utils/integrationApi';

const STATUS_STYLE: Record<string, string> = {
  requested: 'bg-amber-950/60 text-amber-300 border-amber-800',
  approved: 'bg-sky-950/60 text-sky-300 border-sky-800',
  provisioning: 'bg-sky-950/60 text-sky-300 border-sky-800',
  active: 'bg-emerald-950/60 text-emerald-300 border-emerald-800',
  awaiting_evidence: 'bg-indigo-950/60 text-indigo-300 border-indigo-800',
  completed: 'bg-zinc-800 text-zinc-300 border-zinc-700',
  rejected: 'bg-rose-950/60 text-rose-300 border-rose-800',
  closed: 'bg-zinc-800 text-zinc-400 border-zinc-700',
  expired: 'bg-zinc-800 text-zinc-400 border-zinc-700'
};
const STATUS_TEXT: Record<string, string> = {
  requested: 'Waiting for your approval',
  approved: 'Approved',
  provisioning: 'Being set up',
  active: 'Running',
  awaiting_evidence: 'Waiting for evidence',
  completed: 'Completed',
  rejected: 'Rejected',
  closed: 'Closed',
  expired: 'Expired'
};
const PROMOTION_STATUS_TEXT: Record<string, string> = {
  pending: 'Waiting for your approval',
  approved: 'Approved, moving the branch',
  completed: 'Done: the default branch moved',
  rejected: 'Rejected',
  failed: 'Did not happen'
};
const FAILURE_TEXT: Record<string, string> = {
  session_not_running: 'The session is no longer running.',
  evidence_not_ready: 'The evidence was no longer ready when the branch was about to move.',
  provider_unavailable: 'The repository host could not be reached or refused access.',
  default_branch_changed: 'The default branch is no longer the one this session started from.',
  commit_missing: 'The gateway no longer holds that commit.',
  not_fast_forward: 'The commit would not be a straight continuation of the default branch.'
};

const short = (s?: string | null) => (s ? s.slice(0, 8) : '');
const when = (s?: string | null) => (s ? new Date(s).toLocaleString() : '');

export const StatusBadge: React.FC<{ status: string; texts?: Record<string, string> }> = ({ status, texts = STATUS_TEXT }) => (
  <span className={`text-[10px] font-semibold uppercase tracking-wider px-2 py-0.5 rounded border ${STATUS_STYLE[status] ?? STATUS_STYLE.closed}`}>{texts[status] ?? status}</span>
);

/** Runs an action, showing its failure as text. */
function useAction() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const run = useCallback(async (fn: () => Promise<unknown>) => {
    setBusy(true);
    setError(null);
    try {
      await fn();
      return true;
    } catch (e: any) {
      setError(e?.message ?? String(e));
      return false;
    } finally {
      setBusy(false);
    }
  }, []);
  return { busy, error, run };
}

// --- Evidence ----------------------------------------------------------------------------------------------------

const REQ_STATE_TEXT: Record<string, string> = {
  satisfied: 'Met',
  failed: 'Failed',
  inconclusive: 'Inconclusive',
  missing: 'Not delivered yet',
  stale: 'Too old',
  issuer_unavailable: 'Its issuer or key was revoked'
};

const EvidencePanel: React.FC<{ report: EvidenceReport | null; session: WorkSession }> = ({ report, session }) => {
  const reqs = session.evidence_requirements ?? [];
  return (
    <section className="space-y-2" aria-label="Evidence">
      <h4 className="text-xs font-semibold uppercase tracking-wider text-zinc-400">Evidence</h4>
      {reqs.length === 0 && <p className="text-xs text-zinc-500">This session was started with no evidence requirements, so nothing gates a promotion.</p>}
      {reqs.map((r, i) => {
        const ev = report?.evaluation?.requirements?.find((x) => x.evidence_type === r.type && x.issuer_principal_id === r.issuer_principal_id);
        return (
          <div key={i} className="bg-zinc-900 border border-zinc-800 rounded px-2.5 py-2 text-xs space-y-1">
            <div className="flex justify-between gap-2">
              <span className="font-mono text-zinc-200">{r.type}</span>
              <span className={ev?.state === 'satisfied' ? 'text-emerald-300' : 'text-zinc-400'}>{ev ? REQ_STATE_TEXT[ev.state ?? ''] ?? ev.state : 'No commit pushed yet'}</span>
            </div>
            <div className="text-zinc-500">
              {r.required ? 'Required' : 'Optional'} · issuer {short(r.issuer_principal_id)} · {r.tied_to_commit ? 'tied to the exact commit' : 'any commit'}
            </div>
            {r.issuer_is_requester && (
              <div className="flex items-start gap-1.5 text-amber-300" role="alert">
                <AlertTriangle className="w-3.5 h-3.5 shrink-0 mt-px" />
                <span>The requester is also the one who issues this evidence. The same system is checking its own work.</span>
              </div>
            )}
          </div>
        );
      })}
      {report?.evaluation && (
        <p className={`text-xs font-medium ${report.evaluation.ready ? 'text-emerald-300' : 'text-amber-300'}`}>
          {report.evaluation.ready ? `Ready for commit ${short(report.evaluation.commit)}` : 'Not ready: required evidence is missing or failed.'}
        </p>
      )}
    </section>
  );
};

// --- Attribution -------------------------------------------------------------------------------------------------

const AttributionPanel: React.FC<{ items: Contribution[] | null }> = ({ items }) => (
  <section className="space-y-2" aria-label="Attribution">
    <h4 className="text-xs font-semibold uppercase tracking-wider text-zinc-400">Who wrote what</h4>
    {items && items.length === 0 && <p className="text-xs text-zinc-500">Nothing pushed yet.</p>}
    {items?.map((c, i) => (
      <div key={i} className="bg-zinc-900 border border-zinc-800 rounded px-2.5 py-2 text-xs space-y-0.5">
        <div className="font-mono text-zinc-200">{short(c.commit)}</div>
        <div className="text-zinc-400">
          Author: {String(c.author?.executor?.display_name ?? c.author?.executor?.type ?? c.author?.kind ?? 'unknown')} (set by the gateway, not by the commit)
        </div>
        {c.declared_author?.value && <div className="text-zinc-500">The commit claims: {c.declared_author.value} (not trusted)</div>}
      </div>
    ))}
  </section>
);

// --- Attestations --------------------------------------------------------------------------------------------------

const AttestationPanel: React.FC<{ projectId: string; session: WorkSession; items: Attestation[] | null; onChanged: () => void }> = ({ projectId, session, items, onChanged }) => {
  const [authorities, setAuthorities] = useState<Authority[]>([]);
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState({ authority_id: '', claim: '', subject_commit: '', issued_at: new Date().toISOString().replace(/\.\d+Z$/, 'Z'), payload: '', signature: '' });
  const [statement, setStatement] = useState('');
  const { busy, error, run } = useAction();
  const [formError, setFormError] = useState<string | null>(null);

  useEffect(() => {
    if (open) fetchAuthorities().then((a) => setAuthorities(a.filter((x) => !x.revoked_at))).catch(() => setAuthorities([]));
  }, [open]);

  useEffect(() => {
    let cancelled = false;
    setFormError(null);
    if (!form.authority_id || !form.claim || !/^[0-9a-f]{40}$/.test(form.subject_commit)) return setStatement('');
    let payload: Record<string, unknown> | undefined;
    try {
      payload = form.payload.trim() ? JSON.parse(form.payload) : undefined;
      if (payload !== undefined && (typeof payload !== 'object' || payload === null || Array.isArray(payload))) throw new Error('not an object');
    } catch {
      setFormError('The payload must be a JSON object, or empty.');
      return setStatement('');
    }
    attestationStatementToSign({ authority_id: form.authority_id, work_session_id: session.id, claim: form.claim, subject_commit: form.subject_commit, issued_at: form.issued_at, payload })
      .then((s) => !cancelled && setStatement(s))
      .catch(() => !cancelled && setStatement(''));
    return () => {
      cancelled = true;
    };
  }, [form.authority_id, form.claim, form.subject_commit, form.issued_at, form.payload, session.id]);

  const authority = authorities.find((a) => a.id === form.authority_id);
  const submit = async () => {
    const ok = await run(async () => {
      await deliverAttestation(projectId, session.id, {
        authority_id: form.authority_id,
        claim: form.claim,
        subject_commit: form.subject_commit,
        issued_at: form.issued_at,
        ...(form.payload.trim() ? { payload: JSON.parse(form.payload) } : {}),
        signature: { algorithm: (authority?.algorithm as 'Ed25519' | 'ES256') ?? 'Ed25519', value: form.signature.trim() }
      });
    });
    if (ok) {
      setOpen(false);
      setForm({ ...form, signature: '' });
      onChanged();
    }
  };

  return (
    <section className="space-y-2" aria-label="Attestations">
      <div className="flex items-center justify-between">
        <h4 className="text-xs font-semibold uppercase tracking-wider text-zinc-400">Attestations</h4>
        <button className="text-xs text-indigo-400 hover:text-indigo-300" onClick={() => setOpen(!open)}>
          {open ? 'Cancel' : 'Deliver an attestation'}
        </button>
      </div>
      {items && items.length === 0 && <p className="text-xs text-zinc-500">None delivered.</p>}
      {items?.map((a) => (
        <div key={a.id} className="bg-zinc-900 border border-zinc-800 rounded px-2.5 py-2 text-xs flex flex-wrap justify-between gap-1">
          <span className="font-mono text-zinc-200">{a.claim}</span>
          <span className="text-zinc-400">
            by {a.authority?.name ?? short(a.authority?.id)}
            {a.authority?.active === false ? ' (revoked since)' : ''} · commit {short(a.subject_commit)}
          </span>
        </div>
      ))}
      {open && (
        <div className="bg-zinc-900 border border-zinc-800 rounded p-3 space-y-2 text-xs">
          <p className="text-zinc-400">
            An attestation is a statement a signing authority you registered has signed. Sign the text shown below with that authority's key, then paste the signature.
          </p>
          <label className="block">
            <span className="text-zinc-400">Authority</span>
            <select className="mt-1 w-full bg-zinc-950 border border-zinc-700 rounded px-2 py-1" value={form.authority_id} onChange={(e) => setForm({ ...form, authority_id: e.target.value })}>
              <option value="">Choose...</option>
              {authorities.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.name} ({a.algorithm})
                </option>
              ))}
            </select>
          </label>
          <label className="block">
            <span className="text-zinc-400">Claim (for example security_review.passed)</span>
            <input className="mt-1 w-full bg-zinc-950 border border-zinc-700 rounded px-2 py-1 font-mono" value={form.claim} onChange={(e) => setForm({ ...form, claim: e.target.value })} />
          </label>
          <label className="block">
            <span className="text-zinc-400">Commit (full 40-character id)</span>
            <input className="mt-1 w-full bg-zinc-950 border border-zinc-700 rounded px-2 py-1 font-mono" value={form.subject_commit} onChange={(e) => setForm({ ...form, subject_commit: e.target.value.trim() })} />
          </label>
          <label className="block">
            <span className="text-zinc-400">Issued at (UTC, whole seconds)</span>
            <input className="mt-1 w-full bg-zinc-950 border border-zinc-700 rounded px-2 py-1 font-mono" value={form.issued_at} onChange={(e) => setForm({ ...form, issued_at: e.target.value.trim() })} />
          </label>
          <label className="block">
            <span className="text-zinc-400">Payload (JSON object, optional)</span>
            <textarea className="mt-1 w-full bg-zinc-950 border border-zinc-700 rounded px-2 py-1 font-mono" rows={2} value={form.payload} onChange={(e) => setForm({ ...form, payload: e.target.value })} />
          </label>
          {statement && (
            <div>
              <div className="text-zinc-400">Text to sign (the exact bytes, UTF-8)</div>
              <code data-testid="statement" className="block mt-1 bg-zinc-950 border border-zinc-800 rounded px-2 py-1 font-mono text-[11px] text-zinc-300 break-all select-all">
                {statement}
              </code>
            </div>
          )}
          <label className="block">
            <span className="text-zinc-400">Signature (base64url, 64 bytes)</span>
            <input className="mt-1 w-full bg-zinc-950 border border-zinc-700 rounded px-2 py-1 font-mono" value={form.signature} onChange={(e) => setForm({ ...form, signature: e.target.value })} />
          </label>
          {(formError || error) && <div className="text-rose-300" role="alert">{formError || error}</div>}
          <button
            disabled={busy || !statement || !form.signature.trim()}
            onClick={submit}
            className="bg-indigo-600 hover:bg-indigo-500 disabled:opacity-40 text-white font-semibold px-3 py-1.5 rounded"
          >
            {busy ? 'Checking...' : 'Record attestation'}
          </button>
        </div>
      )}
    </section>
  );
};

// --- Promotions ----------------------------------------------------------------------------------------------------

const PromotionPanel: React.FC<{ projectId: string; session: WorkSession; items: Promotion[] | null; onChanged: () => void }> = ({ projectId, session, items, onChanged }) => {
  const [commit, setCommit] = useState('');
  const [reason, setReason] = useState('');
  const [confirmId, setConfirmId] = useState<string | null>(null);
  const { busy, error, run } = useAction();
  const running = session.status === 'active' || session.status === 'awaiting_evidence';
  return (
    <section className="space-y-2" aria-label="Promotions">
      <h4 className="text-xs font-semibold uppercase tracking-wider text-zinc-400">Promotion to the default branch</h4>
      {items && items.length === 0 && <p className="text-xs text-zinc-500">No promotion requested.</p>}
      {items?.map((p) => (
        <div key={p.id} className="bg-zinc-900 border border-zinc-800 rounded px-2.5 py-2 text-xs space-y-1.5">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <span className="font-mono text-zinc-200">
              {short(p.commit)} → {p.target_branch ?? 'default branch'}
            </span>
            <StatusBadge status={p.status} texts={PROMOTION_STATUS_TEXT} />
          </div>
          {p.status === 'failed' && <div className="text-rose-300">{FAILURE_TEXT[p.failure_code ?? ''] ?? p.failure_code ?? 'It failed.'}</div>}
          {p.status === 'rejected' && p.rejected_reason && <div className="text-zinc-400">Reason: {p.rejected_reason}</div>}
          {p.status === 'completed' && <div className="text-zinc-500">Previous tip {short(p.previous_tip)}. Moved {when(p.completed_at)}.</div>}
          {p.status === 'pending' && (
            <div className="space-y-2 pt-1">
              {confirmId === p.id ? (
                <div className="space-y-2">
                  <div className="flex items-start gap-1.5 text-amber-300" role="alert">
                    <AlertTriangle className="w-3.5 h-3.5 shrink-0 mt-px" />
                    <span>Approving moves the repository's default branch to this commit, on GitHub, straight away. Only you can do this, and it cannot be undone from here.</span>
                  </div>
                  <div className="flex gap-2">
                    <button disabled={busy} className="bg-emerald-700 hover:bg-emerald-600 disabled:opacity-50 text-white font-semibold px-3 py-1.5 rounded" onClick={async () => (await run(() => approvePromotion(projectId, p.id))) && (setConfirmId(null), onChanged())}>
                      {busy ? 'Moving...' : 'Move the default branch'}
                    </button>
                    <button className="text-zinc-400 px-3 py-1.5" onClick={() => setConfirmId(null)}>
                      Cancel
                    </button>
                  </div>
                </div>
              ) : (
                <div className="flex flex-wrap gap-2 items-center">
                  <button className="bg-emerald-800 hover:bg-emerald-700 text-white px-3 py-1.5 rounded font-medium" onClick={() => setConfirmId(p.id)}>
                    Approve
                  </button>
                  <input aria-label="Reason for rejecting" placeholder="Reason (optional)" className="bg-zinc-950 border border-zinc-700 rounded px-2 py-1" value={reason} onChange={(e) => setReason(e.target.value)} />
                  <button disabled={busy} className="text-rose-300 hover:text-rose-200" onClick={async () => (await run(() => rejectPromotion(projectId, p.id, reason))) && (setReason(''), onChanged())}>
                    Reject
                  </button>
                </div>
              )}
            </div>
          )}
        </div>
      ))}
      {running && (
        <div className="flex flex-wrap gap-2 items-center text-xs pt-1">
          <input aria-label="Commit to promote" placeholder="Commit (blank: the newest)" className="bg-zinc-950 border border-zinc-700 rounded px-2 py-1 font-mono w-64" value={commit} onChange={(e) => setCommit(e.target.value.trim())} />
          <button disabled={busy} className="bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white font-semibold px-3 py-1.5 rounded" onClick={async () => (await run(() => requestPromotion(projectId, session.id, commit || undefined))) && (setCommit(''), onChanged())}>
            Request a promotion
          </button>
        </div>
      )}
      {error && <div className="text-xs text-rose-300" role="alert">{error}</div>}
    </section>
  );
};

// --- A session ---------------------------------------------------------------------------------------------------------

const SessionDetail: React.FC<{ projectId: string; session: WorkSession; onChanged: () => void }> = ({ projectId, session, onChanged }) => {
  const [evidence, setEvidence] = useState<EvidenceReport | null>(null);
  const [attribution, setAttribution] = useState<Contribution[] | null>(null);
  const [attestations, setAttestations] = useState<Attestation[] | null>(null);
  const [promotions, setPromotions] = useState<Promotion[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => {
    Promise.all([fetchEvidence(projectId, session.id), fetchAttribution(projectId, session.id), fetchAttestations(projectId, session.id), fetchSessionPromotions(projectId, session.id)])
      .then(([e, a, t, p]) => {
        setEvidence(e);
        setAttribution(a);
        setAttestations(t);
        setPromotions(p);
        setError(null);
      })
      .catch((e) => setError(e.message));
  }, [projectId, session.id]);
  useEffect(load, [load]);
  const reload = () => {
    load();
    onChanged();
  };

  const access = session.access;
  return (
    <div className="space-y-4 pt-3 border-t border-zinc-800 mt-3">
      {error && <div className="text-xs text-rose-300" role="alert">{error}</div>}
      <div className="grid sm:grid-cols-2 gap-3 text-xs">
        <div className="space-y-1">
          <h4 className="font-semibold uppercase tracking-wider text-zinc-400">What it may touch</h4>
          <div className="text-zinc-300">{access?.repository === 'read_and_push' ? 'Read and push' : 'Read only'}</div>
          <PathList label="Read" paths={access?.allowed_read_paths} />
          <PathList label="Write" paths={access?.allowed_write_paths} />
          <PathList label="Never" paths={access?.prohibited_paths} />
        </div>
        <div className="space-y-1 text-zinc-400">
          <h4 className="font-semibold uppercase tracking-wider text-zinc-400">Context it came with</h4>
          {session.external_context ? (
            <pre className="whitespace-pre-wrap break-words bg-zinc-900 border border-zinc-800 rounded p-2 text-[11px] text-zinc-300" data-testid="external-context">
              {JSON.stringify(session.external_context, null, 2)}
            </pre>
          ) : (
            <span className="text-zinc-500">None.</span>
          )}
          <p className="text-[11px] text-zinc-500">Shown as plain text. It was written by the requester, so treat it as a claim, not as fact.</p>
        </div>
      </div>
      <EvidencePanel report={evidence} session={session} />
      <AttributionPanel items={attribution} />
      <AttestationPanel projectId={projectId} session={session} items={attestations} onChanged={reload} />
      <PromotionPanel projectId={projectId} session={session} items={promotions} onChanged={reload} />
    </div>
  );
};

const PathList: React.FC<{ label: string; paths?: string[] }> = ({ label, paths }) =>
  paths && paths.length > 0 ? (
    <div className="text-zinc-400">
      {label}: <span className="font-mono text-zinc-300">{paths.join(', ')}</span>
    </div>
  ) : null;

const SessionRow: React.FC<{ projectId: string; session: WorkSession; onChanged: () => void }> = ({ projectId, session, onChanged }) => {
  const [open, setOpen] = useState(session.status === 'requested');
  const [reason, setReason] = useState('');
  const { busy, error, run } = useAction();
  const ex = session.executor;
  return (
    <div className="bg-zinc-950 border border-zinc-800 rounded-xl p-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <button className="text-left space-y-1 flex-1 min-w-0" onClick={() => setOpen(!open)} aria-expanded={open}>
          <div className="text-sm text-zinc-100 font-medium break-words">{session.objective || 'No objective given'}</div>
          <div className="text-xs text-zinc-500">
            {ex?.display_name || ex?.provider || ex?.type || 'automated executor'}
            {ex?.model ? ` · ${ex.model}` : ''} · requested {when(session.created_at)}
          </div>
        </button>
        <StatusBadge status={session.status} />
      </div>
      {session.status === 'requested' && (
        <div className="flex flex-wrap items-center gap-2 mt-3 text-xs">
          <button disabled={busy} className="bg-emerald-700 hover:bg-emerald-600 disabled:opacity-50 text-white font-semibold px-3 py-1.5 rounded-lg flex items-center gap-1" onClick={async () => (await run(() => approveWorkSession(projectId, session.id))) && onChanged()}>
            <CheckCircle2 className="w-3.5 h-3.5" /> Approve
          </button>
          <input aria-label="Reason for rejecting" placeholder="Reason (optional)" className="bg-zinc-900 border border-zinc-700 rounded px-2 py-1.5" value={reason} onChange={(e) => setReason(e.target.value)} />
          <button disabled={busy} className="text-rose-300 hover:text-rose-200 flex items-center gap-1 px-2 py-1.5" onClick={async () => (await run(() => rejectWorkSession(projectId, session.id, reason))) && onChanged()}>
            <XCircle className="w-3.5 h-3.5" /> Reject
          </button>
          {error && <span className="text-rose-300" role="alert">{error}</span>}
        </div>
      )}
      {session.status === 'rejected' && session.closed_reason && <div className="text-xs text-zinc-400 mt-2">Reason: {session.closed_reason}</div>}
      {open && <SessionDetail projectId={projectId} session={session} onChanged={onChanged} />}
    </div>
  );
};

export const SessionsView: React.FC<{ projectId: string; onCountChange?: (waiting: number) => void }> = ({ projectId, onCountChange }) => {
  const [sessions, setSessions] = useState<WorkSession[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const load = useCallback(() => {
    fetchWorkSessions(projectId)
      .then((s) => {
        const automated = s.filter((x) => x.session_type !== 'human_door');
        setSessions(automated);
        onCountChange?.(automated.filter((x) => x.status === 'requested').length);
        setError(null);
      })
      .catch((e) => setError(e.message));
  }, [projectId, onCountChange]);
  useEffect(load, [load]);

  return (
    <div className="space-y-4">
      <div>
        <h2 className="text-lg font-semibold text-white flex items-center gap-2">
          <GitPullRequest className="w-5 h-5 text-indigo-400" /> Work sessions
        </h2>
        <p className="text-xs text-zinc-400 mt-1 max-w-2xl">
          Automated systems (AI assistants, build systems, other services) ask here for a limited view of a repository. Nothing starts until you approve it, and nothing reaches
          your default branch until you approve that too.
        </p>
      </div>
      {error && <div className="text-xs text-rose-300 bg-rose-950/40 border border-rose-900 rounded p-3" role="alert">{error}</div>}
      {sessions === null && !error && <p className="text-xs text-zinc-500">Loading...</p>}
      {sessions && sessions.length === 0 && <p className="text-xs text-zinc-500 bg-zinc-950 border border-zinc-800 rounded-xl p-6 text-center">No automated sessions have been requested for this project.</p>}
      {sessions?.map((s) => <SessionRow key={s.id} projectId={projectId} session={s} onChanged={load} />)}
    </div>
  );
};

export default SessionsView;
