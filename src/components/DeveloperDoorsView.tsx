import React, { useEffect, useState } from 'react';
import { FileSignature, KeyRound, AlertCircle, Copy, Check, AlertTriangle } from 'lucide-react';
import {
  acceptInvite,
  DeveloperDoor,
  fetchDeveloperDoors,
  fetchInvite,
  getDoorCredential,
  registerDeveloperKey,
  signDoorAgreement
} from '../utils/api';
import { deviceKey } from '../utils/signingKey';
import { CONSENT_TEXT, SIGNATURE_PURPOSE, canonicalStatement } from '../../shared/agreementStatement';

interface Props {
  email: string;
  pendingInvite: string | null;
  onInviteHandled: () => void;
}

function CopyLine({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="flex items-center gap-2 bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2">
      <code className="flex-1 text-[11px] font-mono text-zinc-200 break-all">{text}</code>
      <button
        type="button"
        onClick={() => {
          void navigator.clipboard?.writeText(text);
          setCopied(true);
          setTimeout(() => setCopied(false), 1500);
        }}
        className="text-zinc-400 hover:text-zinc-100 shrink-0"
      >
        {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
      </button>
    </div>
  );
}

function AgreementText({ text, sha256 }: { text: string; sha256: string | null }) {
  return (
    <div className="space-y-1">
      <pre className="whitespace-pre-wrap text-[11px] leading-relaxed font-mono text-zinc-300 bg-zinc-950 border border-zinc-800 rounded-lg p-3 max-h-72 overflow-y-auto">
        {text}
      </pre>
      {sha256 && <div className="text-[10px] font-mono text-zinc-500 break-all">SHA-256 of this text: {sha256}</div>}
    </div>
  );
}

/** Signing: a key made on this device (private half never leaves it) signs the statement naming this agreement. */
function SignPanel({ door, identity, email, onSigned }: { door: DeveloperDoor; identity: string; email: string; onSigned: () => void }) {
  const [name, setName] = useState('');
  const [consent, setConsent] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const sign = async () => {
    setBusy(true);
    setError(null);
    try {
      const key = await deviceKey();
      await registerDeveloperKey(key.publicKeySpki);
      const statement = canonicalStatement({
        purpose: SIGNATURE_PURPOSE,
        agreement_sha256: door.agreement_sha256!,
        door_id: door.id,
        project_id: door.project_id,
        developer_email: email,
        developer_identity: identity,
        signer_name: name.trim(),
        consent: CONSENT_TEXT,
        signed_at: new Date().toISOString()
      });
      await signDoorAgreement(door.id, statement, await key.sign(statement));
      onSigned();
    } catch (err: any) {
      setError(err.message || 'Signing failed.');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-3">
      <AgreementText text={door.agreement_text ?? ''} sha256={door.agreement_sha256} />
      <label className="block space-y-1">
        <span className="text-xs text-zinc-400">Your full name</span>
        <input value={name} onChange={(e) => setName(e.target.value)} className="w-full bg-zinc-950 border border-zinc-700 rounded-lg px-3 py-2 text-sm text-zinc-100" />
      </label>
      <label className="flex items-start gap-2 text-xs text-zinc-300">
        <input type="checkbox" checked={consent} onChange={(e) => setConsent(e.target.checked)} className="mt-0.5" />
        <span>{CONSENT_TEXT}</span>
      </label>
      <p className="text-[11px] text-zinc-500">
        Signing uses a key made in this browser. Its private half cannot leave this device; only the public half is sent. Your signature,
        this agreement's SHA-256 and the public key go into the project's tamper-evident record, so anyone can check it later.
      </p>
      {error && <div className="text-xs text-rose-300">{error}</div>}
      <button
        disabled={busy || !consent || name.trim().length < 2}
        onClick={sign}
        className="bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white text-xs font-semibold px-4 py-2.5 rounded-xl flex items-center gap-2"
      >
        <FileSignature className="w-4 h-4" />
        {busy ? 'Signing...' : 'Sign with this device'}
      </button>
    </div>
  );
}

function CredentialPanel({ door }: { door: DeveloperDoor }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [issued, setIssued] = useState<{ token: string; remotes: Array<{ url: string }>; prefix: string } | null>(null);

  if (issued) {
    return (
      <div className="space-y-3">
        <div className="flex items-start gap-2 p-3 rounded-lg bg-amber-950/40 border border-amber-800/70 text-amber-200 text-xs">
          <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
          <span>Shown once. Save it in your git credential manager. Getting a new one ends this one.</span>
        </div>
        <div className="text-xs text-zinc-400">Password for git (any user name works):</div>
        <CopyLine text={issued.token} />
        <div className="text-xs text-zinc-400">Clone:</div>
        {issued.remotes.map((r) => (
          <CopyLine key={r.url} text={`git clone ${r.url}`} />
        ))}
        <div className="text-xs text-zinc-400">Push your work (only branches under your door's prefix are accepted, after a secret scan):</div>
        <CopyLine text={`git push origin HEAD:${issued.prefix}my-change`} />
      </div>
    );
  }
  return (
    <div className="space-y-2">
      {door.credential && (
        <p className="text-xs text-zinc-400">
          You have a credential (last used {door.credential.last_used_at ? new Date(door.credential.last_used_at).toLocaleString() : 'never'}). Getting a new
          one ends it.
        </p>
      )}
      {error && <div className="text-xs text-rose-300">{error}</div>}
      <button
        disabled={busy}
        onClick={async () => {
          setBusy(true);
          setError(null);
          try {
            const r = await getDoorCredential(door.id);
            setIssued({ token: r.credential.token, remotes: r.remotes, prefix: r.branch_prefix });
          } catch (err: any) {
            setError(err.message);
          } finally {
            setBusy(false);
          }
        }}
        className="bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white text-xs font-semibold px-4 py-2.5 rounded-xl flex items-center gap-2"
      >
        <KeyRound className="w-4 h-4" />
        {busy ? 'Getting...' : door.credential ? 'Get a new git credential' : 'Get my git credential'}
      </button>
    </div>
  );
}

/** The developer's side: invitations, agreements to sign, and access to open doors. */
export const DeveloperDoorsView: React.FC<Props> = ({ email, pendingInvite, onInviteHandled }) => {
  const [data, setData] = useState<{ identity: string; doors: DeveloperDoor[] } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [invite, setInvite] = useState<any | null>(null);
  const [inviteError, setInviteError] = useState<string | null>(null);

  const load = async () => {
    try {
      const r = await fetchDeveloperDoors();
      setData({ identity: r.developer_identity ?? '', doors: r.doors });
    } catch (err: any) {
      setError(err.message);
    }
  };

  useEffect(() => {
    void load();
  }, []);

  useEffect(() => {
    if (!pendingInvite) return;
    fetchInvite(pendingInvite)
      .then((inv) => (inv.accepted ? onInviteHandled() : setInvite(inv)))
      .catch((err: any) => {
        setInviteError(err.message);
      });
  }, [pendingInvite]);

  return (
    <div className="space-y-6">
      {inviteError && (
        <div className="p-4 rounded-xl bg-rose-950/50 border border-rose-800 text-xs text-rose-200 flex justify-between gap-3">
          <span>{inviteError}</span>
          <button
            onClick={() => {
              setInviteError(null);
              onInviteHandled();
            }}
          >
            Dismiss
          </button>
        </div>
      )}

      {invite && pendingInvite && (
        <div className="bg-zinc-950 border border-indigo-800 rounded-2xl p-6 space-y-4">
          <h2 className="text-lg font-semibold text-zinc-100">Invitation from {invite.door.creator_name}</h2>
          <p className="text-sm text-zinc-300">
            Project <strong>{invite.door.project_name}</strong>: {invite.door.job_description}
          </p>
          <AgreementText text={invite.door.agreement_text} sha256={invite.door.agreement_sha256} />
          <p className="text-xs text-zinc-400">Accepting links this door to your account ({email}). You sign the agreement in the next step.</p>
          <button
            onClick={async () => {
              try {
                await acceptInvite(pendingInvite);
                setInvite(null);
                onInviteHandled();
                await load();
              } catch (err: any) {
                setInviteError(err.message);
              }
            }}
            className="bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold px-4 py-2.5 rounded-xl"
          >
            Accept the invitation
          </button>
        </div>
      )}

      <div className="bg-zinc-950 border border-zinc-800 rounded-2xl p-6 space-y-5">
        <h2 className="text-lg font-semibold text-zinc-100">Doors you were invited to</h2>
        {error && <div className="text-xs text-rose-300">{error}</div>}
        {data && data.doors.length === 0 && (
          <p className="text-sm text-zinc-400">None yet. When a creator invites you, open the link they send you while signed in here.</p>
        )}
        {data?.doors.map((door) => (
          <div key={door.id} className="border border-zinc-800 rounded-xl p-4 space-y-3">
            <div className="flex flex-wrap justify-between gap-2">
              <div>
                <div className="text-sm font-semibold text-zinc-100">
                  {door.project_name}: {door.job_description}
                </div>
                <div className="text-xs text-zinc-400">
                  From {door.creator_name} · access ends {new Date(door.expires_at).toLocaleString()} · {door.repositories.map((r) => r.full_name).join(', ')}
                </div>
              </div>
              <span className="text-[11px] font-mono px-2 py-0.5 rounded-full border border-zinc-700 text-zinc-300 self-start">
                {door.status === 'awaiting_signature' ? 'waiting for your signature' : door.status}
              </span>
            </div>
            {door.status === 'awaiting_signature' && data && (
              <SignPanel door={door} identity={data.identity} email={door.developer_email} onSigned={load} />
            )}
            {door.status === 'open' && (
              <>
                <div className="text-xs text-emerald-300">Signed {door.agreement_signed_at ? new Date(door.agreement_signed_at).toLocaleString() : ''}.</div>
                <CredentialPanel door={door} />
              </>
            )}
          </div>
        ))}
        <div className="flex items-start gap-2 text-xs text-zinc-500 border-t border-zinc-800 pt-4">
          <AlertCircle className="w-3.5 h-3.5 shrink-0 mt-0.5 text-amber-400" />
          <span>Sandboxed workspaces are not connected yet: you work on your own machine, with git pointed at Custody Core.</span>
        </div>
      </div>
    </div>
  );
};
