import React, { useEffect, useState } from 'react';
import { Github, Loader2, CheckCircle2, XCircle, AlertCircle, ExternalLink, Unplug } from 'lucide-react';
import { CodeHomeStatus, fetchCodeHome, relockOrganization, startCodeHomeConnection, SettingResult } from '../utils/api';

/** Plain names for the settings GitHub reports. */
export const SETTING_LABELS: Record<string, string> = {
  default_repository_permission: 'Members can see repositories',
  members_can_create_repositories: 'Members can create repositories',
  members_can_create_public_repositories: 'Members can create public repositories',
  members_can_create_private_repositories: 'Members can create private repositories',
  members_can_fork_private_repositories: 'Private repositories can be forked',
  private: 'Private',
  visibility: 'Visibility',
  allow_forking: 'Can be forked'
};

const show = (v: unknown) => (v === null || v === undefined ? 'not reported' : v === false ? 'no' : v === true ? 'yes' : v === 'none' ? 'no' : String(v));

export const SettingsList: React.FC<{ settings: SettingResult[] }> = ({ settings }) => (
  <ul className="space-y-1 text-[11px]">
    {settings.map((s) => (
      <li key={s.setting} className="flex items-center gap-2">
        {s.applied ? <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" /> : <XCircle className="w-3.5 h-3.5 text-rose-400 shrink-0" />}
        <span className="text-zinc-300">{SETTING_LABELS[s.setting] ?? s.setting}:</span>
        <span className={s.applied ? 'text-zinc-200 font-mono' : 'text-rose-300 font-mono'}>{show(s.reported)}</span>
        {!s.applied && <span className="text-zinc-500">(asked for {show(s.requested)})</span>}
      </li>
    ))}
  </ul>
);

const OUTCOMES: Record<string, { ok: boolean; text: string }> = {
  connected: { ok: true, text: 'Your code home is connected and locked.' },
  connected_not_all_locked: { ok: false, text: 'Connected, but GitHub did not apply every lock setting. See below for what GitHub reports.' },
  connected_lock_failed: { ok: false, text: 'Connected, but locking the organization failed. It has been recorded.' },
  expired: { ok: false, text: 'That connection attempt expired or was started in another browser. Start again.' },
  not_installed: { ok: false, text: 'The app was not installed. Start again and choose your organization.' },
  not_yours: { ok: false, text: 'GitHub could not confirm that installation belongs to you.' },
  not_an_organization: { ok: false, text: 'Install the app on an organization, not on your personal account.' },
  not_owner: { ok: false, text: 'Only an owner of the organization can connect it.' },
  app_needs_members_permission: {
    ok: false,
    text: 'GitHub would not confirm that you own this organization, because the Custody Core app is missing the "Members: Read-only" organization permission. The app owner must add it (see the setup guide).'
  },
  linked_elsewhere: { ok: false, text: 'That organization is already connected to another Custody Core account.' },
  already_connected: { ok: false, text: 'You already have a code home connected.' },
  github_error: { ok: false, text: 'GitHub did not answer as expected. Nothing was linked. Try again.' }
};

export const CodeHomePanel: React.FC<{ onChange?: (s: CodeHomeStatus) => void }> = ({ onChange }) => {
  const [status, setStatus] = useState<CodeHomeStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [starting, setStarting] = useState(false);
  const [links, setLinks] = useState<{ install_url: string; new_organization_url: string } | null>(null);
  const [outcome, setOutcome] = useState<string | null>(null);
  const [checking, setChecking] = useState(false);

  const recheck = async () => {
    setChecking(true);
    setError(null);
    try {
      await relockOrganization();
    } catch (e: any) {
      setError(e.message);
    }
    try {
      const s = await fetchCodeHome();
      setStatus(s);
      onChange?.(s);
    } catch (e: any) {
      setError(e.message);
    } finally {
      setChecking(false);
    }
  };

  useEffect(() => {
    // GitHub sends the browser back with ?code_home=<outcome>; show it once and tidy the address bar.
    const params = new URLSearchParams(window.location.search);
    const o = params.get('code_home');
    if (o) {
      setOutcome(o);
      params.delete('code_home');
      const rest = params.toString();
      window.history.replaceState(null, '', window.location.pathname + (rest ? `?${rest}` : ''));
    }
    fetchCodeHome()
      .then((s) => {
        setStatus(s);
        onChange?.(s);
      })
      .catch((e) => setError(e.message));
  }, [onChange]);

  const start = async () => {
    setStarting(true);
    setError(null);
    try {
      setLinks(await startCodeHomeConnection());
    } catch (e: any) {
      setError(e.message);
    } finally {
      setStarting(false);
    }
  };

  const message = outcome ? OUTCOMES[outcome] ?? { ok: false, text: 'Unexpected answer from the connection step.' } : null;
  const inst = status?.installation;
  const working = inst && inst.status === 'active';

  return (
    <div className="bg-zinc-950 border border-zinc-800 rounded-2xl p-5 space-y-3" data-testid="code-home-panel">
      <h3 className="text-xs font-semibold uppercase tracking-wider text-zinc-400 flex items-center gap-1.5">
        <Github className="w-3.5 h-3.5 text-indigo-400" />
        Your code home
      </h3>

      {message && (
        <div role="status" className={`p-3 rounded-lg text-xs border ${message.ok ? 'bg-emerald-950/40 border-emerald-800 text-emerald-200' : 'bg-amber-950/40 border-amber-800 text-amber-200'}`}>
          {message.text}
        </div>
      )}
      {error && <div className="p-3 rounded-lg text-xs border bg-rose-950/50 border-rose-800 text-rose-200">{error}</div>}
      {!status && !error && <div className="text-xs text-zinc-500">Loading...</div>}

      {status && !status.configured && (
        <p className="text-xs text-zinc-400">
          <span className="text-amber-300 font-medium">Not connected yet:</span> the GitHub App has not been set up on this server, so nothing can be
          connected.
        </p>
      )}

      {status?.configured && working && (
        <div className="space-y-2">
          <div className="text-sm text-zinc-200">
            Connected: <span className="font-mono text-indigo-300">{inst!.organization}</span>
            {status.organization_lock?.plan && <span className="text-zinc-500 text-xs"> (GitHub plan: {status.organization_lock.plan})</span>}
          </div>
          {status.organization_lock_failed ? (
            <p className="text-xs text-rose-300" data-testid="org-lock-failed">
              Locking {status.organization_lock_failed.organization} failed on {new Date(status.organization_lock_failed.recorded_at).toLocaleString()} (GitHub said:{' '}
              {status.organization_lock_failed.error.message}). Its settings are not confirmed.
            </p>
          ) : status.organization_lock ? (
            <>
              <p className="text-[11px] text-zinc-500">Organization settings, as GitHub reported them on {new Date(status.organization_lock.recorded_at).toLocaleString()}:</p>
              <SettingsList settings={status.organization_lock.settings} />
            </>
          ) : (
            <p className="text-xs text-amber-300">The organization's settings have not been read back from GitHub.</p>
          )}
          <button onClick={recheck} disabled={checking} className="text-[11px] text-indigo-400 hover:text-indigo-300 flex items-center gap-1.5 disabled:opacity-50">
            {checking && <Loader2 className="w-3 h-3 animate-spin" />}
            Check again with GitHub (and re-apply the lock)
          </button>
        </div>
      )}

      {status?.configured && inst && !working && (
        <div className="p-3 rounded-lg border bg-rose-950/40 border-rose-800 text-xs text-rose-200 space-y-1" data-testid="code-home-broken">
          <div className="flex items-center gap-1.5 font-semibold">
            <Unplug className="w-3.5 h-3.5" /> Connection broken
          </div>
          <div>
            {status.broken
              ? `${status.broken.reason}, ${new Date(status.broken.recorded_at).toLocaleString()}.`
              : `The connection to ${inst.organization} is ${inst.status}.`}{' '}
            Custody Core can no longer act on {inst.organization}, and has made no changes there since.
          </div>
        </div>
      )}

      {status?.configured && (!inst || inst.status === 'removed') && (
        <div className="space-y-3 text-xs text-zinc-300">
          <p className="leading-relaxed">
            Your code will live in a <span className="text-zinc-100 font-medium">GitHub organization that you own</span>. Custody Core only manages it for
            you: it creates private repositories there and locks them, so nobody (including developers you invite later) can copy or overwrite your code.
            You do this once; after that you never need to visit GitHub.
          </p>
          {!links ? (
            <button
              onClick={start}
              disabled={starting}
              className="bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white font-medium px-4 py-2 rounded-lg flex items-center gap-2"
            >
              {starting ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Github className="w-3.5 h-3.5" />}
              Connect your code home
            </button>
          ) : (
            <ol className="space-y-3 list-decimal list-inside">
              <li>
                <span className="text-zinc-200">Create a free GitHub organization</span> (GitHub only lets you do this on its website). Skip this if you already
                have one you want to use.{' '}
                <a href={links.new_organization_url} target="_blank" rel="noreferrer" className="text-indigo-400 hover:text-indigo-300 inline-flex items-center gap-1">
                  Open GitHub <ExternalLink className="w-3 h-3" />
                </a>
              </li>
              <li>
                <span className="text-zinc-200">Install Custody Core on that organization.</span> Choose the organization, then "All repositories", then
                Install, then Authorize. You will come straight back here.{' '}
                <a href={links.install_url} className="text-indigo-400 hover:text-indigo-300 inline-flex items-center gap-1" data-testid="install-link">
                  Install Custody Core <ExternalLink className="w-3 h-3" />
                </a>
              </li>
            </ol>
          )}
          <p className="text-[11px] text-zinc-500 flex items-start gap-1.5">
            <AlertCircle className="w-3.5 h-3.5 shrink-0" />
            Custody Core stores only which installation is yours, never a GitHub password or token.
          </p>
        </div>
      )}
    </div>
  );
};
