import React, { useCallback, useEffect, useState } from 'react';
import { Plug, Copy, AlertTriangle } from 'lucide-react';
import {
  WebhookEndpoint, WebhookDelivery, Authority,
  fetchWebhookEndpoints, createWebhookEndpoint, rotateWebhookSecret, setWebhookEnabled, fetchWebhookDeliveries,
  fetchAuthorities, registerAuthority, revokeAuthority
} from '../utils/integrationApi';

const when = (s?: string | null) => (s ? new Date(s).toLocaleString() : '');

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

/** A secret the server shows once. It stays on screen until the owner says they have stored it. */
const SecretNotice: React.FC<{ secret: string; onDone: () => void }> = ({ secret, onDone }) => {
  const [copied, setCopied] = useState(false);
  return (
    <div className="bg-amber-950/40 border border-amber-800 rounded-lg p-3 text-xs space-y-2" role="alert">
      <div className="flex items-start gap-1.5 text-amber-200">
        <AlertTriangle className="w-3.5 h-3.5 shrink-0 mt-px" />
        <span>This is the only time the signing secret is shown. Store it where your receiving service can read it. If you lose it, rotate it.</span>
      </div>
      <code data-testid="webhook-secret" className="block font-mono text-zinc-100 bg-zinc-950 border border-zinc-800 rounded px-2 py-1 break-all select-all">
        {secret}
      </code>
      <div className="flex gap-3">
        <button
          className="text-indigo-300 hover:text-indigo-200 flex items-center gap-1"
          onClick={() => navigator.clipboard?.writeText(secret).then(() => setCopied(true), () => setCopied(false))}
        >
          <Copy className="w-3 h-3" /> {copied ? 'Copied' : 'Copy'}
        </button>
        <button className="text-zinc-300 hover:text-white" onClick={onDone}>
          I have stored it
        </button>
      </div>
    </div>
  );
};

const DELIVERY_STYLE: Record<string, string> = { delivered: 'text-emerald-300', pending: 'text-amber-300', dead: 'text-rose-300' };

const EndpointRow: React.FC<{ endpoint: WebhookEndpoint; onChanged: () => void; onSecret: (s: string) => void }> = ({ endpoint, onChanged, onSecret }) => {
  const [deliveries, setDeliveries] = useState<WebhookDelivery[] | null>(null);
  const [confirmRotate, setConfirmRotate] = useState(false);
  const { busy, error, run } = useAction();
  const d = endpoint.deliveries ?? {};
  return (
    <div className="bg-zinc-950 border border-zinc-800 rounded-xl p-4 space-y-2 text-xs">
      <div className="flex flex-wrap justify-between gap-2">
        <div className="min-w-0">
          <div className="text-sm text-zinc-100 font-medium">{endpoint.name}</div>
          <div className="font-mono text-zinc-400 break-all">{endpoint.url}</div>
        </div>
        <span className={endpoint.status === 'active' ? 'text-emerald-300' : 'text-zinc-500'}>{endpoint.status === 'active' ? 'Active' : 'Disabled'}</span>
      </div>
      <div className="text-zinc-400">
        Sends: <span className="font-mono text-zinc-300">{endpoint.events.join(', ')}</span>
        {endpoint.project_ids?.length ? ` · ${endpoint.project_ids.length} project${endpoint.project_ids.length === 1 ? '' : 's'}` : ' · all projects'}
      </div>
      <div className="text-zinc-500">
        {d.delivered ?? 0} delivered · {d.pending ?? 0} waiting · {d.dead ?? 0} gave up
      </div>
      <div className="flex flex-wrap gap-3 items-center">
        <button disabled={busy} className="text-indigo-400 hover:text-indigo-300" onClick={async () => (await run(() => setWebhookEnabled(endpoint.id, endpoint.status !== 'active'))) && onChanged()}>
          {endpoint.status === 'active' ? 'Disable' : 'Enable'}
        </button>
        {confirmRotate ? (
          <span className="flex gap-2 items-center text-zinc-300">
            The old secret stops working at once.
            <button
              disabled={busy}
              className="text-amber-300 hover:text-amber-200 font-semibold"
              onClick={async () => {
                let out: { secret: string } | null = null;
                if (await run(async () => (out = await rotateWebhookSecret(endpoint.id)))) {
                  setConfirmRotate(false);
                  onSecret(out!.secret);
                  onChanged();
                }
              }}
            >
              Rotate now
            </button>
            <button className="text-zinc-400" onClick={() => setConfirmRotate(false)}>
              Cancel
            </button>
          </span>
        ) : (
          <button className="text-indigo-400 hover:text-indigo-300" onClick={() => setConfirmRotate(true)}>
            Rotate secret
          </button>
        )}
        <button className="text-indigo-400 hover:text-indigo-300" onClick={() => run(async () => setDeliveries(await fetchWebhookDeliveries(endpoint.id)))}>
          {deliveries ? 'Refresh deliveries' : 'Show deliveries'}
        </button>
      </div>
      {error && <div className="text-rose-300" role="alert">{error}</div>}
      {deliveries && (
        <div className="space-y-1 pt-1">
          {deliveries.length === 0 && <div className="text-zinc-500">Nothing sent yet.</div>}
          {deliveries.map((x, i) => (
            <div key={x.id ?? i} className="flex flex-wrap justify-between gap-2 bg-zinc-900 border border-zinc-800 rounded px-2 py-1">
              <span className="font-mono text-zinc-300">{x.event_type}</span>
              <span className={DELIVERY_STYLE[x.status ?? ''] ?? 'text-zinc-400'}>
                {x.status} · {x.attempts} attempt{x.attempts === 1 ? '' : 's'}
                {x.last_status ? ` · last answer ${x.last_status}` : ''}
                {x.last_error ? ` · ${x.last_error}` : ''}
              </span>
              <span className="text-zinc-500">{when(x.created_at)}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

const DEFAULT_EVENTS = 'promotion.*, work_session.*';

const WebhooksSection: React.FC = () => {
  const [endpoints, setEndpoints] = useState<WebhookEndpoint[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [secret, setSecret] = useState<string | null>(null);
  const [form, setForm] = useState({ name: '', url: '', events: DEFAULT_EVENTS });
  const { busy, error: createError, run } = useAction();
  const load = useCallback(() => {
    fetchWebhookEndpoints().then((e) => (setEndpoints(e), setError(null))).catch((e) => setError(e.message));
  }, []);
  useEffect(load, [load]);

  const create = async () => {
    let out: { secret: string } | null = null;
    const events = form.events.split(',').map((e) => e.trim()).filter(Boolean);
    if (await run(async () => (out = await createWebhookEndpoint({ name: form.name.trim(), url: form.url.trim(), events })))) {
      setSecret(out!.secret);
      setForm({ name: '', url: '', events: DEFAULT_EVENTS });
      load();
    }
  };

  return (
    <section className="space-y-3" aria-label="Webhooks">
      <div>
        <h3 className="text-sm font-semibold text-zinc-100">Webhooks</h3>
        <p className="text-xs text-zinc-400 max-w-2xl">
          Custody Core posts a signed message to an https address you choose when something happens (for example <span className="font-mono">promotion.completed</span>). Receivers should verify the signature with the secret shown at creation.
        </p>
      </div>
      {secret && <SecretNotice secret={secret} onDone={() => setSecret(null)} />}
      {error && <div className="text-xs text-rose-300" role="alert">{error}</div>}
      {endpoints?.length === 0 && <p className="text-xs text-zinc-500">No endpoints yet.</p>}
      {endpoints?.map((e) => <EndpointRow key={e.id} endpoint={e} onChanged={load} onSecret={setSecret} />)}
      <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-3 space-y-2 text-xs">
        <div className="font-semibold text-zinc-300">Add an endpoint</div>
        <input aria-label="Endpoint name" placeholder="Name" className="w-full bg-zinc-950 border border-zinc-700 rounded px-2 py-1" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
        <input aria-label="Endpoint address" placeholder="https://example.com/hooks/custody" className="w-full bg-zinc-950 border border-zinc-700 rounded px-2 py-1 font-mono" value={form.url} onChange={(e) => setForm({ ...form, url: e.target.value })} />
        <input aria-label="Events" className="w-full bg-zinc-950 border border-zinc-700 rounded px-2 py-1 font-mono" value={form.events} onChange={(e) => setForm({ ...form, events: e.target.value })} />
        <div className="text-zinc-500">Events: names such as promotion.completed, families such as promotion.*, or * for everything. Separate with commas.</div>
        {createError && <div className="text-rose-300" role="alert">{createError}</div>}
        <button disabled={busy || !form.name.trim() || !form.url.trim()} className="bg-indigo-600 hover:bg-indigo-500 disabled:opacity-40 text-white font-semibold px-3 py-1.5 rounded" onClick={create}>
          {busy ? 'Creating...' : 'Create endpoint'}
        </button>
      </div>
    </section>
  );
};

const AuthoritiesSection: React.FC = () => {
  const [authorities, setAuthorities] = useState<Authority[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [form, setForm] = useState({ name: '', key: '' });
  const [confirmId, setConfirmId] = useState<string | null>(null);
  const { busy, error: actionError, run } = useAction();
  const load = useCallback(() => {
    fetchAuthorities().then((a) => (setAuthorities(a), setError(null))).catch((e) => setError(e.message));
  }, []);
  useEffect(load, [load]);

  const register = async () => {
    let key: unknown;
    try {
      key = JSON.parse(form.key);
    } catch {
      return void run(async () => {
        throw new Error('The public key must be a JSON Web Key, for example {"kty":"OKP","crv":"Ed25519","x":"..."}.');
      });
    }
    if (await run(() => registerAuthority(form.name.trim(), key))) {
      setForm({ name: '', key: '' });
      load();
    }
  };

  return (
    <section className="space-y-3" aria-label="Signing authorities">
      <div>
        <h3 className="text-sm font-semibold text-zinc-100">Signing authorities</h3>
        <p className="text-xs text-zinc-400 max-w-2xl">
          A signing authority is a reviewer or service whose signed statements about a session's commits you are willing to count. You register its public key; Custody Core never holds its private key.
        </p>
      </div>
      {error && <div className="text-xs text-rose-300" role="alert">{error}</div>}
      {authorities?.length === 0 && <p className="text-xs text-zinc-500">None registered.</p>}
      {authorities?.map((a) => (
        <div key={a.id} className="bg-zinc-950 border border-zinc-800 rounded-xl p-3 text-xs space-y-1">
          <div className="flex justify-between gap-2">
            <span className="text-sm text-zinc-100 font-medium">{a.name}</span>
            <span className={a.revoked_at ? 'text-zinc-500' : 'text-emerald-300'}>{a.revoked_at ? `Revoked ${when(a.revoked_at)}` : 'Active'}</span>
          </div>
          <div className="text-zinc-500">{a.algorithm} · key fingerprint <span className="font-mono">{a.fingerprint?.slice(0, 16)}</span></div>
          {!a.revoked_at &&
            (confirmId === a.id ? (
              <div className="flex gap-2 items-center text-zinc-300">
                Its statements stop counting from now on, and cannot be re-enabled.
                <button disabled={busy} className="text-rose-300 font-semibold" onClick={async () => (await run(() => revokeAuthority(a.id))) && (setConfirmId(null), load())}>
                  Revoke
                </button>
                <button className="text-zinc-400" onClick={() => setConfirmId(null)}>
                  Cancel
                </button>
              </div>
            ) : (
              <button className="text-rose-300 hover:text-rose-200" onClick={() => setConfirmId(a.id)}>
                Revoke
              </button>
            ))}
        </div>
      ))}
      <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-3 space-y-2 text-xs">
        <div className="font-semibold text-zinc-300">Register an authority</div>
        <input aria-label="Authority name" placeholder="Name (for example Security reviewer)" className="w-full bg-zinc-950 border border-zinc-700 rounded px-2 py-1" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
        <textarea aria-label="Public key" rows={3} placeholder='Public key as JSON: {"kty":"OKP","crv":"Ed25519","x":"..."}' className="w-full bg-zinc-950 border border-zinc-700 rounded px-2 py-1 font-mono" value={form.key} onChange={(e) => setForm({ ...form, key: e.target.value })} />
        {actionError && <div className="text-rose-300" role="alert">{actionError}</div>}
        <button disabled={busy || !form.name.trim() || !form.key.trim()} className="bg-indigo-600 hover:bg-indigo-500 disabled:opacity-40 text-white font-semibold px-3 py-1.5 rounded" onClick={register}>
          Register
        </button>
      </div>
    </section>
  );
};

export const IntegrationsView: React.FC = () => (
  <div className="space-y-8">
    <div>
      <h2 className="text-lg font-semibold text-white flex items-center gap-2">
        <Plug className="w-5 h-5 text-indigo-400" /> Integrations
      </h2>
      <p className="text-xs text-zinc-400 mt-1">These belong to your account and apply across your projects.</p>
    </div>
    <WebhooksSection />
    <AuthoritiesSection />
  </div>
);

export default IntegrationsView;
