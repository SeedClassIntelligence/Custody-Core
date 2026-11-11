// @vitest-environment jsdom
import React from 'react';
import crypto from 'node:crypto';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { canonicalJsonV2 } from '../shared/crypto';
import { checkRequest, checkResponse, findOperation } from './support/openapiCheck';

/**
 * The owner screens, driven the way a person drives them. The network is replaced by a small in-memory server, and every request the screens make
 * and every answer the stand-in gives is checked against docs/openapi.json, so a screen cannot ask for something the API does not offer and the
 * stand-in cannot drift from what the real server says.
 */

const calls: Array<{ method: string; path: string; body: unknown }> = [];
let handler: (method: string, path: string, body: any) => { status: number; body: any };

vi.mock('../src/auth/supabase', () => ({
  authFetch: async (input: string, init: RequestInit = {}) => {
    const method = (init.method ?? 'GET').toUpperCase();
    const url = new URL(input, 'http://x');
    const body = init.body ? JSON.parse(String(init.body)) : undefined;
    calls.push({ method, path: url.pathname + url.search, body });
    const op = findOperation(method, url.pathname);
    // The backup routes are owner-only and are not (yet) in the API description; they are the only calls allowed to be missing from it.
    if (!op && /^\/api\/v1\/projects\/[^/]+\/snapshots(\/|$)/.test(url.pathname)) return respond(handler(method, url.pathname, body));
    if (!op) throw new Error(`The screen called ${method} ${url.pathname}, which is not in the API description.`);
    const reqProblems = checkRequest(op, body);
    if (reqProblems.length) throw new Error(reqProblems.join('; '));
    const out = handler(method, url.pathname, body);
    if (out.status < 400) {
      const resProblems = checkResponse(op, out.status, out.body);
      if (resProblems.length) throw new Error(`The stand-in server answered off-spec: ${resProblems.join('; ')}`);
    }
    return respond(out);
  }
}));

function respond(out: { status: number; body: any }) {
  return new Response(JSON.stringify(out.body), { status: out.status, headers: { 'Content-Type': 'application/json' } });
}

import { SessionsView } from '../src/components/SessionsView';
import { IntegrationsView } from '../src/components/IntegrationsView';
import { SnapshotSection } from '../src/components/DoorDetailsView';

const PROJECT = '11111111-1111-4111-8111-111111111111';
const SID = '22222222-2222-4222-8222-222222222222';
const PID = '33333333-3333-4333-8333-333333333333';
const AUTH = '44444444-4444-4444-8444-444444444444';
const ISSUER = '55555555-5555-4555-8555-555555555555';
const COMMIT = 'a'.repeat(40);

function session(over: Record<string, unknown> = {}) {
  return {
    id: SID, project_id: PROJECT, session_type: 'automated_work_session', status: 'requested', objective: 'Fix the login bug',
    executor: { type: 'ai_assistant', provider: 'acme', model: 'm1' },
    access: { repository: 'read_and_push', allowed_read_paths: ['src/'], allowed_write_paths: ['src/auth/'], prohibited_paths: ['.env'] },
    evidence_requirements: [{ type: 'tests.passed', issuer_principal_id: ISSUER, required: true, tied_to_commit: true, issuer_is_requester: true }],
    created_at: '2026-01-01T00:00:00Z',
    ...over
  };
}

let sessions: any[];
let promotions: any[];
let attestations: any[];

function sessionsServer(method: string, path: string, body: any) {
  const base = `/api/v1/projects/${PROJECT}`;
  if (method === 'GET' && path === `${base}/work-sessions`) return { status: 200, body: { work_sessions: sessions } };
  if (method === 'POST' && path === `${base}/work-sessions/${SID}/approve`) {
    sessions[0].status = 'approved';
    return { status: 200, body: { id: SID, status: 'approved' } };
  }
  if (method === 'POST' && path === `${base}/work-sessions/${SID}/reject`) {
    sessions[0].status = 'rejected';
    return { status: 200, body: { id: SID, status: 'rejected' } };
  }
  if (method === 'GET' && path === `${base}/work-sessions/${SID}/evidence`) {
    return { status: 200, body: { session_id: SID, evaluation: { commit: null, ready: false, requirements: [{ evidence_type: 'tests.passed', issuer_principal_id: ISSUER, required: true, tied_to_commit: true, state: 'missing' }] }, submissions: [] } };
  }
  if (method === 'GET' && path === `${base}/work-sessions/${SID}/attribution`) return { status: 200, body: { session_id: SID, contributions: [] } };
  if (method === 'GET' && path === `${base}/work-sessions/${SID}/attestations`) return { status: 200, body: { session_id: SID, attestations } };
  if (method === 'GET' && path === `${base}/work-sessions/${SID}/promotions`) return { status: 200, body: { session_id: SID, promotions } };
  if (method === 'POST' && path === `${base}/promotions/${PID}/approve`) {
    promotions[0].status = 'completed';
    return { status: 200, body: { promotion: promotions[0] } };
  }
  if (method === 'GET' && path === '/api/v1/attestation-authorities') return { status: 200, body: { authorities: [{ id: AUTH, name: 'Notary', algorithm: 'Ed25519', fingerprint: 'f'.repeat(64) }] } };
  if (method === 'POST' && path === `${base}/work-sessions/${SID}/attestations`) {
    return { status: 201, body: { id: AUTH, claim: body.claim, subject_commit: body.subject_commit, recorded: true } };
  }
  throw new Error(`unhandled ${method} ${path}`);
}

beforeEach(() => {
  calls.length = 0;
  sessions = [session()];
  promotions = [];
  attestations = [];
  handler = sessionsServer;
});
afterEach(cleanup);

describe('Work sessions screen', () => {
  it('shows a waiting session with its evidence warning, and approving it calls the approve route once', async () => {
    const user = userEvent.setup();
    render(<SessionsView projectId={PROJECT} />);
    expect(await screen.findByText('Fix the login bug')).toBeTruthy();
    expect(screen.getByText('Waiting for your approval')).toBeTruthy();
    // Requested sessions open by themselves: the paths and the self-checking warning are visible without a click.
    expect(await screen.findByText(/same system is checking its own work/)).toBeTruthy();
    expect(screen.getByText(/src\/auth\//)).toBeTruthy();
    expect(await screen.findByText('Not delivered yet')).toBeTruthy();

    await user.click(screen.getByRole('button', { name: /Approve/ }));
    await waitFor(() => expect(screen.getByText('Approved')).toBeTruthy());
    expect(calls.filter((c) => c.method === 'POST')).toEqual([{ method: 'POST', path: `/api/v1/projects/${PROJECT}/work-sessions/${SID}/approve`, body: undefined }]);
  });

  it('rejects with the typed reason', async () => {
    const user = userEvent.setup();
    render(<SessionsView projectId={PROJECT} />);
    await screen.findByText('Fix the login bug');
    await user.type(screen.getByLabelText('Reason for rejecting'), 'Too broad');
    await user.click(screen.getByRole('button', { name: /Reject/ }));
    await waitFor(() => expect(screen.getByText('Rejected')).toBeTruthy());
    expect(calls.find((c) => c.method === 'POST')?.body).toEqual({ reason: 'Too broad' });
  });

  it('shows external context as plain text and never as markup', async () => {
    sessions = [session({ external_context: { namespace: 'com.example.tracker', context: { summary: '<img src=x onerror="window.__pwned=1"><b>bold</b>' } } })];
    render(<SessionsView projectId={PROJECT} />);
    const pre = await screen.findByTestId('external-context');
    expect(pre.textContent).toContain('<img src=x onerror=');
    expect(pre.querySelector('img, b')).toBeNull();
    expect((window as any).__pwned).toBeUndefined();
  });

  it('shows the server error when approving fails', async () => {
    const user = userEvent.setup();
    const original = handler;
    handler = (m, p, b) => (m === 'POST' && p.endsWith('/approve') ? { status: 409, body: { error: 'This session is no longer waiting.' } } : original(m, p, b));
    render(<SessionsView projectId={PROJECT} />);
    await user.click(await screen.findByRole('button', { name: /Approve/ }));
    expect(await screen.findByText('This session is no longer waiting.')).toBeTruthy();
  });

  it('asks for confirmation, with the consequence stated, before moving the default branch', async () => {
    const user = userEvent.setup();
    sessions = [session({ status: 'active' })];
    promotions = [{ id: PID, work_session_id: SID, commit: COMMIT, target_branch: 'main', status: 'pending', requested_at: '2026-01-01T00:00:00Z' }];
    render(<SessionsView projectId={PROJECT} />);
    await user.click(await screen.findByText('Fix the login bug'));
    await user.click(await screen.findByRole('button', { name: 'Approve' }));
    expect(screen.getByText(/moves the repository's default branch/)).toBeTruthy();
    expect(calls.some((c) => c.path.endsWith('/approve'))).toBe(false); // nothing sent yet
    await user.click(screen.getByRole('button', { name: 'Move the default branch' }));
    await waitFor(() => expect(calls.some((c) => c.method === 'POST' && c.path === `/api/v1/projects/${PROJECT}/promotions/${PID}/approve`)).toBe(true));
    expect(await screen.findByText(/the default branch moved/)).toBeTruthy();
  });

  it('explains a failed promotion in words', async () => {
    const user = userEvent.setup();
    sessions = [session({ status: 'active' })];
    promotions = [{ id: PID, work_session_id: SID, commit: COMMIT, target_branch: 'main', status: 'failed', failure_code: 'default_branch_changed' }];
    render(<SessionsView projectId={PROJECT} />);
    await user.click(await screen.findByText('Fix the login bug'));
    expect(await screen.findByText(/no longer the one this session started from/)).toBeTruthy();
  });

  it('shows the exact text to sign, matching what the server verifies, and sends the pasted signature', async () => {
    const user = userEvent.setup();
    sessions = [session({ status: 'active' })];
    render(<SessionsView projectId={PROJECT} />);
    await user.click(await screen.findByText('Fix the login bug'));
    await user.click(await screen.findByRole('button', { name: 'Deliver an attestation' }));
    await user.selectOptions(await screen.findByRole('combobox'), AUTH);
    const textboxes = screen.getAllByRole('textbox');
    const claim = textboxes.find((t) => (t as HTMLInputElement).value === '' && t.tagName === 'INPUT' && !(t as HTMLInputElement).placeholder);
    await user.type(claim!, 'security_review.passed');
    const commitBox = screen.getAllByRole('textbox').find((t) => t.tagName === 'INPUT' && (t as HTMLInputElement).value === '' && !(t as HTMLInputElement).placeholder);
    await user.type(commitBox!, COMMIT);
    const stmt = await screen.findByTestId('statement');
    const issuedAt = (screen.getByDisplayValue(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/) as HTMLInputElement).value;
    const expected = canonicalJsonV2({
      format: 'custody-core.attestation.v1', authority_id: AUTH, work_session_id: SID, claim: 'security_review.passed', subject_commit: COMMIT,
      payload_sha256: crypto.createHash('sha256').update('{}', 'utf8').digest('hex'), issued_at: issuedAt
    });
    expect(stmt.textContent).toBe(expected);

    const sig = 'A'.repeat(86);
    const sigBox = screen.getByText('Signature (base64url, 64 bytes)').closest('label')!.querySelector('input')!;
    await user.type(sigBox, sig);
    await user.click(screen.getByRole('button', { name: 'Record attestation' }));
    await waitFor(() => expect(calls.find((c) => c.method === 'POST' && c.path.endsWith('/attestations'))).toBeTruthy());
    expect(calls.find((c) => c.method === 'POST' && c.path.endsWith('/attestations'))!.body).toMatchObject({ authority_id: AUTH, claim: 'security_review.passed', subject_commit: COMMIT, issued_at: issuedAt, signature: { algorithm: 'Ed25519', value: sig } });
  });
});

describe('Integrations screen', () => {
  const EP = '66666666-6666-4666-8666-666666666666';
  let endpoints: any[];
  let authorities: any[];
  beforeEach(() => {
    endpoints = [];
    authorities = [];
    handler = (method, path, body) => {
      if (method === 'GET' && path === '/api/v1/webhook-endpoints') return { status: 200, body: { endpoints } };
      if (method === 'POST' && path === '/api/v1/webhook-endpoints') {
        const e = { id: EP, name: body.name, url: body.url, events: body.events, status: 'active' };
        endpoints = [{ ...e, deliveries: { pending: 0, delivered: 0, dead: 0 } }];
        return { status: 201, body: { endpoint: e, secret: 'whsec_exampleexampleexample' } };
      }
      if (method === 'GET' && path === '/api/v1/attestation-authorities') return { status: 200, body: { authorities } };
      if (method === 'POST' && path === '/api/v1/attestation-authorities') {
        authorities = [{ id: AUTH, name: body.name, algorithm: 'Ed25519', fingerprint: 'e'.repeat(64) }];
        return { status: 201, body: { authority: authorities[0] } };
      }
      if (method === 'POST' && path === `/api/v1/attestation-authorities/${AUTH}/revoke`) {
        authorities = [{ ...authorities[0], revoked_at: '2026-01-02T00:00:00Z' }];
        return { status: 200, body: { authority: authorities[0] } };
      }
      throw new Error(`unhandled ${method} ${path}`);
    };
  });

  it('creates an endpoint, shows the secret once, and forgets it when dismissed', async () => {
    const user = userEvent.setup();
    render(<IntegrationsView />);
    await user.type(await screen.findByLabelText('Endpoint name'), 'CI');
    await user.type(screen.getByLabelText('Endpoint address'), 'https://example.com/hook');
    await user.click(screen.getByRole('button', { name: 'Create endpoint' }));
    expect((await screen.findByTestId('webhook-secret')).textContent).toBe('whsec_exampleexampleexample');
    expect(calls.find((c) => c.method === 'POST')!.body).toEqual({ name: 'CI', url: 'https://example.com/hook', events: ['promotion.*', 'work_session.*'] });
    await user.click(screen.getByRole('button', { name: 'I have stored it' }));
    expect(screen.queryByTestId('webhook-secret')).toBeNull();
    expect(document.body.textContent).not.toContain('whsec_');
    expect(await screen.findByText('https://example.com/hook')).toBeTruthy();
  });

  it('shows the server\'s reason when an endpoint is refused', async () => {
    const user = userEvent.setup();
    const inner = handler;
    handler = (m, p, b) => (m === 'POST' && p === '/api/v1/webhook-endpoints' ? { status: 400, body: { error: 'The address must use https.' } } : inner(m, p, b));
    render(<IntegrationsView />);
    await user.type(await screen.findByLabelText('Endpoint name'), 'X');
    await user.type(screen.getByLabelText('Endpoint address'), 'http://example.com');
    await user.click(screen.getByRole('button', { name: 'Create endpoint' }));
    expect(await screen.findByText('The address must use https.')).toBeTruthy();
    expect(screen.queryByTestId('webhook-secret')).toBeNull();
  });

  it('registers a signing authority from a public JWK and revokes it after confirmation', async () => {
    const user = userEvent.setup();
    render(<IntegrationsView />);
    await user.type(await screen.findByLabelText('Authority name'), 'Notary');
    await user.click(screen.getByLabelText('Public key'));
    await user.paste('{"kty":"OKP","crv":"Ed25519","x":"AAAA"}');
    await user.click(screen.getByRole('button', { name: 'Register' }));
    expect(await screen.findByText(/key fingerprint/)).toBeTruthy();
    expect(calls.find((c) => c.method === 'POST' && c.path === '/api/v1/attestation-authorities')!.body).toEqual({ name: 'Notary', public_key: { kty: 'OKP', crv: 'Ed25519', x: 'AAAA' } });

    await user.click(screen.getByRole('button', { name: 'Revoke' }));
    expect(calls.some((c) => c.path.endsWith('/revoke'))).toBe(false);
    await user.click(screen.getByRole('button', { name: 'Revoke' }));
    expect(await screen.findByText(/Revoked/)).toBeTruthy();
  });

  it('rejects text that is not JSON before sending anything', async () => {
    const user = userEvent.setup();
    render(<IntegrationsView />);
    await user.type(await screen.findByLabelText('Authority name'), 'Notary');
    await user.type(screen.getByLabelText('Public key'), 'not json');
    await user.click(screen.getByRole('button', { name: 'Register' }));
    expect(await screen.findByText(/must be a JSON Web Key/)).toBeTruthy();
    expect(calls.some((c) => c.method === 'POST')).toBe(false);
  });
});

describe('Backup check', () => {
  const SNAP = '77777777-7777-4777-8777-777777777777';
  const door: any = { id: 'door-1', snapshot_status: 'done' };
  const snap = { id: SNAP, door_id: 'door-1', repository_id: PROJECT, full_name: 'acme/app', refs: { main: COMMIT }, size_bytes: 2048, sha256: 'c'.repeat(64), created_at: '2026-01-01T00:00:00Z' };

  function serve(verify: { status: number; body: any }) {
    handler = (method, path) => {
      if (method === 'GET' && path === `/api/v1/projects/${PROJECT}/snapshots`) return { status: 200, body: { snapshots: [snap] } };
      if (method === 'POST' && path === `/api/v1/projects/${PROJECT}/snapshots/${SNAP}/verify`) return verify;
      throw new Error(`unhandled ${method} ${path}`);
    };
  }

  it('reports an intact backup', async () => {
    const user = userEvent.setup();
    serve({ status: 200, body: { ok: true, encrypted: true, bytes: 2048 } });
    render(<SnapshotSection door={door} projectId={PROJECT} />);
    await user.click(await screen.findByRole('button', { name: 'Check this backup' }));
    expect((await screen.findByRole('status')).textContent).toMatch(/intact.*locked with your server key/);
  });

  it('reports a damaged backup as damaged, not as an error', async () => {
    const user = userEvent.setup();
    serve({ status: 409, body: { ok: false, problem: 'hash_mismatch', error: 'The stored file does not match its record.' } });
    render(<SnapshotSection door={door} projectId={PROJECT} />);
    await user.click(await screen.findByRole('button', { name: 'Check this backup' }));
    expect((await screen.findByRole('status')).textContent).toMatch(/damaged or unreadable: The stored file does not match its record/);
  });

  it('offers the locked file next to the plain download', async () => {
    serve({ status: 200, body: { ok: true } });
    render(<SnapshotSection door={door} projectId={PROJECT} />);
    expect(await screen.findByRole('button', { name: 'Download locked file' })).toBeTruthy();
    expect(within(document.body).getByRole('button', { name: /Download \(git clone works on it\)/ })).toBeTruthy();
  });
});
