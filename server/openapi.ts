/**
 * The OpenAPI 3.1 description of the integration API (docs/integration/PHASE10_DESIGN.md; gate CL-17).
 *
 * Machine callers use /api/v2 (a client assertion signed with the principal's key); owners use the listed /api/v1 routes (their signed-in session).
 * tests/openapi.test.ts keeps this document honest: every route the server registers under /api/v2 is described here and the other way round,
 * every described /api/v1 route exists, the document is structurally valid, and docs/openapi.json is exactly what this file produces
 * (`npm run build:openapi`).
 */

import { ATTRIBUTION_CLAIM, SUBMISSION_CONTRACT } from './attestation';

type J = Record<string, any>;
const ref = (name: string): J => ({ $ref: `#/components/schemas/${name}` });
const resp = (name: string): J => ({ $ref: `#/components/responses/${name}` });
const obj = (properties: J, required: string[] = [], extra: J = {}): J => ({ type: 'object', properties, ...(required.length ? { required } : {}), additionalProperties: false, ...extra });
const arr = (items: J, extra: J = {}): J => ({ type: 'array', items, ...extra });
const nullable = (schema: J): J => ({ oneOf: [schema, { type: 'null' }] });
const str = (extra: J = {}): J => ({ type: 'string', ...extra });
const jsonBody = (schema: J, required = true): J => ({ required, content: { 'application/json': { schema } } });
const ok = (description: string, schema: J): J => ({ description, content: { 'application/json': { schema } } });
const pathParam = (name: string, description: string): J => ({ name, in: 'path', required: true, description, schema: ref('Uuid') });
const ID = pathParam('id', 'The work session.');
const SID = pathParam('sid', 'The work session.');
const PID = pathParam('pid', 'The promotion request.');
const PROJECT = pathParam('id', 'The project.');
const COMMIT_QUERY: J = { name: 'commit', in: 'query', required: false, description: 'A real commit id the session produced. Default: the newest.', schema: ref('Sha1') };

const MACHINE: J[] = [{ principalAssertion: [] }];
const OWNER: J[] = [{ ownerSession: [] }];

const errors = (...names: string[]): J => Object.fromEntries(names.map((n) => [{ BadRequest: '400', Unauthorized: '401', Forbidden: '403', NotFound: '404', Conflict: '409', Unprocessable: '422', TooMany: '429', Unavailable: '503' }[n], resp(n)]));

const executor = obj(
  { type: { type: 'string', enum: ['ai_assistant', 'ide_runtime', 'ci_runtime', 'platform_service'] }, provider: nullable(str({ maxLength: 200 })), model: nullable(str({ maxLength: 200 })), external_id: nullable(str({ maxLength: 200 })), display_name: nullable(str({ maxLength: 200 })) },
  ['type']
);

const evidenceRequirementInput = obj(
  {
    type: str({ pattern: '^[a-z][a-z0-9_.-]{0,63}$', description: 'The kind of evidence, such as "tests" or "review.security".' }),
    issuer_principal_id: { ...ref('Uuid'), description: 'The registered principal (same owner, active, holding evidence:submit) that may issue it.' },
    required: { type: 'boolean', default: true },
    tied_to_commit: { type: 'boolean', default: true, description: 'If false, evidence about any commit of the session satisfies it.' },
    specification_hash: nullable(ref('Sha256')),
    max_age_seconds: nullable({ type: 'integer', minimum: 60, maximum: 31536000 })
  },
  ['type', 'issuer_principal_id']
);

const sessionRequest = obj(
  {
    project_id: ref('Uuid'),
    repository_id: ref('Uuid'),
    executor,
    sponsor: obj({ type: { const: 'creator' }, id: { ...ref('Uuid'), description: "The project owner's id. Must be the owner of the project." } }, ['type', 'id']),
    objective: str({ minLength: 1, maxLength: 2000 }),
    base_commit: { ...ref('Sha1'), description: 'The commit the session starts from. It must be part of the repository\'s default branch (checked when the credential is issued).' },
    access: obj(
      {
        repository: { type: 'string', enum: ['read', 'read_and_push'] },
        allowed_read_paths: arr(str({ minLength: 1, maxLength: 200 }), { minItems: 1, maxItems: 50, description: 'Path patterns the session may read. Nothing is readable unless listed.' }),
        allowed_write_paths: arr(str({ minLength: 1, maxLength: 200 }), { maxItems: 50, description: 'Empty for read-only access; required for read_and_push.' }),
        prohibited_paths: arr(str({ minLength: 1, maxLength: 200 }), { maxItems: 50, description: 'Always wins over the allowed lists. A pattern with no "/" matches that name at any depth.' })
      },
      ['repository', 'allowed_read_paths']
    ),
    expires_in_seconds: { type: 'integer', minimum: 60, maximum: 86400, default: 3600 },
    external_context: ref('ExternalContext'),
    evidence_requirements: arr(evidenceRequirementInput, { maxItems: 10 })
  },
  ['project_id', 'repository_id', 'executor', 'sponsor', 'objective', 'base_commit', 'access']
);

const evidenceRequirementView = obj(
  {
    type: str(), issuer_principal_id: ref('Uuid'), required: { type: 'boolean' }, tied_to_commit: { type: 'boolean' }, specification_hash: nullable(ref('Sha256')),
    max_age_seconds: nullable({ type: 'integer' }), issuer_is_requester: { type: 'boolean', description: 'True when the principal that asked for the work is also the one that may vouch for it.' }
  },
  ['type', 'issuer_principal_id', 'required', 'tied_to_commit']
);

const workSession = obj(
  {
    id: ref('Uuid'), project_id: ref('Uuid'), repository_id: nullable(ref('Uuid')), session_type: { type: 'string', enum: ['automated_work_session', 'human_door'] }, door_id: nullable(ref('Uuid')),
    status: ref('SessionStatus'),
    requested_by: nullable(obj({ principal_id: ref('Uuid'), name: nullable(str()) }, ['principal_id'])),
    executor: obj({ type: str(), provider: nullable(str()), model: nullable(str()), external_id: nullable(str()), display_name: nullable(str()) }),
    sponsor_id: ref('Uuid'), objective: str(), base_commit: nullable(ref('Sha1')), branch_name: nullable(str()),
    access: nullable(obj({ repository: str(), allowed_read_paths: arr(str()), allowed_write_paths: arr(str()), prohibited_paths: arr(str()) })),
    external_context: nullable(obj({ namespace: str(), context: { type: 'object' }, sha256: ref('Sha256') })),
    evidence_requirements: arr(evidenceRequirementView),
    created_at: ref('Timestamp'), approved_at: nullable(ref('Timestamp')), approved_by: nullable(str()), expires_at: nullable(ref('Timestamp')), closed_at: nullable(ref('Timestamp')), closed_reason: nullable(str())
  },
  ['id', 'project_id', 'status']
);

const signature = obj({ key_id: ref('Uuid'), algorithm: { type: 'string', enum: ['Ed25519', 'ES256'] }, value: str({ pattern: '^[A-Za-z0-9_-]{86}$', description: 'The 64-byte signature, base64url without padding.' }) }, ['key_id', 'algorithm', 'value']);

const submissionView = obj(
  {
    id: ref('Uuid'), evidence_type: str(), issuer_principal_id: ref('Uuid'), signature_key_id: ref('Uuid'), subject_commit: ref('Sha1'), status: { type: 'string', enum: ['pass', 'fail', 'inconclusive'] },
    specification_hash: ref('Sha256'), evidence_hash: ref('Sha256'), payload_sha256: ref('Sha256'), issued_at: ref('IssuedAt'),
    signature: obj({ algorithm: str(), value: str() }), created_at: ref('Timestamp'), payload: { type: 'object' }
  },
  ['id', 'evidence_type', 'subject_commit', 'status']
);

const promotion = obj(
  {
    id: ref('Uuid'), work_session_id: ref('Uuid'), repository_id: ref('Uuid'), target_branch: str(), commit: ref('Sha1'), status: { type: 'string', enum: ['pending', 'approved', 'completed', 'rejected', 'failed'] },
    requested_by: obj({ kind: { type: 'string', enum: ['principal', 'creator'] }, id: ref('Uuid') }),
    requested_at: ref('Timestamp'), evidence_at_request: ref('EvidenceEvaluation'), attestations_at_request: arr(obj({ id: ref('Uuid'), claim: str(), authority_id: ref('Uuid') })),
    approved_by: nullable(str()), approved_at: nullable(ref('Timestamp')), rejected_reason: nullable(str()), previous_tip: nullable(ref('Sha1')), completed_at: nullable(ref('Timestamp')), failure_code: nullable(str())
  },
  ['id', 'work_session_id', 'commit', 'status']
);

const webhookEndpoint = obj(
  {
    id: ref('Uuid'), name: str(), url: str({ format: 'uri' }), events: arr(str()), project_ids: nullable(arr(ref('Uuid'))), status: { type: 'string', enum: ['active', 'disabled'] },
    created_at: ref('Timestamp'), secret_rotated_at: nullable(ref('Timestamp')), disabled_at: nullable(ref('Timestamp'))
  },
  ['id', 'name', 'url', 'events', 'status']
);

const attestationView = obj(
  {
    id: ref('Uuid'), authority: obj({ id: ref('Uuid'), name: str(), active: { type: 'boolean' } }), claim: str(), subject_commit: ref('Sha1'), payload_sha256: ref('Sha256'), payload: { type: 'object' },
    issued_at: ref('IssuedAt'), signature: obj({ algorithm: str(), value: str() }), recorded_at: ref('Timestamp')
  },
  ['id', 'claim', 'subject_commit']
);

const schemas: J = {
  Uuid: str({ format: 'uuid' }),
  Sha1: str({ pattern: '^[0-9a-f]{40}$', description: 'A full 40-character lowercase commit id.' }),
  Sha256: str({ pattern: '^[0-9a-f]{64}$' }),
  Timestamp: str({ format: 'date-time' }),
  IssuedAt: str({ pattern: '^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z$', description: 'UTC, whole seconds.' }),
  SessionStatus: { type: 'string', enum: ['requested', 'approved', 'provisioning', 'active', 'awaiting_evidence', 'completed', 'rejected', 'closed', 'expired'] },
  Error: obj({ error: str({ description: 'In words. Never contains a secret.' }), code: str({ description: 'A stable machine-readable reason, where the route has them.' }) }, ['error'], { additionalProperties: true }),
  ExternalContext: obj({ namespace: str({ description: 'Lowercase reverse-DNS, two or more labels. A label, not an identity.' }), context: { type: 'object', description: 'Plain JSON, at most 16 KiB, whole numbers only. Never acted on.' } }, ['namespace', 'context']),
  SessionRequest: sessionRequest,
  SessionRequested: obj({ session_id: ref('Uuid'), status: ref('SessionStatus'), requires_approval: { const: true }, sponsor_id: ref('Uuid'), branch_prefix: str(), expires_at: ref('Timestamp'), event_hash: ref('Sha256') }, ['session_id', 'status']),
  WorkSession: workSession,
  SessionCredential: obj(
    {
      session_id: ref('Uuid'), repository: str(), read_only: { type: 'boolean' }, git_url: str({ description: 'Clone and push here, with any user name and the credential as the password.' }),
      credential: obj({ token: str({ pattern: '^ccs_', description: 'Shown once; only its hash is kept.' }), expires_at: ref('Timestamp') }, ['token', 'expires_at']),
      branch_prefix: str(), view: obj({ commit: ref('Sha1'), tree: ref('Sha1'), file_count: { type: 'integer' }, base_commit: ref('Sha1') }), replaced: { type: 'boolean' }
    },
    ['session_id', 'git_url', 'credential']
  ),
  SessionCommits: obj({ session_id: ref('Uuid'), commits: arr(obj({ view_sha: ref('Sha1'), real_sha: ref('Sha1'), parent_view_sha: ref('Sha1'), declared_author: str(), created_at: ref('Timestamp') })) }),
  EvidenceSubmission: obj(
    {
      evidence_type: str({ pattern: '^[a-z][a-z0-9_.-]{0,63}$' }), subject_commit: ref('Sha1'), status: { type: 'string', enum: ['pass', 'fail', 'inconclusive'] }, specification_hash: ref('Sha256'), evidence_hash: ref('Sha256'),
      issued_at: ref('IssuedAt'), payload: { type: 'object', description: 'Optional plain JSON (whole numbers only), kept with the statement; scanned for secrets. Covered by the signature through its hash.' }, signature
    },
    ['evidence_type', 'subject_commit', 'status', 'specification_hash', 'evidence_hash', 'issued_at', 'signature'],
    { description: 'The signature is over the canonical JSON of { format: "custody-core.evidence.v1", work_session_id, evidence_type, subject_commit, status, specification_hash, evidence_hash, payload_sha256, issued_at }.' }
  ),
  EvidenceRecorded: { ...submissionView, properties: { ...submissionView.properties, recorded: { type: 'boolean', description: 'False when this exact statement was already recorded.' } } },
  EvidenceSubmissionView: submissionView,
  EvidenceEvaluation: obj(
    {
      commit: nullable(ref('Sha1')), ready: { type: 'boolean', description: 'Every required requirement is satisfied for this commit.' },
      requirements: arr(obj({ evidence_type: str(), issuer_principal_id: ref('Uuid'), required: { type: 'boolean' }, tied_to_commit: { type: 'boolean' }, specification_hash: nullable(ref('Sha256')), max_age_seconds: nullable({ type: 'integer' }), state: { type: 'string', enum: ['satisfied', 'failed', 'inconclusive', 'missing', 'stale', 'issuer_unavailable'] }, submission_id: nullable(ref('Uuid')), issued_at: nullable(ref('IssuedAt')) }))
    },
    ['commit', 'ready', 'requirements']
  ),
  EvidenceReport: obj({ session_id: ref('Uuid'), evaluation: ref('EvidenceEvaluation'), submissions: arr(ref('EvidenceSubmissionView')) }),
  Attribution: obj({
    session_id: ref('Uuid'),
    contributions: arr(obj({
      commit: ref('Sha1'), pushed_as: ref('Sha1'),
      author: obj({ kind: { const: 'executor' }, principal_id: ref('Uuid'), executor: obj({ type: str(), provider: nullable(str()), model: nullable(str()), external_id: nullable(str()), display_name: nullable(str()) }), as_written_in_git: obj({ name: str(), email: str() }) }),
      committer: obj({ kind: { const: 'gateway' } }), sponsor: obj({ kind: { const: 'creator' }, id: ref('Uuid') }),
      declared_author: obj({ value: str(), trusted: { const: false } }), recorded_at: ref('Timestamp')
    }))
  }),
  Attestations: obj({ session_id: ref('Uuid'), attestations: arr(ref('Attestation')) }),
  Attestation: attestationView,
  AttestationRecorded: { ...attestationView, properties: { ...attestationView.properties, recorded: { type: 'boolean', description: 'False when this exact statement was already recorded.' } } },
  AttestationReceipt: obj(
    {
      contract: str({ description: 'The contract and version this server implements: "commit-attribution-submission/1".' }), attestation_id: ref('Uuid'), work_session_id: ref('Uuid'), authority_id: ref('Uuid'),
      claim: str(), subject_commit: ref('Sha1'), statement_sha256: { ...ref('Sha256'), description: 'SHA-256 of the exact signed statement. Identical on every retry; compute it yourself to check.' }, recorded_at: ref('Timestamp')
    },
    ['contract', 'attestation_id', 'work_session_id', 'authority_id', 'claim', 'subject_commit', 'statement_sha256', 'recorded_at']
  ),
  AttestationSubmitted: { ...attestationView, properties: { ...attestationView.properties, recorded: { type: 'boolean', description: 'False when this exact statement was already recorded (a retry).' }, receipt: ref('AttestationReceipt') }, required: [...attestationView.required, 'recorded', 'receipt'] },
  SubmissionGrant: obj({ id: ref('Uuid'), principal_id: ref('Uuid'), authority_id: ref('Uuid'), project_id: ref('Uuid'), created_at: ref('Timestamp'), revoked_at: nullable(ref('Timestamp')) }, ['id', 'principal_id', 'authority_id', 'project_id']),
  SubmissionGrantRequest: obj({ principal_id: ref('Uuid'), authority_id: ref('Uuid'), project_id: ref('Uuid') }, ['principal_id', 'authority_id', 'project_id']),
  AttestationRequest: obj(
    { authority_id: ref('Uuid'), claim: str({ pattern: '^[a-z][a-z0-9_.-]{0,63}$' }), subject_commit: ref('Sha1'), issued_at: ref('IssuedAt'), payload: { type: 'object' }, signature: obj({ algorithm: { type: 'string', enum: ['Ed25519', 'ES256'] }, value: str({ pattern: '^[A-Za-z0-9_-]{86}$' }) }, ['algorithm', 'value']) },
    ['authority_id', 'claim', 'subject_commit', 'issued_at', 'signature'],
    { description: 'The signature is by the authority\'s registered key over the canonical JSON of { format: "custody-core.attestation.v1", authority_id, work_session_id, claim, subject_commit, payload_sha256, issued_at }.' }
  ),
  AttestationAuthority: obj({ id: ref('Uuid'), name: str(), algorithm: { type: 'string', enum: ['Ed25519', 'ES256'] }, public_key: { type: 'object' }, fingerprint: ref('Sha256'), created_at: ref('Timestamp'), revoked_at: nullable(ref('Timestamp')) }, ['id', 'name']),
  PromotionRequest: obj({ commit: ref('Sha1') }),
  Promotion: promotion,
  PromotionRequested: obj({ promotion: ref('Promotion'), requires_approval: { const: true } }, ['promotion']),
  Promotions: obj({ session_id: ref('Uuid'), promotions: arr(ref('Promotion')) }),
  Principal: obj({ principal: obj({ id: ref('Uuid'), name: str(), platform_type: str(), environment: str(), scopes: arr(str()), allowed_project_ids: nullable(arr(ref('Uuid'))), expires_at: nullable(ref('Timestamp')) }) }),
  WebhookEndpoint: webhookEndpoint,
  WebhookEndpointSummary: { ...webhookEndpoint, properties: { ...webhookEndpoint.properties, deliveries: obj({ pending: { type: 'integer' }, delivered: { type: 'integer' }, dead: { type: 'integer' } }) } },
  WebhookEndpointRequest: obj(
    { name: str({ minLength: 1, maxLength: 100 }), url: str({ description: 'https, a host name (no IP address), resolving only to public addresses.' }), events: arr(str(), { minItems: 1, maxItems: 20, description: '"*", a family such as "promotion.*", or an exact event name.' }), project_ids: arr(ref('Uuid'), { minItems: 1 }) },
    ['name', 'url', 'events']
  ),
  WebhookEndpointWithSecret: obj({ endpoint: ref('WebhookEndpoint'), secret: str({ pattern: '^whsec_', description: 'Shown once.' }) }, ['endpoint', 'secret']),
  WebhookDelivery: obj({ id: ref('Uuid'), event_id: ref('Uuid'), event_type: str(), project_id: ref('Uuid'), status: { type: 'string', enum: ['pending', 'delivered', 'dead'] }, attempts: { type: 'integer' }, next_attempt_at: nullable(ref('Timestamp')), last_status: nullable({ type: 'integer' }), last_error: nullable(str()), created_at: ref('Timestamp'), delivered_at: nullable(ref('Timestamp')) }),
  WebhookEvent: obj(
    {
      format: { const: 'custody-core.webhook.v1' }, id: ref('Uuid'), type: str(), project_id: ref('Uuid'), occurred_at: ref('Timestamp'),
      actor: obj({ type: str(), id: str() }), subject: obj({ type: str(), id: str() }), data: { type: 'object', description: "The event's payload." },
      record: obj({ seq: { type: 'integer' }, prev_hash: ref('Sha256'), hash: ref('Sha256'), hash_version: { type: 'integer' }, hashed_timestamp: str(), canonical_payload: nullable(str()) }, [], { description: "What the project's tamper-evident chain holds for this event (docs/EVENT_HASH_FORMAT.md)." })
    },
    ['format', 'id', 'type', 'project_id', 'data', 'record']
  )
};

const errorResponse = (description: string): J => ({ description, content: { 'application/json': { schema: ref('Error') } } });

const op = (operationId: string, summary: string, tags: string[], security: J[], extra: J): J => ({ operationId, summary, tags, security, ...extra });

const paths: J = {
  '/api/v2/openapi.json': { get: op('getOpenApiDocument', 'This document.', ['Meta'], [], { responses: { '200': ok('The OpenAPI document.', { type: 'object' }) } }) },
  '/api/v2/whoami': {
    get: op('whoami', 'Who the server says you are (from its own records, never from the token).', ['Meta'], MACHINE, { responses: { '200': ok('The calling principal.', ref('Principal')), ...errors('Unauthorized') } })
  },
  '/api/v2/work-sessions': {
    post: op('requestWorkSession', 'Ask for a work session. It starts `requested`; a person must approve it.', ['Work sessions'], MACHINE, {
      description: 'Scope `work-sessions:request`. Every text field is scanned for secrets before it is recorded (the record is permanent). At most 25 requests may wait for approval per principal.',
      requestBody: jsonBody(ref('SessionRequest')),
      responses: { '202': ok('Requested. Nothing can happen until the owner approves.', ref('SessionRequested')), ...errors('BadRequest', 'Unauthorized', 'Forbidden', 'NotFound', 'Unprocessable', 'TooMany', 'Unavailable') }
    }),
    get: op('listWorkSessions', 'The sessions this principal requested (or, with `work-sessions:approve`, those of the projects it can reach).', ['Work sessions'], MACHINE, {
      description: 'Scope `work-sessions:read`. At most 100, newest first.',
      parameters: [{ name: 'project_id', in: 'query', schema: ref('Uuid') }, { name: 'status', in: 'query', schema: ref('SessionStatus') }],
      responses: { '200': ok('The sessions.', obj({ work_sessions: arr(ref('WorkSession')) })), ...errors('BadRequest', 'Unauthorized', 'Forbidden') }
    })
  },
  '/api/v2/work-sessions/{id}': {
    get: op('getWorkSession', 'One session.', ['Work sessions'], MACHINE, { description: 'Scope `work-sessions:read`.', parameters: [ID], responses: { '200': ok('The session.', obj({ work_session: ref('WorkSession') })), ...errors('Unauthorized', 'Forbidden', 'NotFound') } })
  },
  '/api/v2/work-sessions/{id}/close': {
    post: op('closeWorkSession', 'Close a session this principal requested (idempotent).', ['Work sessions'], MACHINE, {
      description: 'Scope `work-sessions:close-own`. Revokes the session\'s credential and deletes the gateway\'s copy. Branches already pushed stay in the repository.', parameters: [ID],
      responses: { '200': ok('Closed.', obj({ session_id: ref('Uuid'), status: ref('SessionStatus') })), ...errors('Unauthorized', 'Forbidden', 'NotFound', 'Conflict') }
    })
  },
  '/api/v2/work-sessions/{id}/credential': {
    post: op('issueSessionCredential', 'Prepare an approved session and get its git credential (or a replacement).', ['Work sessions'], MACHINE, {
      description: 'Scope `repositories:push-session`; only the principal that requested the session. First call (session `approved`): the gateway builds a filtered one-commit view of the repository and issues a credential (201). Later calls (session `active`): a replacement; the old credential stops working at once (200). Failures return the session to `approved` with nothing issued.',
      parameters: [ID], responses: { '200': ok('A replacement credential.', ref('SessionCredential')), '201': ok('Prepared; the credential is shown once.', ref('SessionCredential')), ...errors('Unauthorized', 'Forbidden', 'NotFound', 'Conflict', 'Unprocessable', 'TooMany', 'Unavailable') }
    })
  },
  '/api/v2/work-sessions/{id}/commits': {
    get: op('listSessionCommits', 'Which real commit each pushed commit became.', ['Work sessions'], MACHINE, { description: 'Scope `work-sessions:read`.', parameters: [ID], responses: { '200': ok('The pairs.', ref('SessionCommits')), ...errors('Unauthorized', 'Forbidden', 'NotFound') } })
  },
  '/api/v2/work-sessions/{id}/evidence': {
    post: op('submitEvidence', 'Submit a signed statement about one commit of the session.', ['Evidence'], MACHINE, {
      description: 'Scope `evidence:submit`; only the issuer the request named (anyone else gets 404). Only while the session is running. Sending the identical statement again is harmless (200); a different result for the same `evidence_hash` is a 409.',
      parameters: [ID], requestBody: jsonBody(ref('EvidenceSubmission')),
      responses: { '200': ok('Already recorded.', ref('EvidenceRecorded')), '201': ok('Recorded.', ref('EvidenceRecorded')), ...errors('BadRequest', 'Unauthorized', 'Forbidden', 'NotFound', 'Conflict', 'Unprocessable', 'TooMany', 'Unavailable') }
    }),
    get: op('getEvidence', 'The session\'s evidence and whether each requirement is met for a commit.', ['Evidence'], MACHINE, {
      description: 'Scope `work-sessions:read`.', parameters: [ID, COMMIT_QUERY], responses: { '200': ok('The report.', ref('EvidenceReport')), ...errors('BadRequest', 'Unauthorized', 'Forbidden', 'NotFound', 'Unprocessable') }
    })
  },
  '/api/v2/work-sessions/{id}/attribution': {
    get: op('getAttribution', 'Who authored, committed and answers for each commit the session pushed.', ['Attribution'], MACHINE, { description: 'Scope `work-sessions:read`.', parameters: [ID], responses: { '200': ok('The contributions.', ref('Attribution')), ...errors('Unauthorized', 'Forbidden', 'NotFound') } })
  },
  '/api/v2/work-sessions/{id}/attestations': {
    get: op('listAttestations', 'Attestations by signing authorities about the session\'s commits.', ['Attribution'], MACHINE, {
      description: 'Scope `work-sessions:read`.', parameters: [ID, COMMIT_QUERY], responses: { '200': ok('The attestations.', ref('Attestations')), ...errors('BadRequest', 'Unauthorized', 'Forbidden', 'NotFound') }
    }),
    post: op('submitAttestation', 'Deliver a detached signed commit-attribution statement for a commit of your own session (contract commit-attribution-submission/1).', ['Attribution'], MACHINE, {
      description: [
        'Scope `attestations:submit`, and an owner\'s grant naming this principal, the authority and the project (`/api/v1/attestation-submission-grants`). The scope alone permits nothing.',
        'Only the claim `commit.attribution` is accepted here, and only for a session this principal requested. The owner, sponsor, requester, repository and project are taken from our records: the body cannot name them.',
        'The signature is verified (before anything is stored) with the authority\'s registered key over the canonical statement described on `AttestationRequest`. Sending the identical statement again (after a lost response) answers 200 with the same receipt and `recorded: false`; a different statement for the same commit is a new attestation, never a replacement.',
        'Errors, all `{ error, code }`: 403 `not_granted`; 404 (not your session); 422 `claim_not_allowed`, `authority_revoked`, `bad_signature` (a changed claim, commit or payload fails here), `unknown_commit`, `issued_before_commit`, `issued_in_future`; 400 `secret_found`; 429 `too_many`; 503 `scanner_unavailable`.'
      ].join('\n\n'),
      parameters: [ID], requestBody: jsonBody(ref('AttestationRequest')),
      responses: { '200': ok('Already recorded: the same receipt.', ref('AttestationSubmitted')), '201': ok('Recorded.', ref('AttestationSubmitted')), ...errors('BadRequest', 'Unauthorized', 'Forbidden', 'NotFound', 'Unprocessable', 'TooMany', 'Unavailable') }
    })
  },
  '/api/v2/work-sessions/{id}/promote': {
    post: op('requestPromotion', 'Ask for the repository\'s default branch to be moved to a commit of the session.', ['Promotion'], MACHINE, {
      description: 'Scope `repositories:promote` (cannot be held with work scopes). Refused (422 `evidence_not_ready`, with the evaluation) unless the evidence is ready for that commit. The request is `pending`; only the owner can approve it.',
      parameters: [ID], requestBody: jsonBody(ref('PromotionRequest'), false),
      responses: { '202': ok('Pending approval.', ref('PromotionRequested')), ...errors('BadRequest', 'Unauthorized', 'Forbidden', 'NotFound', 'Conflict', 'Unprocessable') }
    })
  },
  '/api/v2/work-sessions/{id}/promotions': {
    get: op('listPromotions', 'The session\'s promotion requests.', ['Promotion'], MACHINE, { description: 'Scope `work-sessions:read` or `repositories:promote`.', parameters: [ID], responses: { '200': ok('The requests.', ref('Promotions')), ...errors('Unauthorized', 'Forbidden', 'NotFound') } })
  },

  // ---- the owner (signed in with the code step) ----------------------------------------------------------------------
  '/api/v1/projects/{id}/work-sessions': {
    get: op('ownerListWorkSessions', 'The project\'s sessions (doors included).', ['Owner'], OWNER, { parameters: [PROJECT], responses: { '200': ok('The sessions.', obj({ work_sessions: arr(ref('WorkSession')) })), ...errors('Unauthorized', 'NotFound') } })
  },
  '/api/v1/projects/{id}/work-sessions/{sid}/approve': {
    post: op('ownerApproveWorkSession', 'Approve a requested session (only its sponsor).', ['Owner'], OWNER, { parameters: [PROJECT, SID], responses: { '200': ok('Approved.', obj({ id: ref('Uuid'), status: ref('SessionStatus') })), ...errors('Unauthorized', 'Forbidden', 'NotFound', 'Conflict') } })
  },
  '/api/v1/projects/{id}/work-sessions/{sid}/reject': {
    post: op('ownerRejectWorkSession', 'Reject a requested session.', ['Owner'], OWNER, { parameters: [PROJECT, SID], requestBody: jsonBody(obj({ reason: str({ maxLength: 500 }) }), false), responses: { '200': ok('Rejected.', obj({ id: ref('Uuid'), status: ref('SessionStatus') })), ...errors('BadRequest', 'Unauthorized', 'Forbidden', 'NotFound', 'Conflict') } })
  },
  '/api/v1/projects/{id}/work-sessions/{sid}/evidence': {
    get: op('ownerGetEvidence', 'The session\'s evidence and its evaluation.', ['Owner'], OWNER, { parameters: [PROJECT, SID, COMMIT_QUERY], responses: { '200': ok('The report.', ref('EvidenceReport')), ...errors('BadRequest', 'Unauthorized', 'NotFound', 'Unprocessable') } })
  },
  '/api/v1/projects/{id}/work-sessions/{sid}/attribution': {
    get: op('ownerGetAttribution', 'Attribution for the session\'s commits.', ['Owner'], OWNER, { parameters: [PROJECT, SID], responses: { '200': ok('The contributions.', ref('Attribution')), ...errors('Unauthorized', 'NotFound') } })
  },
  '/api/v1/projects/{id}/work-sessions/{sid}/attestations': {
    get: op('ownerListAttestations', 'Attestations about the session\'s commits.', ['Owner'], OWNER, { parameters: [PROJECT, SID, COMMIT_QUERY], responses: { '200': ok('The attestations.', ref('Attestations')), ...errors('BadRequest', 'Unauthorized', 'NotFound') } }),
    post: op('ownerRecordAttestation', 'Deliver a signature by one of your signing authorities about a commit. Verified before it is stored.', ['Owner'], OWNER, {
      parameters: [PROJECT, SID], requestBody: jsonBody(ref('AttestationRequest')), responses: { '200': ok('Already recorded.', ref('AttestationRecorded')), '201': ok('Recorded.', ref('AttestationRecorded')), ...errors('BadRequest', 'Unauthorized', 'NotFound', 'Unprocessable', 'TooMany', 'Unavailable') }
    })
  },
  '/api/v1/projects/{id}/work-sessions/{sid}/promotions': {
    get: op('ownerListPromotions', 'The session\'s promotion requests.', ['Owner'], OWNER, { parameters: [PROJECT, SID], responses: { '200': ok('The requests.', ref('Promotions')), ...errors('Unauthorized', 'NotFound') } }),
    post: op('ownerRequestPromotion', 'Ask for a promotion yourself (then decide on it).', ['Owner'], OWNER, { parameters: [PROJECT, SID], requestBody: jsonBody(ref('PromotionRequest'), false), responses: { '201': ok('Pending.', obj({ promotion: ref('Promotion') })), ...errors('BadRequest', 'Unauthorized', 'NotFound', 'Conflict', 'Unprocessable') } })
  },
  '/api/v1/projects/{id}/promotions': {
    get: op('ownerListProjectPromotions', 'All promotion requests of the project.', ['Owner'], OWNER, { parameters: [PROJECT], responses: { '200': ok('The requests.', obj({ promotions: arr(ref('Promotion')) })), ...errors('Unauthorized', 'NotFound') } })
  },
  '/api/v1/projects/{id}/promotions/{pid}/approve': {
    post: op('ownerApprovePromotion', 'Approve a promotion; the gateway carries it out at once (a fast-forward only).', ['Owner'], OWNER, {
      description: 'Only the session\'s sponsor, as a person. Evidence is checked again. Approving an approved-but-unfinished request resumes it.', parameters: [PROJECT, PID],
      responses: { '200': ok('Completed.', obj({ promotion: ref('Promotion') })), ...errors('Unauthorized', 'Forbidden', 'NotFound', 'Conflict', 'Unprocessable') }
    })
  },
  '/api/v1/projects/{id}/promotions/{pid}/reject': {
    post: op('ownerRejectPromotion', 'Reject a pending promotion.', ['Owner'], OWNER, { parameters: [PROJECT, PID], requestBody: jsonBody(obj({ reason: str({ maxLength: 500 }) }), false), responses: { '200': ok('Rejected.', obj({ promotion: ref('Promotion') })), ...errors('BadRequest', 'Unauthorized', 'Forbidden', 'NotFound', 'Conflict') } })
  },
  '/api/v1/attestation-authorities': {
    get: op('listAttestationAuthorities', 'Your registered signing authorities.', ['Owner'], OWNER, { responses: { '200': ok('The authorities.', obj({ authorities: arr(ref('AttestationAuthority')) })), ...errors('Unauthorized') } }),
    post: op('registerAttestationAuthority', 'Register the public key of a signer you trust.', ['Owner'], OWNER, {
      requestBody: jsonBody(obj({ name: str({ minLength: 1, maxLength: 100 }), public_key: { type: 'object', description: 'An Ed25519 (OKP) or P-256 (EC) public JWK. A private key is refused.' } }, ['name', 'public_key'])),
      responses: { '201': ok('Registered.', obj({ authority: ref('AttestationAuthority') })), ...errors('BadRequest', 'Unauthorized', 'Conflict') }
    })
  },
  '/api/v1/attestation-authorities/{id}/revoke': {
    post: op('revokeAttestationAuthority', 'Revoke an authority (final).', ['Owner'], OWNER, { parameters: [pathParam('id', 'The authority.')], responses: { '200': ok('Revoked.', obj({ authority: ref('AttestationAuthority') })), ...errors('Unauthorized', 'NotFound') } })
  },
  '/api/v1/attestation-submission-grants': {
    get: op('listSubmissionGrants', 'Your submission grants.', ['Owner'], OWNER, { responses: { '200': ok('The grants.', obj({ grants: arr(ref('SubmissionGrant')) })), ...errors('Unauthorized') } }),
    post: op('createSubmissionGrant', 'Let one service principal deliver statements by one of your authorities for one of your projects.', ['Owner'], OWNER, {
      description: 'The principal must already hold `attestations:submit` (a scope can never be added to an existing principal). Revoking the grant, the authority or the principal ends it at once.',
      requestBody: jsonBody(ref('SubmissionGrantRequest')), responses: { '201': ok('Granted.', obj({ grant: ref('SubmissionGrant') })), ...errors('BadRequest', 'Unauthorized', 'NotFound', 'Conflict', 'Unprocessable') }
    })
  },
  '/api/v1/attestation-submission-grants/{id}/revoke': {
    post: op('revokeSubmissionGrant', 'Revoke a grant (final).', ['Owner'], OWNER, { parameters: [pathParam('id', 'The grant.')], responses: { '200': ok('Revoked.', obj({ grant: ref('SubmissionGrant') })), ...errors('Unauthorized', 'NotFound') } })
  },
  '/api/v1/webhook-endpoints': {
    get: op('listWebhookEndpoints', 'Your webhook endpoints, with delivery counts.', ['Webhooks'], OWNER, { responses: { '200': ok('The endpoints.', obj({ endpoints: arr(ref('WebhookEndpointSummary')) })), ...errors('Unauthorized') } }),
    post: op('createWebhookEndpoint', 'Register an https address to receive events. The signing secret is shown once.', ['Webhooks'], OWNER, {
      description: 'The address must be https with a host name, and every address it resolves to must be public (checked now and before every delivery). See `docs/WEBHOOKS.md` for how to verify what you receive.',
      requestBody: jsonBody(ref('WebhookEndpointRequest')), responses: { '201': ok('Registered.', ref('WebhookEndpointWithSecret')), ...errors('BadRequest', 'Unauthorized', 'NotFound', 'Conflict', 'Unprocessable', 'TooMany', 'Unavailable') }
    })
  },
  '/api/v1/webhook-endpoints/{id}/rotate-secret': {
    post: op('rotateWebhookSecret', 'Make a new signing secret (the old one stops being used at once).', ['Webhooks'], OWNER, { parameters: [pathParam('id', 'The endpoint.')], responses: { '200': ok('Rotated; the secret is shown once.', ref('WebhookEndpointWithSecret')), ...errors('Unauthorized', 'NotFound', 'Unavailable') } })
  },
  '/api/v1/webhook-endpoints/{id}/disable': {
    post: op('disableWebhookEndpoint', 'Stop sending to an endpoint.', ['Webhooks'], OWNER, { parameters: [pathParam('id', 'The endpoint.')], responses: { '200': ok('Disabled.', obj({ endpoint: ref('WebhookEndpoint') })), ...errors('Unauthorized', 'NotFound') } })
  },
  '/api/v1/webhook-endpoints/{id}/enable': {
    post: op('enableWebhookEndpoint', 'Resume sending (its address is checked again).', ['Webhooks'], OWNER, { parameters: [pathParam('id', 'The endpoint.')], responses: { '200': ok('Enabled.', obj({ endpoint: ref('WebhookEndpoint') })), ...errors('Unauthorized', 'NotFound', 'Unprocessable') } })
  },
  '/api/v1/webhook-endpoints/{id}/deliveries': {
    get: op('listWebhookDeliveries', 'The last 100 deliveries of an endpoint, and what went wrong.', ['Webhooks'], OWNER, { parameters: [pathParam('id', 'The endpoint.')], responses: { '200': ok('The deliveries.', obj({ deliveries: arr(ref('WebhookDelivery')) })), ...errors('Unauthorized', 'NotFound') } })
  }
};

export const openApiDocument: J = {
  openapi: '3.1.0',
  info: {
    title: 'Custody Core integration API',
    version: '1.0.0',
    summary: 'Let an outside platform request, work on, evidence and promote code under the creator\'s control.',
    'x-custody-contracts': { [SUBMISSION_CONTRACT.name]: { version: SUBMISSION_CONTRACT.version, scope: 'attestations:submit', route: 'POST /api/v2/work-sessions/{id}/attestations', claim: ATTRIBUTION_CLAIM, document: 'docs/contracts/commit-attribution-submission.v1.md' } },
    description: [
      'Machine callers sign in with a **client assertion**: a short-lived JWT signed with a key registered for their principal (EdDSA or ES256), sent as `Authorization: Bearer <jwt>` on every request. Claims: `iss` = `sub` = the principal id, `aud` = `custody-core`, `iat`, `exp` (at most 300 seconds after `iat`), a unique `jti`; header: `alg`, `kid` (the key id). What a caller may do comes from its principal\'s recorded scopes, never from the token.',
      'Owners use the `/api/v1` routes listed here with their signed-in session (a login with the authenticator code step). Approval and promotion decisions are only ever made there, by a person.',
      'Errors are `{ "error": "<words>", "code": "<stable reason, where there is one>" }`. Nothing in an error contains a secret.',
      'Guides: `docs/INTEGRATION.md` (the whole flow), `docs/WORK_SESSIONS.md`, `docs/WEBHOOKS.md`, `docs/EVENT_HASH_FORMAT.md`.'
    ].join('\n\n')
  },
  servers: [{ url: '/', description: 'This server (the app\'s public address).' }],
  tags: [{ name: 'Meta' }, { name: 'Work sessions' }, { name: 'Evidence' }, { name: 'Attribution' }, { name: 'Promotion' }, { name: 'Owner', description: 'For the project owner, signed in as a person.' }, { name: 'Webhooks', description: 'For the project owner.' }],
  paths,
  webhooks: {
    'custody-event': {
      post: {
        operationId: 'receiveCustodyEvent',
        summary: 'What your webhook endpoint receives for each event it subscribed to.',
        description: 'Signed with `Custody-Signature: t=<unix>,v1=<hex HMAC-SHA256 of "<t>.<raw body>" with your endpoint secret>`. Answer 2xx quickly; anything else (a redirect included) is retried after 1 minute, 5 minutes, 30 minutes, 2 hours and 6 hours, then given up. At least once and unordered: de-duplicate on `Custody-Event-Id`, order by `record.seq`. Reject a `t` more than five minutes old.',
        parameters: [
          { name: 'Custody-Signature', in: 'header', required: true, schema: { type: 'string' } }, { name: 'Custody-Event-Id', in: 'header', required: true, schema: ref('Uuid') },
          { name: 'Custody-Event-Type', in: 'header', required: true, schema: { type: 'string' } }, { name: 'Custody-Delivery-Id', in: 'header', required: true, schema: ref('Uuid') }, { name: 'Custody-Delivery-Attempt', in: 'header', required: true, schema: { type: 'integer', minimum: 1, maximum: 6 } }
        ],
        requestBody: jsonBody(ref('WebhookEvent')),
        responses: { '200': { description: 'Received (any 2xx).' } }
      }
    }
  },
  components: {
    securitySchemes: {
      principalAssertion: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT', description: 'A client assertion signed with a key registered for the principal (EdDSA or ES256). Claims: iss = sub = principal id, aud = "custody-core", iat, exp (at most 300 s after iat), jti (never reused). Header: alg, kid.' },
      ownerSession: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT', description: 'The owner\'s signed-in session (an access token that has passed the authenticator code step).' }
    },
    schemas,
    responses: {
      BadRequest: errorResponse('The request is not valid; the message says what.'),
      Unauthorized: errorResponse('No valid credentials.'),
      Forbidden: errorResponse('The credentials lack the scope this needs (or the person is not the one allowed to decide).'),
      NotFound: errorResponse('No such thing, or not one you may see (the two look the same on purpose).'),
      Conflict: errorResponse('The thing is in a state that does not allow this, or already exists.'),
      Unprocessable: errorResponse('Understood, but refused for a stated reason (see `code`).'),
      TooMany: errorResponse('A limit was reached.'),
      Unavailable: errorResponse('A needed service (database, secret scanner, repository host) is not available. Nothing was recorded.')
    }
  }
};
