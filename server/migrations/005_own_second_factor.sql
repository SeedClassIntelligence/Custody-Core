-- 005: Custody Core runs the authenticator-app (second factor) step itself.
--
-- Supabase Auth keeps handling email and password. The 6-digit code step moves here so that wrong codes can
-- be limited: Supabase's own code-check endpoint is public and cannot be limited on every plan, so a limit
-- that only watched our server could be bypassed by guessing there. Codes are now checked only by this
-- server, against keys stored here (encrypted by the server; the database never sees a key in the clear).

-- One row per authenticator. Only one verified authenticator per login.
CREATE TABLE mfa_factor (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  identity_id TEXT NOT NULL,              -- the login system's user id (creator.identity_id)
  secret_ciphertext TEXT NOT NULL,        -- AES-256-GCM, key held by the server only
  status TEXT NOT NULL CHECK (status IN ('unverified', 'verified', 'abandoned')),
  last_used_step BIGINT,                  -- TOTP time step of the last accepted code (blocks reuse)
  locked_until TIMESTAMPTZ,               -- set after too many wrong codes
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  verified_at TIMESTAMPTZ
);
CREATE UNIQUE INDEX uq_mfa_factor_one_verified ON mfa_factor (identity_id) WHERE status = 'verified';
CREATE INDEX idx_mfa_factor_identity ON mfa_factor (identity_id);

-- Every code attempt, kept in the database so limits survive restarts and cover every server instance.
CREATE TABLE mfa_attempt (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  factor_id UUID NOT NULL REFERENCES mfa_factor (id),
  identity_id TEXT NOT NULL,
  outcome TEXT NOT NULL CHECK (outcome IN ('accepted', 'wrong_code', 'reused_code', 'locked')),
  attempted_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_mfa_attempt_factor_time ON mfa_attempt (factor_id, attempted_at);

-- A login session (Supabase session id) that has passed the code step on this server.
CREATE TABLE mfa_session (
  session_id TEXT PRIMARY KEY,
  identity_id TEXT NOT NULL,
  factor_id UUID NOT NULL REFERENCES mfa_factor (id),
  verified_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------------------------------------
-- Account record: an append-only, hash-chained log per login, for things that belong to the account rather
-- than to one project (for example a lockout after too many wrong codes). Built by the database, exactly
-- like the project event chain (see docs/EVENT_HASH_FORMAT.md, "Account events").
-- ---------------------------------------------------------------------------------------------------------
CREATE TABLE account_event (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  account_id TEXT NOT NULL,               -- the login system's user id
  seq BIGINT NOT NULL,
  actor_type TEXT NOT NULL,
  actor_id TEXT NOT NULL,
  action TEXT NOT NULL,
  payload JSONB NOT NULL,
  canonical_payload TEXT NOT NULL,
  prev_hash CHAR(64) NOT NULL,
  hash CHAR(64) NOT NULL,
  hashed_timestamp TEXT NOT NULL CHECK (hashed_timestamp <> ''),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT uq_account_event_seq UNIQUE (account_id, seq),
  CONSTRAINT chk_account_event_payload CHECK (payload = canonical_payload::jsonb)
);

CREATE FUNCTION reject_account_event_change() RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  RAISE EXCEPTION 'Table account_event is append-only: % operations are strictly forbidden.', TG_OP;
END
$$;

CREATE TRIGGER trg_account_event_append_only
  BEFORE UPDATE OR DELETE ON account_event
  FOR EACH ROW EXECUTE FUNCTION reject_account_event_change();
CREATE TRIGGER trg_account_event_prevent_truncate
  BEFORE TRUNCATE ON account_event
  FOR EACH STATEMENT EXECUTE FUNCTION reject_account_event_change();

CREATE FUNCTION append_account_event(
  p_account_id text,
  p_actor_type text,
  p_actor_id text,
  p_action text,
  p_payload jsonb
) RETURNS public.account_event
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_seq bigint;
  v_prev_hash text;
  v_now timestamptz;
  v_ts text;
  v_canonical text;
  v_hash text;
  v_row public.account_event;
BEGIN
  IF p_account_id IS NULL OR p_actor_type IS NULL OR p_actor_id IS NULL OR p_action IS NULL OR p_payload IS NULL THEN
    RAISE EXCEPTION 'append_account_event: every argument is required' USING ERRCODE = 'null_value_not_allowed';
  END IF;
  IF p_actor_type NOT IN ('creator', 'developer', 'system', 'gateway') THEN
    RAISE EXCEPTION 'append_account_event: unknown actor_type %', p_actor_type USING ERRCODE = 'check_violation';
  END IF;
  IF p_account_id ~ '^[[:space:]]*$' OR p_actor_id ~ '^[[:space:]]*$' OR p_action ~ '^[[:space:]]*$' THEN
    RAISE EXCEPTION 'append_account_event: account_id, actor_id and action must not be empty' USING ERRCODE = 'check_violation';
  END IF;
  IF jsonb_typeof(p_payload) <> 'object' THEN
    RAISE EXCEPTION 'append_account_event: payload must be a JSON object' USING ERRCODE = 'check_violation';
  END IF;
  IF octet_length(p_payload::text) > 65536 THEN
    RAISE EXCEPTION 'append_account_event: payload is larger than 64 KiB' USING ERRCODE = 'program_limit_exceeded';
  END IF;

  -- One writer at a time per account, so sequence numbers and links never branch.
  PERFORM pg_advisory_xact_lock(hashtextextended('account_event:' || p_account_id, 0));

  SELECT e.seq, e.hash INTO v_seq, v_prev_hash
    FROM public.account_event e
   WHERE e.account_id = p_account_id
   ORDER BY e.seq DESC
   LIMIT 1;
  IF NOT FOUND THEN
    v_seq := 0;
    v_prev_hash := repeat('0', 64);
  END IF;
  v_seq := v_seq + 1;

  v_now := clock_timestamp();
  v_ts := to_char(v_now AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
  v_canonical := public.canonical_jsonb(p_payload);

  v_hash := encode(sha256(convert_to(
    '{"account_id":' || to_jsonb(p_account_id)::text ||
    ',"action":' || to_jsonb(p_action)::text ||
    ',"actor_id":' || to_jsonb(p_actor_id)::text ||
    ',"actor_type":' || to_jsonb(p_actor_type)::text ||
    ',"payload":' || v_canonical ||
    ',"prev_hash":' || to_jsonb(v_prev_hash)::text ||
    ',"seq":' || v_seq::text ||
    ',"timestamp":' || to_jsonb(v_ts)::text ||
    '}', 'UTF8')), 'hex');

  INSERT INTO public.account_event (
    account_id, seq, actor_type, actor_id, action, payload, canonical_payload, prev_hash, hash, hashed_timestamp, created_at
  ) VALUES (
    p_account_id, v_seq, p_actor_type, p_actor_id, p_action, p_payload, v_canonical, v_prev_hash, v_hash, v_ts, v_now
  ) RETURNING * INTO v_row;

  RETURN v_row;
END
$$;

REVOKE ALL ON FUNCTION append_account_event(text, text, text, text, jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION reject_account_event_change() FROM PUBLIC;
