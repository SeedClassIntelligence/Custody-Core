-- 003: the database builds the event chain; the application can no longer write chain fields.
--
-- Events written before this migration keep hash_version = 1 (hashed by application code) and still
-- verify. Every event written by append_event() has hash_version = 2. See docs/EVENT_HASH_FORMAT.md.

ALTER TABLE event ADD COLUMN hash_version SMALLINT NOT NULL DEFAULT 1;
-- Exact payload text that was hashed (version 2 only). The hash covers this text byte for byte.
ALTER TABLE event ADD COLUMN canonical_payload TEXT;

ALTER TABLE event ADD CONSTRAINT chk_event_hash_version CHECK (hash_version IN (1, 2));
ALTER TABLE event ADD CONSTRAINT chk_event_v2_canonical_payload
  CHECK (hash_version = 1 OR (canonical_payload IS NOT NULL AND payload = canonical_payload::jsonb));

-- Canonical JSON text of a jsonb value:
--   * objects: keys sorted by Unicode code point (byte order of UTF-8), no whitespace
--   * arrays: order preserved
--   * strings: JSON-escaped exactly as JavaScript JSON.stringify does (non-ASCII left as is)
--   * numbers: exact decimal, no exponent, no trailing zeros ("100.0" -> "100", "1e3" -> "1000")
--   * true / false / null as literals
CREATE FUNCTION canonical_jsonb(j jsonb) RETURNS text
LANGUAGE plpgsql IMMUTABLE STRICT
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  kind text := jsonb_typeof(j);
  result text;
BEGIN
  IF kind = 'object' THEN
    SELECT '{' || coalesce(
             string_agg(to_jsonb(e.key)::text || ':' || public.canonical_jsonb(e.value), ',' ORDER BY e.key COLLATE "C"),
             '') || '}'
      INTO result
      FROM jsonb_each(j) AS e;
    RETURN result;
  ELSIF kind = 'array' THEN
    SELECT '[' || coalesce(string_agg(public.canonical_jsonb(a.value), ',' ORDER BY a.ord), '') || ']'
      INTO result
      FROM jsonb_array_elements(j) WITH ORDINALITY AS a(value, ord);
    RETURN result;
  ELSIF kind = 'string' OR kind = 'boolean' THEN
    RETURN j::text;
  ELSIF kind = 'number' THEN
    RETURN trim_scale(j::text::numeric)::text;
  END IF;
  RETURN 'null';
END
$$;

-- The only way to write an event. The caller says what happened; the database assigns the
-- sequence number, previous hash, timestamp and hash. None of those can be supplied.
CREATE FUNCTION append_event(
  p_project_id uuid,
  p_actor_type text,
  p_actor_id text,
  p_action text,
  p_subject_type text,
  p_subject_id text,
  p_payload jsonb
) RETURNS public.event
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
  v_row public.event;
BEGIN
  IF p_project_id IS NULL OR p_actor_type IS NULL OR p_actor_id IS NULL OR p_action IS NULL
     OR p_subject_type IS NULL OR p_subject_id IS NULL OR p_payload IS NULL THEN
    RAISE EXCEPTION 'append_event: every argument is required' USING ERRCODE = 'null_value_not_allowed';
  END IF;
  IF p_actor_type NOT IN ('creator', 'developer', 'system', 'gateway') THEN
    RAISE EXCEPTION 'append_event: unknown actor_type %', p_actor_type USING ERRCODE = 'check_violation';
  END IF;
  IF p_actor_id = '' OR p_action = '' OR p_subject_type = '' OR p_subject_id = '' THEN
    RAISE EXCEPTION 'append_event: actor_id, action, subject_type and subject_id must not be empty'
      USING ERRCODE = 'check_violation';
  END IF;
  IF jsonb_typeof(p_payload) <> 'object' THEN
    RAISE EXCEPTION 'append_event: payload must be a JSON object' USING ERRCODE = 'check_violation';
  END IF;

  -- Lock the project so two writers cannot take the same sequence number or branch the chain.
  PERFORM 1 FROM public.project WHERE id = p_project_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'append_event: project % does not exist', p_project_id USING ERRCODE = 'foreign_key_violation';
  END IF;

  SELECT e.seq, e.hash INTO v_seq, v_prev_hash
    FROM public.event e
   WHERE e.project_id = p_project_id
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

  -- Hash input: one JSON object, keys in alphabetical order, no whitespace, payload embedded as
  -- its canonical text. Identical to what shared/crypto.ts builds for hash_version 2.
  v_hash := encode(sha256(convert_to(
    '{"action":' || to_jsonb(p_action)::text ||
    ',"actor_id":' || to_jsonb(p_actor_id)::text ||
    ',"actor_type":' || to_jsonb(p_actor_type)::text ||
    ',"payload":' || v_canonical ||
    ',"prev_hash":' || to_jsonb(v_prev_hash)::text ||
    ',"project_id":' || to_jsonb(p_project_id::text)::text ||
    ',"seq":' || v_seq::text ||
    ',"subject_id":' || to_jsonb(p_subject_id)::text ||
    ',"subject_type":' || to_jsonb(p_subject_type)::text ||
    ',"timestamp":' || to_jsonb(v_ts)::text ||
    '}', 'UTF8')), 'hex');

  INSERT INTO public.event (
    seq, project_id, actor_type, actor_id, action, subject_type, subject_id,
    payload, prev_hash, hash, seed_signature_id, hashed_timestamp, created_at, updated_at,
    hash_version, canonical_payload
  ) VALUES (
    v_seq, p_project_id, p_actor_type, p_actor_id, p_action, p_subject_type, p_subject_id,
    p_payload, v_prev_hash, v_hash, '', v_ts, v_now, v_now,
    2, v_canonical
  ) RETURNING * INTO v_row;

  RETURN v_row;
END
$$;

REVOKE ALL ON FUNCTION append_event(uuid, text, text, text, text, text, jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION canonical_jsonb(jsonb) FROM PUBLIC;
