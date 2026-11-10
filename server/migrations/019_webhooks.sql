-- ---------------------------------------------------------------------------------------------------------
-- Phase 9: signed outbound webhooks (docs/integration/PHASE9_DESIGN.md).
--
--   webhook_endpoint  an https address the owner wants told about events of their projects; its signing secret is stored ENCRYPTED (never a hash:
--                     a hash cannot sign anything)
--   webhook_delivery  one row per (endpoint, event), created by a trigger in the same transaction as the event (nothing can be recorded without
--                     being owed, nothing is lost if the server is down); it only ever moves forward: pending -> delivered | dead
--   webhook_attempt   one immutable row per try, for the record
-- ---------------------------------------------------------------------------------------------------------

-- A subscription is "*", an exact event name ("promotion.completed"), or a family ("promotion.*").
CREATE FUNCTION webhook_events_valid(p text[]) RETURNS boolean
LANGUAGE sql IMMUTABLE AS $$
  SELECT cardinality(p) BETWEEN 1 AND 20
     AND NOT EXISTS (SELECT 1 FROM unnest(p) e WHERE e IS NULL OR e !~ '^(\*|[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*(\.\*)?)$' OR char_length(e) > 100)
$$;

CREATE FUNCTION webhook_event_matches(p text[], action text) RETURNS boolean
LANGUAGE sql IMMUTABLE AS $$
  SELECT EXISTS (
    SELECT 1 FROM unnest(p) e
     WHERE e = '*' OR e = action OR (right(e, 2) = '.*' AND starts_with(action, left(e, char_length(e) - 1)))
  )
$$;

CREATE TABLE webhook_endpoint (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  creator_id UUID NOT NULL REFERENCES creator (id) ON DELETE CASCADE,
  name TEXT NOT NULL CHECK (char_length(name) BETWEEN 1 AND 100),
  url TEXT NOT NULL CHECK (url ~ '^https://[^/?#@[:space:]]+' AND char_length(url) <= 2000),
  secret_ciphertext TEXT NOT NULL CHECK (secret_ciphertext ~ '^v1\.'),
  subscribed_events TEXT[] NOT NULL CHECK (webhook_events_valid(subscribed_events)),
  project_ids UUID[],                       -- NULL: every project of this owner
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  secret_rotated_at TIMESTAMPTZ,
  disabled_at TIMESTAMPTZ,
  CONSTRAINT uq_webhook_endpoint_name UNIQUE (creator_id, name),
  CONSTRAINT chk_webhook_disabled CHECK ((status = 'disabled') = (disabled_at IS NOT NULL))
);

CREATE FUNCTION webhook_endpoint_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'webhook_endpoint %: cannot be deleted, only disabled', OLD.id USING ERRCODE = 'check_violation';
  END IF;
  IF NEW.id <> OLD.id OR NEW.creator_id <> OLD.creator_id OR NEW.created_at <> OLD.created_at OR NEW.name <> OLD.name
     OR NEW.url <> OLD.url OR NEW.subscribed_events <> OLD.subscribed_events OR NEW.project_ids IS DISTINCT FROM OLD.project_ids THEN
    RAISE EXCEPTION 'webhook_endpoint %: only the secret and the enabled state can change (make a new endpoint to change where or what)', OLD.id USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER trg_webhook_endpoint_guard BEFORE UPDATE OR DELETE ON webhook_endpoint FOR EACH ROW EXECUTE FUNCTION webhook_endpoint_guard();

CREATE TABLE webhook_delivery (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  endpoint_id UUID NOT NULL REFERENCES webhook_endpoint (id),
  -- Deliberately not a foreign key: nothing may reference the append-only event table in a way that changes how it can be refused or truncated.
  -- The trigger below is the only thing that creates these rows, from an event that has just been written.
  event_id UUID NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'delivered', 'dead')),
  attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 20),
  next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  payload_sha256 CHAR(64) CHECK (payload_sha256 IS NULL OR payload_sha256 ~ '^[0-9a-f]{64}$'),
  last_status INTEGER,
  last_error TEXT CHECK (last_error IS NULL OR char_length(last_error) <= 300),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  delivered_at TIMESTAMPTZ,
  CONSTRAINT uq_webhook_delivery UNIQUE (endpoint_id, event_id),
  CONSTRAINT chk_webhook_delivered CHECK ((status = 'delivered') = (delivered_at IS NOT NULL))
);
CREATE INDEX idx_webhook_delivery_due ON webhook_delivery (next_attempt_at) WHERE status = 'pending';
CREATE INDEX idx_webhook_delivery_endpoint ON webhook_delivery (endpoint_id, created_at DESC);

-- Bookkeeping only: what is owed and to whom never changes, a finished delivery is final, the attempt count goes up by one at a time,
-- and the body that was signed is the same every time.
CREATE FUNCTION webhook_delivery_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'webhook_delivery %: cannot be deleted', OLD.id USING ERRCODE = 'check_violation';
  END IF;
  IF NEW.id <> OLD.id OR NEW.endpoint_id <> OLD.endpoint_id OR NEW.event_id <> OLD.event_id OR NEW.created_at <> OLD.created_at THEN
    RAISE EXCEPTION 'webhook_delivery %: what is owed, and to whom, cannot change', OLD.id USING ERRCODE = 'check_violation';
  END IF;
  IF OLD.status <> 'pending' THEN
    RAISE EXCEPTION 'webhook_delivery %: a finished delivery is final', OLD.id USING ERRCODE = 'check_violation';
  END IF;
  IF NEW.attempts < OLD.attempts OR NEW.attempts > OLD.attempts + 1 THEN
    RAISE EXCEPTION 'webhook_delivery %: attempts go up one at a time', OLD.id USING ERRCODE = 'check_violation';
  END IF;
  IF OLD.payload_sha256 IS NOT NULL AND NEW.payload_sha256 IS DISTINCT FROM OLD.payload_sha256 THEN
    RAISE EXCEPTION 'webhook_delivery %: the signed body cannot change between attempts', OLD.id USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER trg_webhook_delivery_guard BEFORE UPDATE OR DELETE ON webhook_delivery FOR EACH ROW EXECUTE FUNCTION webhook_delivery_guard();

CREATE TABLE webhook_attempt (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  delivery_id UUID NOT NULL REFERENCES webhook_delivery (id),
  attempt INTEGER NOT NULL CHECK (attempt >= 1),
  started_at TIMESTAMPTZ NOT NULL,
  duration_ms INTEGER NOT NULL CHECK (duration_ms >= 0),
  outcome TEXT NOT NULL CHECK (outcome IN ('delivered', 'http_error', 'network_error', 'timeout', 'blocked_address', 'endpoint_unavailable')),
  http_status INTEGER,
  error TEXT CHECK (error IS NULL OR char_length(error) <= 300),
  CONSTRAINT uq_webhook_attempt UNIQUE (delivery_id, attempt)
);
CREATE TRIGGER trg_webhook_attempt_immutable BEFORE UPDATE OR DELETE ON webhook_attempt FOR EACH ROW EXECUTE FUNCTION session_record_immutable();

-- Fan-out: when an event is written, every active endpoint of the project's owner that subscribed to it is owed a delivery, in the same transaction.
CREATE FUNCTION webhook_fan_out() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
  INSERT INTO webhook_delivery (endpoint_id, event_id)
  SELECT e.id, NEW.id
    FROM webhook_endpoint e JOIN project p ON p.id = NEW.project_id
   WHERE e.status = 'active' AND e.creator_id = p.creator_id
     AND (e.project_ids IS NULL OR NEW.project_id = ANY (e.project_ids))
     AND webhook_event_matches(e.subscribed_events, NEW.action)
  ON CONFLICT (endpoint_id, event_id) DO NOTHING;
  RETURN NEW;
END
$$;
REVOKE ALL ON FUNCTION webhook_fan_out() FROM PUBLIC;
CREATE TRIGGER trg_event_webhook_fan_out AFTER INSERT ON event FOR EACH ROW EXECUTE FUNCTION webhook_fan_out();
