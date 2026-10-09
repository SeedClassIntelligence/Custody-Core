-- 009: the scheduler (doors close at their end date, locks are re-checked) and backup snapshots on close.
--
-- When a door that was open closes (by the creator or at its end date), a snapshot of its work is due: for each of
-- the door's repositories, a git bundle of the default branch and the door's own branches, fetched from GitHub,
-- verified, and stored with its SHA-256. Closing never waits for it: the door records that a snapshot is pending,
-- and the scheduler takes it, retrying if GitHub or the storage is unavailable.

ALTER TABLE door ADD COLUMN snapshot_status TEXT CHECK (snapshot_status IN ('pending', 'done', 'failed'));
ALTER TABLE door ADD COLUMN snapshot_attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE door ADD COLUMN snapshot_next_attempt_at TIMESTAMPTZ;
ALTER TABLE door ADD COLUMN snapshot_error TEXT;
CREATE INDEX idx_door_snapshot_pending ON door (snapshot_next_attempt_at) WHERE snapshot_status = 'pending';
CREATE INDEX idx_door_open_expiry ON door (expires_at) WHERE status IN ('draft', 'awaiting_signature', 'open');

ALTER TABLE mirror_snapshot ADD COLUMN door_id UUID REFERENCES door (id);
ALTER TABLE mirror_snapshot ADD COLUMN trigger TEXT;
ALTER TABLE mirror_snapshot ADD COLUMN refs JSONB;          -- {"refs/heads/main": "<sha>", ...} as bundled
CREATE INDEX idx_mirror_snapshot_door ON mirror_snapshot (door_id);

-- A snapshot record never changes once written.
CREATE FUNCTION mirror_snapshot_is_final() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'mirror_snapshot %: a snapshot record cannot be changed or deleted', OLD.id USING ERRCODE = 'check_violation';
END
$$;
CREATE TRIGGER trg_mirror_snapshot_is_final BEFORE UPDATE OR DELETE ON mirror_snapshot FOR EACH ROW EXECUTE FUNCTION mirror_snapshot_is_final();
