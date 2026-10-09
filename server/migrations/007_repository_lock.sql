-- 007: locking a project's repositories on GitHub.
--
-- When a repository is added to a project, Custody Core puts a ruleset on it: the default branch cannot be
-- deleted or force-pushed by anyone except the Custody Core GitHub App, and forking is turned off where GitHub
-- allows it. The repository counts as locked (locked_at) only after the ruleset has been read back from GitHub
-- and checked. Every check after that reads it back again and records it if it was removed or changed.

ALTER TABLE repository ADD COLUMN lock_ruleset_id BIGINT;
ALTER TABLE repository ADD COLUMN lock_checked_at TIMESTAMPTZ;
-- Why the last attempt did not lock it, in words for the creator (for example the GitHub plan does not allow
-- rulesets on private repositories). Empty when locked.
ALTER TABLE repository ADD COLUMN lock_error TEXT;
