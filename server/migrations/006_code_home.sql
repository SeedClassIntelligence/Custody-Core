-- 006: Code home (GitHub). A creator's GitHub organization, connected through the Custody Core GitHub App.
--
-- Only the installation's id is stored, never a token: tokens are requested per operation and revoked after it.

-- The app installed on a creator's organization. Linked to the creator only after GitHub itself confirmed,
-- through a signed-in GitHub user, that this installation belongs to them (server/github/connect.ts).
CREATE TABLE github_installation (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  creator_id UUID NOT NULL REFERENCES creator (id),
  installation_id BIGINT NOT NULL UNIQUE,
  account_login TEXT NOT NULL,            -- the organization's name on GitHub
  account_id BIGINT NOT NULL,
  owner_login TEXT,                       -- the GitHub user GitHub confirmed as an owner when connecting
  status TEXT NOT NULL CHECK (status IN ('active', 'suspended', 'removed')),
  connected_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  status_changed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- One working code home per creator.
CREATE UNIQUE INDEX uq_github_installation_one_active ON github_installation (creator_id) WHERE status <> 'removed';

-- One-time codes that tie a GitHub installation round trip to the creator who started it. Only a hash is kept.
CREATE TABLE github_connect_state (
  state_hash CHAR(64) PRIMARY KEY,
  creator_id UUID NOT NULL REFERENCES creator (id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL,
  installation_hint BIGINT,               -- what GitHub's redirect said; only trusted after GitHub confirms it
  used_at TIMESTAMPTZ
);

-- Every webhook GitHub sent us that passed the signature check, once (GitHub may deliver the same one again).
CREATE TABLE github_webhook_delivery (
  delivery_id TEXT PRIMARY KEY,
  event TEXT NOT NULL,
  action TEXT,
  installation_id BIGINT,
  received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  outcome TEXT NOT NULL
);

-- Repositories now come from GitHub: which installation created them, and GitHub's own id.
ALTER TABLE repository ADD COLUMN installation_id BIGINT;
CREATE UNIQUE INDEX uq_repository_github_repo_id ON repository (github_repo_id) WHERE github_repo_id <> '';
