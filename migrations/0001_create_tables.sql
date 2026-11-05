PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS workspaces (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS workspace_members (
  workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  email TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('owner', 'admin', 'editor', 'viewer')),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY(workspace_id, email)
);
CREATE INDEX IF NOT EXISTS idx_member_email ON workspace_members(email);

CREATE TABLE IF NOT EXISTS oauth_states (
  id_hash TEXT PRIMARY KEY,
  nonce_hash TEXT NOT NULL,
  workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  email TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  used_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_oauth_state_expires ON oauth_states(expires_at);

CREATE TABLE IF NOT EXISTS social_connections (
  id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  provider TEXT NOT NULL DEFAULT 'facebook',
  page_id TEXT NOT NULL,
  page_name TEXT NOT NULL,
  encrypted_page_token TEXT NOT NULL,
  page_tasks TEXT NOT NULL DEFAULT '[]',
  connected_by TEXT NOT NULL,
  connected_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(workspace_id, provider, page_id)
);
CREATE INDEX IF NOT EXISTS idx_connections_workspace ON social_connections(workspace_id);
