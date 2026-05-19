ALTER TABLE access_sessions
  ADD COLUMN IF NOT EXISTS dav_password_ciphertext bytea,
  ADD COLUMN IF NOT EXISTS dav_password_nonce bytea;

CREATE UNIQUE INDEX IF NOT EXISTS access_sessions_active_dav_username_idx
  ON access_sessions(dav_username)
  WHERE status = 'active' AND dav_username IS NOT NULL;

INSERT INTO system_settings (key, value)
VALUES (
  'webdav_access_policy',
  '{
    "enabled": true,
    "read_only": true,
    "requires_basic_auth": true,
    "requires_active_access_session": true,
    "requires_can_view_folder": true,
    "requires_can_list_files": true,
    "requires_can_unlock_and_access": true,
    "file_denies_hide_entries": true,
    "allowed_methods": ["OPTIONS", "PROPFIND", "GET", "HEAD"],
    "denied_methods": ["PUT", "DELETE", "MKCOL", "MOVE", "COPY", "PROPPATCH", "LOCK", "UNLOCK"]
  }'::jsonb
)
ON CONFLICT (key) DO NOTHING;
