CREATE TABLE IF NOT EXISTS admin_dav_sessions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  protected_folder_id uuid NOT NULL REFERENCES protected_folders(id) ON DELETE CASCADE,
  dav_username text NOT NULL UNIQUE,
  dav_password_hash text NOT NULL,
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked', 'expired')),
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz
);

CREATE INDEX IF NOT EXISTS admin_dav_sessions_active_idx
  ON admin_dav_sessions(tenant_id, user_id, protected_folder_id, status, expires_at);

CREATE UNIQUE INDEX IF NOT EXISTS admin_dav_sessions_one_active_per_user_folder_idx
  ON admin_dav_sessions(tenant_id, user_id, protected_folder_id)
  WHERE status = 'active';

INSERT INTO system_settings (key, value)
VALUES (
  'admin_webdav_upload_policy',
  '{
    "enabled": true,
    "scope": "selected_folder",
    "roles": ["super_admin", "admin"],
    "ttl_hours": 12,
    "client_webdav_remains_read_only": true,
    "allowed_methods": ["OPTIONS", "PROPFIND", "GET", "HEAD", "PUT", "MKCOL", "LOCK", "UNLOCK"],
    "denied_methods": ["DELETE", "MOVE", "COPY", "PROPPATCH"]
  }'::jsonb
)
ON CONFLICT (key) DO UPDATE
SET value = EXCLUDED.value,
    updated_at = now();
