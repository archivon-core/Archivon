CREATE TABLE IF NOT EXISTS user_sessions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash char(64) NOT NULL UNIQUE,
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked', 'expired')),
  ip_address text,
  user_agent text,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz
);

CREATE INDEX IF NOT EXISTS user_sessions_user_status_idx
  ON user_sessions(user_id, status, expires_at);

CREATE INDEX IF NOT EXISTS user_sessions_expires_idx
  ON user_sessions(expires_at)
  WHERE status = 'active';

CREATE UNIQUE INDEX IF NOT EXISTS users_single_super_admin_bootstrap_idx
  ON users(tenant_id)
  WHERE role = 'super_admin';

INSERT INTO system_settings (key, value)
VALUES
  ('password_policy', '{"min_length":10}'::jsonb),
  ('auth_session_ttl_hours', '{"default":12}'::jsonb)
ON CONFLICT (key) DO NOTHING;
