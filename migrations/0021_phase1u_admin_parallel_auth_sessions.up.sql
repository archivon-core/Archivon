ALTER TABLE user_sessions
  ADD COLUMN IF NOT EXISTS role_at_login text;

UPDATE user_sessions us
SET role_at_login = u.role
FROM users u
WHERE us.tenant_id = u.tenant_id
  AND us.user_id = u.id
  AND us.role_at_login IS NULL;

UPDATE user_sessions
SET role_at_login = 'client'
WHERE role_at_login IS NULL;

ALTER TABLE user_sessions
  ALTER COLUMN role_at_login SET NOT NULL;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'user_sessions_role_at_login_check'
  ) THEN
    ALTER TABLE user_sessions
      ADD CONSTRAINT user_sessions_role_at_login_check
      CHECK (role_at_login IN ('super_admin', 'admin', 'client'));
  END IF;
END $$;

DROP INDEX IF EXISTS user_sessions_one_active_per_user_idx;

CREATE UNIQUE INDEX IF NOT EXISTS user_sessions_one_active_client_per_user_idx
  ON user_sessions(tenant_id, user_id)
  WHERE status = 'active' AND role_at_login = 'client';

INSERT INTO system_settings (key, value)
VALUES
  ('auth_single_active_session', '{"enabled":true,"client_mode":"latest_login_wins","admin_mode":"parallel_allowed","super_admin_mode":"parallel_allowed","auth_ttl_hours":12}'::jsonb)
ON CONFLICT (key) DO UPDATE
SET value = excluded.value,
    updated_at = now();
