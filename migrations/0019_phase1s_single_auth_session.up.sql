UPDATE user_sessions
SET status = 'expired'
WHERE status = 'active'
  AND expires_at <= now();

WITH ranked_sessions AS (
  SELECT id,
         row_number() OVER (
           PARTITION BY tenant_id, user_id
           ORDER BY created_at DESC, expires_at DESC, id DESC
         ) AS rn
  FROM user_sessions
  WHERE status = 'active'
)
UPDATE user_sessions us
SET status = 'revoked',
    revoked_at = now()
FROM ranked_sessions ranked
WHERE us.id = ranked.id
  AND ranked.rn > 1;

CREATE UNIQUE INDEX IF NOT EXISTS user_sessions_one_active_per_user_idx
  ON user_sessions(tenant_id, user_id)
  WHERE status = 'active';

INSERT INTO system_settings (key, value)
VALUES
  ('auth_single_active_session', '{"enabled":true,"mode":"deny_second_login"}'::jsonb)
ON CONFLICT (key) DO UPDATE
SET value = excluded.value,
    updated_at = now();
