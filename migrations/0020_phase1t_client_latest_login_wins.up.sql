INSERT INTO system_settings (key, value)
VALUES
  ('auth_single_active_session', '{"enabled":true,"client_mode":"latest_login_wins","admin_mode":"deny_second_login"}'::jsonb)
ON CONFLICT (key) DO UPDATE
SET value = excluded.value,
    updated_at = now();
