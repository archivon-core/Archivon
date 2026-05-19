CREATE INDEX IF NOT EXISTS folder_permissions_folder_idx
  ON folder_permissions(protected_folder_id, user_id);

CREATE INDEX IF NOT EXISTS folder_permissions_effective_idx
  ON folder_permissions(user_id, protected_folder_id, expires_at)
  WHERE can_view_folder = true;

CREATE INDEX IF NOT EXISTS file_denies_file_idx
  ON file_denies(file_id, user_id);

INSERT INTO system_settings (key, value)
VALUES (
  'access_rights_policy',
  '{"scope":"per-user","groups_enabled":false,"flags":["view_folder","list_files","unlock_and_access"],"file_level_deny":true,"download_requires_pow":true}'::jsonb
)
ON CONFLICT (key) DO UPDATE
SET value = excluded.value,
    updated_at = now();
