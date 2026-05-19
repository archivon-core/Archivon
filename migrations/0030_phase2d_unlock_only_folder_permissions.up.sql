DROP INDEX IF EXISTS folder_permissions_effective_idx;

UPDATE folder_permissions
SET can_view_folder = can_unlock_and_access,
    can_list_files = can_unlock_and_access,
    updated_at = now()
WHERE can_view_folder IS DISTINCT FROM can_unlock_and_access
   OR can_list_files IS DISTINCT FROM can_unlock_and_access;

ALTER TABLE folder_permissions
  DROP COLUMN IF EXISTS can_view_folder,
  DROP COLUMN IF EXISTS can_list_files;

CREATE INDEX IF NOT EXISTS folder_permissions_unlock_idx
  ON folder_permissions(user_id, protected_folder_id, expires_at)
  WHERE can_unlock_and_access = true;

INSERT INTO system_settings (key, value)
VALUES (
  'access_rights_policy',
  '{"scope":"per-user","groups_enabled":false,"flags":["unlock_and_access"],"folder_visibility":"unlock_only","file_level_deny":false,"download_requires_pow":true}'::jsonb
)
ON CONFLICT (key) DO UPDATE
SET value = EXCLUDED.value,
    updated_at = now();

UPDATE system_settings
SET value = value - 'client_download_requires_can_view_folder' - 'client_download_requires_can_list_files',
    updated_at = now()
WHERE key = 'download_access_policy';

UPDATE system_settings
SET value = value - 'requires_can_view_folder' - 'requires_can_list_files',
    updated_at = now()
WHERE key = 'webdav_access_policy';
