DROP INDEX IF EXISTS file_denies_file_idx;
DROP TABLE IF EXISTS file_denies;

INSERT INTO system_settings (key, value)
VALUES (
  'access_rights_policy',
  '{"scope":"per-user","groups_enabled":false,"flags":["view_folder","list_files","unlock_and_access"],"file_level_deny":false,"download_requires_pow":true}'::jsonb
)
ON CONFLICT (key) DO UPDATE
SET value = EXCLUDED.value,
    updated_at = now();

UPDATE system_settings
SET value = value - 'file_denies_hide_download',
    updated_at = now()
WHERE key = 'download_access_policy';

UPDATE system_settings
SET value = value - 'file_denies_hide_entries',
    updated_at = now()
WHERE key = 'webdav_access_policy';
