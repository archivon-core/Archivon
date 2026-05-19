CREATE INDEX IF NOT EXISTS access_sessions_active_download_idx
  ON access_sessions(tenant_id, user_id, protected_folder_id, expires_at)
  WHERE status = 'active';

CREATE INDEX IF NOT EXISTS files_active_download_idx
  ON files(tenant_id, id, protected_folder_id)
  WHERE status = 'active';

INSERT INTO system_settings (key, value)
VALUES (
  'download_access_policy',
  '{
    "client_download_requires_can_view_folder": true,
    "client_download_requires_can_list_files": true,
    "client_download_requires_can_unlock_and_access": true,
    "client_download_requires_active_access_session": true,
    "file_denies_hide_download": true,
    "verify_plaintext_sha256_before_response": true
  }'::jsonb
)
ON CONFLICT (key) DO NOTHING;
