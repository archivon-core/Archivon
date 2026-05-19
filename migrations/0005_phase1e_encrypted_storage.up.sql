ALTER TABLE protected_folders
  ADD COLUMN IF NOT EXISTS description_ciphertext bytea,
  ADD COLUMN IF NOT EXISTS description_nonce bytea;

CREATE INDEX IF NOT EXISTS files_tenant_status_idx
  ON files(tenant_id, status, source_created_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS folder_entries_file_idx
  ON folder_entries(file_id)
  WHERE file_id IS NOT NULL;

INSERT INTO system_settings (key, value)
VALUES (
  'storage_encryption_policy',
  '{"metadata":"kms-derived-aes-256-gcm","file_content":"per-file-dek-aes-256-gcm","chunk_size_bytes":1048576,"storage_object_names":"opaque-random"}'::jsonb
)
ON CONFLICT (key) DO UPDATE
SET value = excluded.value,
    updated_at = now();
