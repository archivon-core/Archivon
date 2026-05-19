-- Archivon Core no longer encrypts archive content or archive metadata.
-- This is a clean pre-production storage pivot: encrypted test archives are
-- not converted because the old rows preserve an obsolete security model.

DELETE FROM pow_shares
WHERE pow_job_id IN (SELECT id FROM pow_jobs);

DELETE FROM access_sessions;
DELETE FROM pow_jobs;
DELETE FROM file_denies;
DELETE FROM folder_permissions;
DELETE FROM folder_entries;
DELETE FROM encrypted_data_keys;
DELETE FROM files;
DELETE FROM protected_folders;

DELETE FROM audit_events
WHERE event_type LIKE 'archive.%'
   OR event_type LIKE 'access.%'
   OR target_type IN ('file', 'folder', 'protected_folder');

ALTER TABLE protected_folders
  ADD COLUMN IF NOT EXISTS name text;

UPDATE protected_folders
SET name = coalesce(name, '');

ALTER TABLE protected_folders
  ALTER COLUMN name SET NOT NULL,
  ALTER COLUMN description SET DEFAULT '',
  DROP COLUMN IF EXISTS name_ciphertext,
  DROP COLUMN IF EXISTS name_nonce,
  DROP COLUMN IF EXISTS description_ciphertext,
  DROP COLUMN IF EXISTS description_nonce,
  DROP COLUMN IF EXISTS created_at,
  DROP COLUMN IF EXISTS updated_at;

ALTER TABLE files
  ADD COLUMN IF NOT EXISTS original_name text;

UPDATE files
SET original_name = coalesce(original_name, '');

ALTER TABLE files
  ALTER COLUMN original_name SET NOT NULL,
  DROP COLUMN IF EXISTS original_name_ciphertext,
  DROP COLUMN IF EXISTS original_name_nonce,
  DROP COLUMN IF EXISTS encrypted_manifest,
  DROP COLUMN IF EXISTS wrapped_dek,
  DROP COLUMN IF EXISTS source_created_at,
  DROP COLUMN IF EXISTS created_at,
  DROP COLUMN IF EXISTS updated_at;

ALTER TABLE folder_entries
  ADD COLUMN IF NOT EXISTS name text;

UPDATE folder_entries
SET name = coalesce(name, '');

ALTER TABLE folder_entries
  ALTER COLUMN name SET NOT NULL,
  DROP COLUMN IF EXISTS name_ciphertext,
  DROP COLUMN IF EXISTS name_nonce,
  DROP COLUMN IF EXISTS created_at;

DROP TABLE IF EXISTS encrypted_data_keys;

DROP INDEX IF EXISTS files_tenant_status_idx;

CREATE INDEX IF NOT EXISTS files_tenant_status_idx
  ON files(tenant_id, status, id DESC);

INSERT INTO system_settings (key, value)
VALUES (
  'storage_policy',
  '{"content":"plain-server-storage","archive_dates":"disabled","object_names":"opaque-random","kms_role":"policy-seal"}'::jsonb
)
ON CONFLICT (key) DO UPDATE
SET value = EXCLUDED.value,
    updated_at = now();

DELETE FROM system_settings
WHERE key = 'storage_encryption_policy';
