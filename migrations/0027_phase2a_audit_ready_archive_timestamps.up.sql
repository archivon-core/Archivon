ALTER TABLE protected_folders
  ADD COLUMN IF NOT EXISTS created_at timestamptz,
  ADD COLUMN IF NOT EXISTS updated_at timestamptz;

UPDATE protected_folders
SET
  created_at = coalesce(created_at, now()),
  updated_at = coalesce(updated_at, now());

ALTER TABLE protected_folders
  ALTER COLUMN created_at SET DEFAULT now(),
  ALTER COLUMN updated_at SET DEFAULT now(),
  ALTER COLUMN created_at SET NOT NULL,
  ALTER COLUMN updated_at SET NOT NULL;

ALTER TABLE files
  ADD COLUMN IF NOT EXISTS created_at timestamptz,
  ADD COLUMN IF NOT EXISTS updated_at timestamptz;

UPDATE files
SET
  created_at = coalesce(created_at, now()),
  updated_at = coalesce(updated_at, now());

ALTER TABLE files
  ALTER COLUMN created_at SET DEFAULT now(),
  ALTER COLUMN updated_at SET DEFAULT now(),
  ALTER COLUMN created_at SET NOT NULL,
  ALTER COLUMN updated_at SET NOT NULL;

ALTER TABLE folder_entries
  ADD COLUMN IF NOT EXISTS created_at timestamptz;

UPDATE folder_entries
SET created_at = coalesce(created_at, now());

ALTER TABLE folder_entries
  ALTER COLUMN created_at SET DEFAULT now(),
  ALTER COLUMN created_at SET NOT NULL;

DROP INDEX IF EXISTS files_tenant_status_idx;

CREATE INDEX IF NOT EXISTS files_tenant_status_idx
  ON files(tenant_id, status, created_at DESC, id DESC);

INSERT INTO system_settings (key, value)
VALUES (
  'storage_policy',
  '{"content":"plain-server-storage","archive_dates":"enabled","object_names":"opaque-random","kms_role":"policy-seal","timestamp_model":"audit-ready"}'::jsonb
)
ON CONFLICT (key) DO UPDATE
SET value = EXCLUDED.value,
    updated_at = now();
