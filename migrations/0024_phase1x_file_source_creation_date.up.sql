-- File rows must not preserve upload timestamps. The only file date kept by
-- Archivon is the source creation date extracted from file metadata when it is
-- available.

ALTER TABLE files
  ADD COLUMN IF NOT EXISTS source_created_at timestamptz;

UPDATE files
SET encrypted_manifest = encrypted_manifest - 'created_at'
WHERE encrypted_manifest ? 'created_at';

DELETE FROM audit_events
WHERE event_type = 'archive.file.uploaded';

DROP INDEX IF EXISTS files_tenant_status_idx;

CREATE INDEX IF NOT EXISTS files_tenant_status_idx
  ON files(tenant_id, status);

ALTER TABLE files
  DROP COLUMN IF EXISTS created_at,
  DROP COLUMN IF EXISTS updated_at;

ALTER TABLE folder_entries
  DROP COLUMN IF EXISTS created_at;

ALTER TABLE encrypted_data_keys
  DROP COLUMN IF EXISTS created_at;
