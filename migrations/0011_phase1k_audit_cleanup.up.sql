ALTER TABLE log_cleanup_backups
  ADD COLUMN IF NOT EXISTS event_count integer NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS restored_by uuid REFERENCES users(id) ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS restore_checksum_sha256 char(64),
  ADD COLUMN IF NOT EXISTS restore_event_count integer,
  ADD COLUMN IF NOT EXISTS metadata jsonb NOT NULL DEFAULT '{}'::jsonb;

CREATE INDEX IF NOT EXISTS log_cleanup_backups_tenant_created_idx
  ON log_cleanup_backups(tenant_id, created_at DESC);

CREATE INDEX IF NOT EXISTS audit_events_tenant_created_idx
  ON audit_events(tenant_id, created_at DESC);

INSERT INTO system_settings (key, value)
VALUES (
  'file_activity_cleanup_policy',
  '{
    "retention_days": 30,
    "allow_clear_all": true,
    "backup_required": true,
    "restore_requires_checksum": true,
    "backup_storage": "download_only",
    "protected_cleanup_events": true
  }'::jsonb
)
ON CONFLICT (key) DO NOTHING;
