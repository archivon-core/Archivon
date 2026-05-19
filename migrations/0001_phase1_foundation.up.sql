CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS tenants (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  slug text NOT NULL UNIQUE,
  display_name text NOT NULL,
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  role text NOT NULL CHECK (role IN ('super_admin', 'admin', 'client')),
  username text NOT NULL,
  lower_username text NOT NULL,
  password_hash text,
  must_change_password boolean NOT NULL DEFAULT true,
  is_blocked boolean NOT NULL DEFAULT false,
  description text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  last_login_at timestamptz,
  UNIQUE (tenant_id, lower_username)
);

CREATE TABLE IF NOT EXISTS protected_folders (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  parent_folder_id uuid REFERENCES protected_folders(id) ON DELETE RESTRICT,
  name_ciphertext bytea NOT NULL,
  name_nonce bytea NOT NULL,
  description text,
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'deleted')),
  created_by uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS files (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  protected_folder_id uuid NOT NULL REFERENCES protected_folders(id) ON DELETE RESTRICT,
  storage_object_id text NOT NULL UNIQUE,
  original_name_ciphertext bytea NOT NULL,
  original_name_nonce bytea NOT NULL,
  plaintext_sha256 char(64) NOT NULL,
  size_bytes bigint NOT NULL CHECK (size_bytes >= 0),
  encrypted_manifest jsonb NOT NULL,
  wrapped_dek jsonb NOT NULL,
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'deleted')),
  created_by uuid REFERENCES users(id) ON DELETE SET NULL,
  source_created_at timestamptz
);

CREATE TABLE IF NOT EXISTS folder_entries (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  protected_folder_id uuid NOT NULL REFERENCES protected_folders(id) ON DELETE CASCADE,
  parent_entry_id uuid REFERENCES folder_entries(id) ON DELETE CASCADE,
  entry_type text NOT NULL CHECK (entry_type IN ('folder', 'file')),
  name_ciphertext bytea NOT NULL,
  name_nonce bytea NOT NULL,
  file_id uuid REFERENCES files(id) ON DELETE CASCADE,
  CHECK (
    (entry_type = 'file' AND file_id IS NOT NULL)
    OR (entry_type = 'folder' AND file_id IS NULL)
  )
);

CREATE TABLE IF NOT EXISTS folder_permissions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  protected_folder_id uuid NOT NULL REFERENCES protected_folders(id) ON DELETE CASCADE,
  can_view_folder boolean NOT NULL DEFAULT false,
  can_list_files boolean NOT NULL DEFAULT false,
  can_unlock_and_access boolean NOT NULL DEFAULT false,
  expires_at timestamptz,
  created_by uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (user_id, protected_folder_id)
);

CREATE TABLE IF NOT EXISTS file_denies (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  file_id uuid NOT NULL REFERENCES files(id) ON DELETE CASCADE,
  reason text,
  created_by uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (user_id, file_id)
);

CREATE TABLE IF NOT EXISTS pow_jobs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  protected_folder_id uuid NOT NULL REFERENCES protected_folders(id) ON DELETE RESTRICT,
  status text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'running', 'succeeded', 'failed', 'canceled', 'timeout')),
  required_hashrate_ths numeric(24, 6) NOT NULL CHECK (required_hashrate_ths > 0),
  required_work_th numeric(30, 6) NOT NULL CHECK (required_work_th >= 0),
  observed_hashrate_ths numeric(24, 6),
  min_workers integer NOT NULL DEFAULT 1 CHECK (min_workers > 0),
  timeout_seconds integer NOT NULL CHECK (timeout_seconds > 0),
  failure_reason text,
  created_at timestamptz NOT NULL DEFAULT now(),
  started_at timestamptz,
  finished_at timestamptz
);

CREATE TABLE IF NOT EXISTS compute_workers (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  worker_name text NOT NULL,
  password_version integer NOT NULL DEFAULT 1,
  status text NOT NULL DEFAULT 'disconnected' CHECK (status IN ('connected', 'disconnected', 'conflict', 'blocked')),
  reported_hashrate_ths numeric(24, 6),
  connection_count integer NOT NULL DEFAULT 0 CHECK (connection_count >= 0),
  last_seen_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, worker_name)
);

CREATE TABLE IF NOT EXISTS pow_shares (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  pow_job_id uuid NOT NULL REFERENCES pow_jobs(id) ON DELETE CASCADE,
  compute_worker_id uuid REFERENCES compute_workers(id) ON DELETE SET NULL,
  share_hash text NOT NULL,
  share_target text NOT NULL,
  work_th numeric(30, 6) NOT NULL CHECK (work_th >= 0),
  is_valid boolean NOT NULL,
  rejection_reason text,
  submitted_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS access_sessions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  protected_folder_id uuid NOT NULL REFERENCES protected_folders(id) ON DELETE CASCADE,
  pow_job_id uuid REFERENCES pow_jobs(id) ON DELETE SET NULL,
  status text NOT NULL CHECK (status IN ('active', 'closed', 'expired', 'revoked')),
  dav_username text,
  dav_password_hash text,
  opened_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  closed_at timestamptz,
  close_reason text
);

CREATE UNIQUE INDEX IF NOT EXISTS access_sessions_one_active_per_user_folder
  ON access_sessions(user_id, protected_folder_id)
  WHERE status = 'active';

CREATE TABLE IF NOT EXISTS system_settings (
  key text PRIMARY KEY,
  value jsonb NOT NULL,
  updated_by uuid REFERENCES users(id) ON DELETE SET NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS audit_events (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid REFERENCES tenants(id) ON DELETE SET NULL,
  actor_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  event_type text NOT NULL,
  target_type text,
  target_id uuid,
  severity text NOT NULL DEFAULT 'info' CHECK (severity IN ('debug', 'info', 'warning', 'error', 'critical')),
  ip_address text,
  details jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS log_cleanup_backups (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid REFERENCES tenants(id) ON DELETE SET NULL,
  backup_type text NOT NULL CHECK (backup_type IN ('file_activity', 'audit_subset')),
  checksum_sha256 char(64) NOT NULL,
  file_name text NOT NULL,
  created_by uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  restored_at timestamptz
);

CREATE INDEX IF NOT EXISTS users_tenant_role_idx ON users(tenant_id, role);
CREATE INDEX IF NOT EXISTS protected_folders_tenant_idx ON protected_folders(tenant_id, status);
CREATE INDEX IF NOT EXISTS files_folder_idx ON files(protected_folder_id, status);
CREATE INDEX IF NOT EXISTS folder_entries_folder_parent_idx ON folder_entries(protected_folder_id, parent_entry_id);
CREATE INDEX IF NOT EXISTS folder_permissions_user_idx ON folder_permissions(user_id);
CREATE INDEX IF NOT EXISTS pow_jobs_status_idx ON pow_jobs(status, created_at);
CREATE INDEX IF NOT EXISTS pow_shares_job_idx ON pow_shares(pow_job_id, submitted_at);
CREATE INDEX IF NOT EXISTS compute_workers_status_idx ON compute_workers(tenant_id, status);
CREATE INDEX IF NOT EXISTS audit_events_created_idx ON audit_events(created_at);
CREATE INDEX IF NOT EXISTS audit_events_type_idx ON audit_events(event_type, created_at);

INSERT INTO tenants (slug, display_name)
VALUES ('default', 'Default')
ON CONFLICT (slug) DO NOTHING;

INSERT INTO system_settings (key, value)
VALUES
  ('access_session_ttl_minutes', '{"default":30,"allowed":[10,15,30,60]}'::jsonb),
  ('pow_job_timeout_minutes', '{"default":15,"allowed":[5,10,15,30]}'::jsonb),
  ('audit_retention_days', '{"default":30}'::jsonb),
  ('compute_power_policy', '{"required_hashrate_ths":1,"min_workers":1}'::jsonb)
ON CONFLICT (key) DO NOTHING;
