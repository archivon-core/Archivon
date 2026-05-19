CREATE UNIQUE INDEX IF NOT EXISTS pow_jobs_one_running_per_tenant
  ON pow_jobs(tenant_id)
  WHERE status = 'running';

CREATE UNIQUE INDEX IF NOT EXISTS access_sessions_one_active_per_tenant
  ON access_sessions(tenant_id)
  WHERE status = 'active';

CREATE INDEX IF NOT EXISTS access_sessions_tenant_status_expires_idx
  ON access_sessions(tenant_id, status, expires_at);

CREATE INDEX IF NOT EXISTS pow_jobs_user_folder_status_idx
  ON pow_jobs(user_id, protected_folder_id, status, created_at);

INSERT INTO system_settings (key, value)
VALUES (
  'pow_access_policy',
  '{
    "required_hashrate_ths": 1,
    "min_workers": 1,
    "proof_window_seconds": 60,
    "job_timeout_minutes": 15,
    "session_ttl_minutes": 30,
    "allowed_session_ttl_minutes": [10, 15, 30, 60],
    "single_active_session": true,
    "heartbeat_enabled": false,
    "upload_pow_required": false
  }'::jsonb
)
ON CONFLICT (key) DO UPDATE
SET value = excluded.value,
    updated_at = now();
