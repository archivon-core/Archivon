CREATE INDEX IF NOT EXISTS access_sessions_tenant_user_folder_status_idx
  ON access_sessions(tenant_id, user_id, protected_folder_id, status, expires_at);

CREATE INDEX IF NOT EXISTS pow_jobs_tenant_user_folder_status_idx
  ON pow_jobs(tenant_id, user_id, protected_folder_id, status, created_at);

INSERT INTO system_settings (key, value)
VALUES (
  'access_session_workflow_policy',
  '{
    "admin_can_close_active_sessions": true,
    "permission_revoke_closes_active_sessions": true,
    "permission_revoke_cancels_open_jobs": true,
    "client_file_search_sort_enabled": true,
    "queue_progress_percentage_enabled": true
  }'::jsonb
)
ON CONFLICT (key) DO NOTHING;
