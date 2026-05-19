CREATE INDEX IF NOT EXISTS pow_jobs_tenant_running_idx
  ON pow_jobs(tenant_id, started_at)
  WHERE status = 'running';

CREATE INDEX IF NOT EXISTS pow_shares_tenant_submitted_idx
  ON pow_shares(tenant_id, submitted_at DESC);

CREATE INDEX IF NOT EXISTS pow_shares_worker_valid_idx
  ON pow_shares(compute_worker_id, is_valid, submitted_at DESC);

ALTER TABLE compute_workers
  ADD COLUMN IF NOT EXISTS last_connected_at timestamptz,
  ADD COLUMN IF NOT EXISTS last_disconnected_at timestamptz,
  ADD COLUMN IF NOT EXISTS last_ip text,
  ADD COLUMN IF NOT EXISTS last_error text;

INSERT INTO system_settings (key, value)
VALUES (
  'compute_gateway_policy',
  '{
    "enabled": true,
    "bind_address": ":3333",
    "stratum_port": 3333,
    "share_difficulty": 0.0025,
    "extranonce2_size": 4,
    "password_configured": false,
    "password_hash": "",
    "password_updated_at": null
  }'::jsonb
)
ON CONFLICT (key) DO NOTHING;
