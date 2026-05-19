ALTER TABLE compute_workers
  ADD COLUMN IF NOT EXISTS stats_reset_at timestamptz;

CREATE INDEX IF NOT EXISTS compute_workers_stats_reset_idx
  ON compute_workers(tenant_id, stats_reset_at DESC);
