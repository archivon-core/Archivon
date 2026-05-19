ALTER TABLE pow_jobs
  ADD COLUMN IF NOT EXISTS proof_window_seconds integer,
  ADD COLUMN IF NOT EXISTS hashrate_tolerance_percent numeric(6, 2) NOT NULL DEFAULT 10,
  ADD COLUMN IF NOT EXISTS max_proof_attempts integer NOT NULL DEFAULT 3,
  ADD COLUMN IF NOT EXISTS session_ttl_minutes integer NOT NULL DEFAULT 30;

UPDATE pow_jobs
SET proof_window_seconds = GREATEST(
  10,
  COALESCE(
    proof_window_seconds,
    CEIL(required_work_th / NULLIF(required_hashrate_ths, 0))::int,
    60
  )
)
WHERE proof_window_seconds IS NULL;

ALTER TABLE pow_jobs
  ALTER COLUMN proof_window_seconds SET NOT NULL;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'pow_jobs_proof_window_seconds_check'
  ) THEN
    ALTER TABLE pow_jobs
      ADD CONSTRAINT pow_jobs_proof_window_seconds_check
      CHECK (proof_window_seconds > 0);
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'pow_jobs_hashrate_tolerance_percent_check'
  ) THEN
    ALTER TABLE pow_jobs
      ADD CONSTRAINT pow_jobs_hashrate_tolerance_percent_check
      CHECK (hashrate_tolerance_percent >= 0 AND hashrate_tolerance_percent <= 90);
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'pow_jobs_max_proof_attempts_check'
  ) THEN
    ALTER TABLE pow_jobs
      ADD CONSTRAINT pow_jobs_max_proof_attempts_check
      CHECK (max_proof_attempts > 0);
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'pow_jobs_session_ttl_minutes_check'
  ) THEN
    ALTER TABLE pow_jobs
      ADD CONSTRAINT pow_jobs_session_ttl_minutes_check
      CHECK (session_ttl_minutes > 0);
  END IF;
END $$;

UPDATE system_settings
SET value = jsonb_set(
  jsonb_set(
    jsonb_set(
      jsonb_set(value, '{min_workers}', '1'::jsonb, true),
      '{hashrate_tolerance_percent}',
      COALESCE(value->'hashrate_tolerance_percent', '10'::jsonb),
      true
    ),
    '{max_proof_attempts}',
    '3'::jsonb,
    true
  ),
  '{proof_window_seconds}',
  COALESCE(value->'proof_window_seconds', '60'::jsonb),
  true
)
WHERE key = 'pow_access_policy';
