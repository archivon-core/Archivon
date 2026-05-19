ALTER TABLE protected_folders
  ADD COLUMN IF NOT EXISTS pow_required_hashrate_ths numeric(24, 6),
  ADD COLUMN IF NOT EXISTS pow_hashrate_tolerance_percent numeric(6, 2),
  ADD COLUMN IF NOT EXISTS pow_proof_window_seconds integer,
  ADD COLUMN IF NOT EXISTS pow_max_proof_attempts integer;

UPDATE protected_folders pf
SET
  pow_required_hashrate_ths = COALESCE(pf.pow_required_hashrate_ths, (settings.value->>'required_hashrate_ths')::numeric, 1),
  pow_hashrate_tolerance_percent = COALESCE(pf.pow_hashrate_tolerance_percent, (settings.value->>'hashrate_tolerance_percent')::numeric, 10),
  pow_proof_window_seconds = COALESCE(pf.pow_proof_window_seconds, (settings.value->>'proof_window_seconds')::integer, 60),
  pow_max_proof_attempts = COALESCE(pf.pow_max_proof_attempts, (settings.value->>'max_proof_attempts')::integer, 3)
FROM (
  SELECT COALESCE(
    (SELECT value FROM system_settings WHERE key = 'pow_access_policy'),
    '{"required_hashrate_ths":1,"hashrate_tolerance_percent":10,"proof_window_seconds":60,"max_proof_attempts":3}'::jsonb
  ) AS value
) settings
WHERE pf.pow_required_hashrate_ths IS NULL
   OR pf.pow_hashrate_tolerance_percent IS NULL
   OR pf.pow_proof_window_seconds IS NULL
   OR pf.pow_max_proof_attempts IS NULL;

ALTER TABLE protected_folders
  ALTER COLUMN pow_required_hashrate_ths SET NOT NULL,
  ALTER COLUMN pow_hashrate_tolerance_percent SET NOT NULL,
  ALTER COLUMN pow_proof_window_seconds SET NOT NULL,
  ALTER COLUMN pow_max_proof_attempts SET NOT NULL;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'protected_folders_pow_required_hashrate_check'
  ) THEN
    ALTER TABLE protected_folders
      ADD CONSTRAINT protected_folders_pow_required_hashrate_check
      CHECK (pow_required_hashrate_ths > 0);
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'protected_folders_pow_tolerance_check'
  ) THEN
    ALTER TABLE protected_folders
      ADD CONSTRAINT protected_folders_pow_tolerance_check
      CHECK (pow_hashrate_tolerance_percent >= 0 AND pow_hashrate_tolerance_percent <= 50);
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'protected_folders_pow_window_check'
  ) THEN
    ALTER TABLE protected_folders
      ADD CONSTRAINT protected_folders_pow_window_check
      CHECK (pow_proof_window_seconds >= 5 AND pow_proof_window_seconds <= 600);
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'protected_folders_pow_attempts_check'
  ) THEN
    ALTER TABLE protected_folders
      ADD CONSTRAINT protected_folders_pow_attempts_check
      CHECK (pow_max_proof_attempts >= 1 AND pow_max_proof_attempts <= 10);
  END IF;
END $$;
