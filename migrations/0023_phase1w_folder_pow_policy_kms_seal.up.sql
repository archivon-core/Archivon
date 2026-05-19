ALTER TABLE protected_folders
ADD COLUMN IF NOT EXISTS pow_policy_seal text;

ALTER TABLE protected_folders
DROP CONSTRAINT IF EXISTS protected_folders_pow_policy_seal_format;

ALTER TABLE protected_folders
ADD CONSTRAINT protected_folders_pow_policy_seal_format
CHECK (
  pow_policy_seal IS NULL
  OR pow_policy_seal ~ '^kms-hmac-sha256:v1:[0-9a-f]{64}$'
);

CREATE OR REPLACE FUNCTION prevent_protected_folder_pow_policy_update()
RETURNS trigger AS $$
BEGIN
  IF NEW.pow_required_hashrate_ths IS DISTINCT FROM OLD.pow_required_hashrate_ths
    OR NEW.pow_hashrate_tolerance_percent IS DISTINCT FROM OLD.pow_hashrate_tolerance_percent
    OR NEW.pow_proof_window_seconds IS DISTINCT FROM OLD.pow_proof_window_seconds
    OR NEW.pow_max_proof_attempts IS DISTINCT FROM OLD.pow_max_proof_attempts
  THEN
    RAISE EXCEPTION 'folder_pow_policy_immutable'
      USING ERRCODE = '23514';
  END IF;

  IF OLD.pow_policy_seal IS NOT NULL
    AND NEW.pow_policy_seal IS DISTINCT FROM OLD.pow_policy_seal
  THEN
    RAISE EXCEPTION 'folder_pow_policy_seal_immutable'
      USING ERRCODE = '23514';
  END IF;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS protected_folders_pow_policy_immutable ON protected_folders;

CREATE TRIGGER protected_folders_pow_policy_immutable
BEFORE UPDATE OF
  pow_required_hashrate_ths,
  pow_hashrate_tolerance_percent,
  pow_proof_window_seconds,
  pow_max_proof_attempts,
  pow_policy_seal
ON protected_folders
FOR EACH ROW
EXECUTE FUNCTION prevent_protected_folder_pow_policy_update();
