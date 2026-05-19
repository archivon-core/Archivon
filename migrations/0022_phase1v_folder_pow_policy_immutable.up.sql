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

  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS protected_folders_pow_policy_immutable ON protected_folders;

CREATE TRIGGER protected_folders_pow_policy_immutable
BEFORE UPDATE OF
  pow_required_hashrate_ths,
  pow_hashrate_tolerance_percent,
  pow_proof_window_seconds,
  pow_max_proof_attempts
ON protected_folders
FOR EACH ROW
EXECUTE FUNCTION prevent_protected_folder_pow_policy_update();
