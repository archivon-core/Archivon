UPDATE system_settings
SET value = jsonb_set(
  jsonb_set(value, '{proof_window_seconds}', '60'::jsonb, true),
  '{max_proof_attempts}',
  '3'::jsonb,
  true
)
WHERE key = 'pow_access_policy';
