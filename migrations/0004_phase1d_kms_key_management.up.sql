CREATE TABLE IF NOT EXISTS kms_key_slots (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  key_id text NOT NULL,
  provider text NOT NULL,
  purpose text NOT NULL CHECK (purpose IN ('master')),
  status text NOT NULL CHECK (status IN ('active', 'missing', 'retired')),
  fingerprint_sha256 text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz,
  UNIQUE (tenant_id, key_id)
);

CREATE TABLE IF NOT EXISTS encrypted_data_keys (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  key_slot_id uuid NOT NULL REFERENCES kms_key_slots(id) ON DELETE RESTRICT,
  owner_type text NOT NULL CHECK (owner_type IN ('file', 'folder', 'system_test')),
  owner_id uuid,
  wrap_algorithm text NOT NULL DEFAULT 'AES-256-GCM',
  nonce bytea NOT NULL,
  ciphertext bytea NOT NULL,
  aad jsonb NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS kms_key_slots_status_idx
  ON kms_key_slots(tenant_id, status, purpose);

CREATE INDEX IF NOT EXISTS encrypted_data_keys_owner_idx
  ON encrypted_data_keys(tenant_id, owner_type, owner_id);

INSERT INTO system_settings (key, value)
VALUES
  (
    'kms_policy',
    '{"provider":"local-file","key_id":"local-master-v1","min_key_bytes":32,"ready_required_for_protected_operations":true,"future_external_kms":true}'::jsonb
  )
ON CONFLICT (key) DO UPDATE
SET value = EXCLUDED.value,
    updated_at = now();
