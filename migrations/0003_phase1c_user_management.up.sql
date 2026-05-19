CREATE INDEX IF NOT EXISTS users_tenant_blocked_idx
    ON users (tenant_id, is_blocked);

CREATE INDEX IF NOT EXISTS users_tenant_must_change_password_idx
    ON users (tenant_id, must_change_password);

INSERT INTO system_settings (key, value)
VALUES
    (
        'user_management_policy',
        '{"super_admin_can_create_roles":["admin","client"],"admin_can_create_roles":["client"],"super_admin_user_management_protected":true,"temporary_password_requires_change":true}'::jsonb
    )
ON CONFLICT (key) DO UPDATE
SET value = EXCLUDED.value,
    updated_at = now();
