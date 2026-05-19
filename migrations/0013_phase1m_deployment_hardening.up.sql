INSERT INTO system_settings (key, value)
VALUES (
  'deployment_hardening_policy',
  '{
    "https_enabled": true,
    "https_port": 8443,
    "http_port": 8088,
    "http_kept_for_lab_compatibility": true,
    "nginx_security_headers": true,
    "docker_healthchecks": true,
    "preprod_self_signed_tls_allowed": true,
    "production_requires_publicly_trusted_tls": true
  }'::jsonb
)
ON CONFLICT (key) DO NOTHING;
