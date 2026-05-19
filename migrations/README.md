# Migrations

Status: `phase2d`

Migration files use the `*.up.sql` suffix and are applied by `archivon-api`
on startup. Applied migrations are tracked in PostgreSQL table
`schema_migrations` with a SHA-256 checksum. A changed checksum for an already
applied migration is treated as a startup error.

Current latest migration:

```text
0027_phase2a_audit_ready_archive_timestamps
0028_phase2b_admin_webdav_upload
0029_phase2c_remove_file_denies
0030_phase2d_unlock_only_folder_permissions
```
