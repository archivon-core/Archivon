-- Simplified permission model:
-- view_folder now means "see folder and file list"; unlock remains the only
-- permission that allows PoW access and download during an active TTL session.
UPDATE folder_permissions
SET can_list_files = true,
    updated_at = now()
WHERE can_view_folder = true
  AND can_list_files = false;
