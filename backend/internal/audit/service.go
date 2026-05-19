package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"archivon/backend/internal/auth"
)

const (
	fileActivityCleanupPolicyKey = "file_activity_cleanup_policy"
	backupFormat                 = "archivon.audit.file_activity.backup.v1"
	exportFormat                 = "archivon.audit.export.v1"
	defaultAuditLimit            = 50
	maxAuditLimit                = 200
)

type Service struct {
	db     *sql.DB
	logger *slog.Logger
	auth   *auth.Service
}

type Event struct {
	ID          string          `json:"id"`
	TenantID    string          `json:"tenant_id,omitempty"`
	ActorUserID *string         `json:"actor_user_id,omitempty"`
	EventType   string          `json:"event_type"`
	TargetType  string          `json:"target_type,omitempty"`
	TargetID    *string         `json:"target_id,omitempty"`
	Severity    string          `json:"severity"`
	IPAddress   string          `json:"ip_address,omitempty"`
	Details     json.RawMessage `json:"details"`
	CreatedAt   time.Time       `json:"created_at"`
}

type CleanupPolicy struct {
	RetentionDays           int    `json:"retention_days"`
	AllowClearAll           bool   `json:"allow_clear_all"`
	BackupRequired          bool   `json:"backup_required"`
	RestoreRequiresChecksum bool   `json:"restore_requires_checksum"`
	BackupStorage           string `json:"backup_storage"`
	ProtectedCleanupEvents  bool   `json:"protected_cleanup_events"`
}

type settingsResponse struct {
	Policy CleanupPolicy `json:"policy"`
}

type updateSettingsRequest struct {
	RetentionDays int `json:"retention_days"`
}

type eventsResponse struct {
	Events            []Event `json:"events"`
	Limit             int     `json:"limit"`
	Offset            int     `json:"offset"`
	FileActivityCount int     `json:"file_activity_count"`
}

type backupRecord struct {
	ID             string     `json:"id"`
	BackupType     string     `json:"backup_type"`
	ChecksumSHA256 string     `json:"checksum_sha256"`
	FileName       string     `json:"file_name"`
	EventCount     int        `json:"event_count"`
	CreatedBy      *string    `json:"created_by,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	RestoredAt     *time.Time `json:"restored_at,omitempty"`
	RestoredBy     *string    `json:"restored_by,omitempty"`
}

type backupsResponse struct {
	Backups []backupRecord `json:"backups"`
}

type cleanupRequest struct {
	OlderThanDays *int   `json:"older_than_days"`
	Before        string `json:"before"`
}

type cleanupScope struct {
	OlderThanDays *int       `json:"older_than_days,omitempty"`
	Before        *time.Time `json:"before,omitempty"`
	FileRelated   bool       `json:"file_related"`
}

type backupPayload struct {
	Format         string       `json:"format"`
	BackupID       string       `json:"backup_id"`
	TenantID       string       `json:"tenant_id"`
	CreatedAt      time.Time    `json:"created_at"`
	CreatedBy      string       `json:"created_by"`
	CleanupScope   cleanupScope `json:"cleanup_scope"`
	EventCount     int          `json:"event_count"`
	Events         []Event      `json:"events"`
	ChecksumSHA256 string       `json:"checksum_sha256"`
}

type backupChecksumPayload struct {
	Format       string       `json:"format"`
	BackupID     string       `json:"backup_id"`
	TenantID     string       `json:"tenant_id"`
	CreatedAt    time.Time    `json:"created_at"`
	CreatedBy    string       `json:"created_by"`
	CleanupScope cleanupScope `json:"cleanup_scope"`
	EventCount   int          `json:"event_count"`
	Events       []Event      `json:"events"`
}

type restoreResponse struct {
	BackupID       string `json:"backup_id"`
	ChecksumSHA256 string `json:"checksum_sha256"`
	RestoredEvents int    `json:"restored_events"`
}

type exportPayload struct {
	Format    string         `json:"format"`
	TenantID  string         `json:"tenant_id"`
	CreatedAt time.Time      `json:"created_at"`
	CreatedBy string         `json:"created_by"`
	Filters   map[string]any `json:"filters"`
	Events    []Event        `json:"events"`
}

type eventFilters struct {
	EventType   string
	Severity    string
	TargetType  string
	FileRelated bool
	From        *time.Time
	To          *time.Time
	Limit       int
	Offset      int
}

func NewService(db *sql.DB, logger *slog.Logger, authService *auth.Service) *Service {
	return &Service{db: db, logger: logger, auth: authService}
}

func (s *Service) Register(mux *http.ServeMux) {
	mux.Handle("/api/admin/audit/settings", s.auth.RequireRole(http.HandlerFunc(s.handleSettings), "super_admin", "admin"))
	mux.Handle("/api/admin/audit/events", s.auth.RequireRole(http.HandlerFunc(s.handleEvents), "super_admin", "admin"))
	mux.Handle("/api/admin/audit/export", s.auth.RequireRole(http.HandlerFunc(s.handleExport), "super_admin", "admin"))
	mux.Handle("/api/admin/audit/cleanup/backups", s.auth.RequireRole(http.HandlerFunc(s.handleBackups), "super_admin", "admin"))
	mux.Handle("/api/admin/audit/cleanup/file-activity", s.auth.RequireRole(http.HandlerFunc(s.handleCleanupFileActivity), "super_admin", "admin"))
	mux.Handle("/api/admin/audit/cleanup/restore", s.auth.RequireRole(http.HandlerFunc(s.handleRestore), "super_admin", "admin"))
}

func (s *Service) handleSettings(w http.ResponseWriter, r *http.Request) {
	user, err := s.auth.CurrentUser(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "not_authenticated")
		return
	}
	switch r.Method {
	case http.MethodGet:
		policy, err := s.loadPolicy(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, "audit_policy_load_failed")
			return
		}
		writeJSON(w, http.StatusOK, settingsResponse{Policy: policy})
	case http.MethodPost:
		var req updateSettingsRequest
		if !decodeJSON(w, r, &req) {
			return
		}
		policy := normalizePolicy(CleanupPolicy{
			RetentionDays:           req.RetentionDays,
			AllowClearAll:           true,
			BackupRequired:          true,
			RestoreRequiresChecksum: true,
			BackupStorage:           "download_only",
			ProtectedCleanupEvents:  true,
		})
		raw, err := json.Marshal(policy)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "audit_policy_encode_failed")
			return
		}
		if _, err := s.db.ExecContext(r.Context(), `
INSERT INTO system_settings (key, value, updated_by, updated_at)
VALUES ($1, $2::jsonb, $3, now())
ON CONFLICT (key) DO UPDATE
SET value = EXCLUDED.value,
    updated_by = EXCLUDED.updated_by,
    updated_at = now()`, fileActivityCleanupPolicyKey, string(raw), user.ID); err != nil {
			writeError(w, http.StatusInternalServerError, "audit_policy_update_failed")
			return
		}
		_ = s.insertAuditEvent(r.Context(), user.TenantID, user.ID, "audit.cleanup_policy.updated", "system_setting", nil, "warning", clientIP(r), map[string]any{
			"retention_days": policy.RetentionDays,
		})
		writeJSON(w, http.StatusOK, settingsResponse{Policy: policy})
	default:
		writeMethodNotAllowed(w, "GET, POST")
	}
}

func (s *Service) handleEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, "GET")
		return
	}
	user, err := s.auth.CurrentUser(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "not_authenticated")
		return
	}
	filters, err := parseFilters(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	events, err := s.queryEvents(r.Context(), user.TenantID, filters)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "audit_query_failed")
		return
	}
	fileCount, err := s.fileActivityCount(r.Context(), user.TenantID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "audit_count_failed")
		return
	}
	writeJSON(w, http.StatusOK, eventsResponse{
		Events:            events,
		Limit:             filters.Limit,
		Offset:            filters.Offset,
		FileActivityCount: fileCount,
	})
}

func (s *Service) handleExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, "GET")
		return
	}
	user, err := s.auth.CurrentUser(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "not_authenticated")
		return
	}
	filters, err := parseFilters(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	filters.Limit = maxAuditLimit
	events, err := s.queryEvents(r.Context(), user.TenantID, filters)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "audit_export_failed")
		return
	}
	payload := exportPayload{
		Format:    exportFormat,
		TenantID:  user.TenantID,
		CreatedAt: time.Now().UTC(),
		CreatedBy: user.ID,
		Filters:   filters.asMap(),
		Events:    events,
	}
	raw, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "audit_export_encode_failed")
		return
	}
	_ = s.insertAuditEvent(r.Context(), user.TenantID, user.ID, "audit.exported", "audit_events", nil, "info", clientIP(r), map[string]any{
		"event_count":   len(events),
		"file_related":  filters.FileRelated,
		"event_type":    filters.EventType,
		"severity":      filters.Severity,
		"target_type":   filters.TargetType,
		"export_format": exportFormat,
	})
	fileName := "archivon-audit-export-" + time.Now().UTC().Format("20060102-150405") + ".json"
	writeDownload(w, http.StatusOK, fileName, raw)
}

func (s *Service) handleBackups(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, "GET")
		return
	}
	user, err := s.auth.CurrentUser(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "not_authenticated")
		return
	}
	rows, err := s.db.QueryContext(r.Context(), `
SELECT id::text, backup_type, checksum_sha256, file_name, event_count, created_by::text, created_at, restored_at, restored_by::text
FROM log_cleanup_backups
WHERE tenant_id = $1
ORDER BY created_at DESC
LIMIT 30`, user.TenantID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "backup_query_failed")
		return
	}
	defer rows.Close()

	backups := []backupRecord{}
	for rows.Next() {
		var backup backupRecord
		var createdBy sql.NullString
		var restoredBy sql.NullString
		var restoredAt sql.NullTime
		if err := rows.Scan(&backup.ID, &backup.BackupType, &backup.ChecksumSHA256, &backup.FileName, &backup.EventCount, &createdBy, &backup.CreatedAt, &restoredAt, &restoredBy); err != nil {
			writeError(w, http.StatusInternalServerError, "backup_scan_failed")
			return
		}
		if createdBy.Valid {
			backup.CreatedBy = &createdBy.String
		}
		if restoredBy.Valid {
			backup.RestoredBy = &restoredBy.String
		}
		if restoredAt.Valid {
			backup.RestoredAt = &restoredAt.Time
		}
		backups = append(backups, backup)
	}
	if err := rows.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, "backup_rows_failed")
		return
	}
	writeJSON(w, http.StatusOK, backupsResponse{Backups: backups})
}

func (s *Service) handleCleanupFileActivity(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, "POST")
		return
	}
	user, err := s.auth.CurrentUser(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "not_authenticated")
		return
	}
	var req cleanupRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	policy, err := s.loadPolicy(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "audit_policy_load_failed")
		return
	}
	scope, err := cleanupScopeFromRequest(req, policy)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	payload, raw, err := s.cleanupFileActivity(r.Context(), user, scope, clientIP(r))
	if err != nil {
		if errors.Is(err, errNoClearAll) {
			writeError(w, http.StatusBadRequest, "clear_all_not_allowed")
			return
		}
		writeError(w, http.StatusInternalServerError, "audit_cleanup_failed")
		return
	}
	writeDownload(w, http.StatusOK, backupFileName(payload.BackupID), raw)
}

func (s *Service) handleRestore(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, "POST")
		return
	}
	user, err := s.auth.CurrentUser(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "not_authenticated")
		return
	}
	defer r.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(r.Body, 20<<20))
	if err != nil || len(bytes.TrimSpace(raw)) == 0 {
		writeError(w, http.StatusBadRequest, "backup_required")
		return
	}
	result, err := s.restoreBackup(r.Context(), user, raw, clientIP(r))
	if err != nil {
		switch {
		case errors.Is(err, errChecksumMismatch):
			writeError(w, http.StatusBadRequest, "checksum_mismatch")
		case errors.Is(err, errBackupNotFound):
			writeError(w, http.StatusNotFound, "backup_not_found")
		case errors.Is(err, errBackupAlreadyRestored):
			writeError(w, http.StatusConflict, "backup_already_restored")
		default:
			writeError(w, http.StatusInternalServerError, "backup_restore_failed")
		}
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Service) cleanupFileActivity(ctx context.Context, user auth.User, scope cleanupScope, ipAddress string) (backupPayload, []byte, error) {
	if scope.OlderThanDays != nil && *scope.OlderThanDays == 0 {
		policy, err := s.loadPolicy(ctx)
		if err != nil {
			return backupPayload{}, nil, err
		}
		if !policy.AllowClearAll {
			return backupPayload{}, nil, errNoClearAll
		}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return backupPayload{}, nil, err
	}
	defer func() {
		_ = tx.Rollback()
	}()
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(110011111)`); err != nil {
		return backupPayload{}, nil, err
	}
	backupID, err := newUUIDTx(ctx, tx)
	if err != nil {
		return backupPayload{}, nil, err
	}
	events, err := queryFileActivityEventsTx(ctx, tx, user.TenantID, scope)
	if err != nil {
		return backupPayload{}, nil, err
	}
	payload := backupPayload{
		Format:       backupFormat,
		BackupID:     backupID,
		TenantID:     user.TenantID,
		CreatedAt:    time.Now().UTC(),
		CreatedBy:    user.ID,
		CleanupScope: scope,
		EventCount:   len(events),
		Events:       events,
	}
	checksum, raw, err := encodeBackup(payload)
	if err != nil {
		return backupPayload{}, nil, err
	}
	payload.ChecksumSHA256 = checksum
	raw, err = json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return backupPayload{}, nil, err
	}
	fileName := backupFileName(backupID)
	metadata, _ := json.Marshal(map[string]any{
		"scope":       scope,
		"format":      backupFormat,
		"downloaded":  true,
		"event_count": len(events),
	})
	if _, err := tx.ExecContext(ctx, `
INSERT INTO log_cleanup_backups (id, tenant_id, backup_type, checksum_sha256, file_name, created_by, event_count, metadata)
VALUES ($1, $2, 'file_activity', $3, $4, $5, $6, $7::jsonb)`,
		backupID, user.TenantID, checksum, fileName, user.ID, len(events), string(metadata)); err != nil {
		return backupPayload{}, nil, err
	}
	if err := deleteEventsTx(ctx, tx, events); err != nil {
		return backupPayload{}, nil, err
	}
	targetID := backupID
	if err := insertAuditEventTx(ctx, tx, user.TenantID, user.ID, "audit.file_activity.cleaned", "log_cleanup_backup", &targetID, "warning", ipAddress, map[string]any{
		"backup_id":       backupID,
		"checksum_sha256": checksum,
		"event_count":     len(events),
		"scope":           scope,
	}); err != nil {
		return backupPayload{}, nil, err
	}
	if err := tx.Commit(); err != nil {
		return backupPayload{}, nil, err
	}
	return payload, raw, nil
}

func (s *Service) restoreBackup(ctx context.Context, user auth.User, raw []byte, ipAddress string) (restoreResponse, error) {
	var payload backupPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return restoreResponse{}, err
	}
	if payload.Format != backupFormat || payload.BackupID == "" || payload.TenantID != user.TenantID {
		return restoreResponse{}, errBackupNotFound
	}
	checksum, _, err := encodeBackup(payload)
	if err != nil {
		return restoreResponse{}, err
	}
	if payload.ChecksumSHA256 != "" && payload.ChecksumSHA256 != checksum {
		return restoreResponse{}, errChecksumMismatch
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return restoreResponse{}, err
	}
	defer func() {
		_ = tx.Rollback()
	}()
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(110011112)`); err != nil {
		return restoreResponse{}, err
	}
	var restoredAt sql.NullTime
	var storedChecksum string
	var backupType string
	if err := tx.QueryRowContext(ctx, `
SELECT backup_type, checksum_sha256, restored_at
FROM log_cleanup_backups
WHERE tenant_id = $1 AND id = $2`, user.TenantID, payload.BackupID).Scan(&backupType, &storedChecksum, &restoredAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return restoreResponse{}, errBackupNotFound
		}
		return restoreResponse{}, err
	}
	if backupType != "file_activity" {
		return restoreResponse{}, errBackupNotFound
	}
	if restoredAt.Valid {
		return restoreResponse{}, errBackupAlreadyRestored
	}
	if storedChecksum != checksum {
		return restoreResponse{}, errChecksumMismatch
	}
	restored, err := insertEventsTx(ctx, tx, user.TenantID, payload.Events)
	if err != nil {
		return restoreResponse{}, err
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE log_cleanup_backups
SET restored_at = now(),
    restored_by = $1,
    restore_checksum_sha256 = $2,
    restore_event_count = $3
WHERE tenant_id = $4 AND id = $5`, user.ID, checksum, restored, user.TenantID, payload.BackupID); err != nil {
		return restoreResponse{}, err
	}
	targetID := payload.BackupID
	if err := insertAuditEventTx(ctx, tx, user.TenantID, user.ID, "audit.file_activity.restored", "log_cleanup_backup", &targetID, "warning", ipAddress, map[string]any{
		"backup_id":       payload.BackupID,
		"checksum_sha256": checksum,
		"restored_events": restored,
	}); err != nil {
		return restoreResponse{}, err
	}
	if err := tx.Commit(); err != nil {
		return restoreResponse{}, err
	}
	return restoreResponse{BackupID: payload.BackupID, ChecksumSHA256: checksum, RestoredEvents: restored}, nil
}

func (s *Service) loadPolicy(ctx context.Context) (CleanupPolicy, error) {
	var raw []byte
	if err := s.db.QueryRowContext(ctx, `SELECT value FROM system_settings WHERE key = $1`, fileActivityCleanupPolicyKey).Scan(&raw); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return defaultPolicy(), nil
		}
		return CleanupPolicy{}, err
	}
	var policy CleanupPolicy
	if err := json.Unmarshal(raw, &policy); err != nil {
		return CleanupPolicy{}, err
	}
	return normalizePolicy(policy), nil
}

func defaultPolicy() CleanupPolicy {
	return normalizePolicy(CleanupPolicy{RetentionDays: 30})
}

func normalizePolicy(policy CleanupPolicy) CleanupPolicy {
	if policy.RetentionDays < 0 {
		policy.RetentionDays = 0
	}
	policy.AllowClearAll = true
	policy.BackupRequired = true
	policy.RestoreRequiresChecksum = true
	policy.BackupStorage = "download_only"
	policy.ProtectedCleanupEvents = true
	return policy
}

func cleanupScopeFromRequest(req cleanupRequest, policy CleanupPolicy) (cleanupScope, error) {
	scope := cleanupScope{FileRelated: true}
	if req.Before != "" {
		parsed, err := time.Parse(time.RFC3339, req.Before)
		if err != nil {
			return cleanupScope{}, errors.New("invalid_before")
		}
		value := parsed.UTC()
		scope.Before = &value
	}
	if req.OlderThanDays != nil {
		if *req.OlderThanDays < 0 {
			return cleanupScope{}, errors.New("invalid_retention_days")
		}
		value := *req.OlderThanDays
		scope.OlderThanDays = &value
		return scope, nil
	}
	if scope.Before == nil {
		value := policy.RetentionDays
		scope.OlderThanDays = &value
	}
	return scope, nil
}

func parseFilters(r *http.Request) (eventFilters, error) {
	query := r.URL.Query()
	filters := eventFilters{
		EventType:   strings.TrimSpace(query.Get("event_type")),
		Severity:    strings.TrimSpace(query.Get("severity")),
		TargetType:  strings.TrimSpace(query.Get("target_type")),
		FileRelated: query.Get("file_related") == "true",
		Limit:       defaultAuditLimit,
	}
	if value := strings.TrimSpace(query.Get("limit")); value != "" {
		limit, err := strconv.Atoi(value)
		if err != nil || limit <= 0 {
			return eventFilters{}, errors.New("invalid_limit")
		}
		if limit > maxAuditLimit {
			limit = maxAuditLimit
		}
		filters.Limit = limit
	}
	if value := strings.TrimSpace(query.Get("offset")); value != "" {
		offset, err := strconv.Atoi(value)
		if err != nil || offset < 0 {
			return eventFilters{}, errors.New("invalid_offset")
		}
		filters.Offset = offset
	}
	if value := strings.TrimSpace(query.Get("from")); value != "" {
		parsed, err := time.Parse(time.RFC3339, value)
		if err != nil {
			return eventFilters{}, errors.New("invalid_from")
		}
		value := parsed.UTC()
		filters.From = &value
	}
	if value := strings.TrimSpace(query.Get("to")); value != "" {
		parsed, err := time.Parse(time.RFC3339, value)
		if err != nil {
			return eventFilters{}, errors.New("invalid_to")
		}
		value := parsed.UTC()
		filters.To = &value
	}
	return filters, nil
}

func (filters eventFilters) asMap() map[string]any {
	result := map[string]any{
		"event_type":   filters.EventType,
		"severity":     filters.Severity,
		"target_type":  filters.TargetType,
		"file_related": filters.FileRelated,
		"limit":        filters.Limit,
		"offset":       filters.Offset,
	}
	if filters.From != nil {
		result["from"] = filters.From.Format(time.RFC3339)
	}
	if filters.To != nil {
		result["to"] = filters.To.Format(time.RFC3339)
	}
	return result
}

func (s *Service) queryEvents(ctx context.Context, tenantID string, filters eventFilters) ([]Event, error) {
	where, args := eventWhereClause(tenantID, filters)
	args = append(args, filters.Limit, filters.Offset)
	query := `
SELECT id::text, tenant_id::text, actor_user_id::text, event_type, coalesce(target_type, ''), target_id::text,
       severity, coalesce(ip_address, ''), details, created_at
FROM audit_events
` + where + `
ORDER BY created_at DESC, id DESC
LIMIT $` + strconv.Itoa(len(args)-1) + ` OFFSET $` + strconv.Itoa(len(args))
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanEvents(rows)
}

func (s *Service) fileActivityCount(ctx context.Context, tenantID string) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND `+fileActivitySQL(), tenantID).Scan(&count)
	return count, err
}

func queryFileActivityEventsTx(ctx context.Context, tx *sql.Tx, tenantID string, scope cleanupScope) ([]Event, error) {
	args := []any{tenantID}
	conditions := []string{"tenant_id = $1", fileActivitySQL(), "event_type NOT IN ('audit.file_activity.cleaned', 'audit.file_activity.restored')"}
	if scope.Before != nil {
		args = append(args, *scope.Before)
		conditions = append(conditions, "created_at < $"+strconv.Itoa(len(args)))
	}
	if scope.OlderThanDays != nil && *scope.OlderThanDays > 0 {
		args = append(args, time.Now().UTC().Add(-time.Duration(*scope.OlderThanDays)*24*time.Hour))
		conditions = append(conditions, "created_at < $"+strconv.Itoa(len(args)))
	}
	query := `
SELECT id::text, tenant_id::text, actor_user_id::text, event_type, coalesce(target_type, ''), target_id::text,
       severity, coalesce(ip_address, ''), details, created_at
FROM audit_events
WHERE ` + strings.Join(conditions, " AND ") + `
ORDER BY created_at ASC, id ASC
FOR UPDATE`
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanEvents(rows)
}

func eventWhereClause(tenantID string, filters eventFilters) (string, []any) {
	args := []any{tenantID}
	conditions := []string{"tenant_id = $1"}
	if filters.EventType != "" {
		args = append(args, filters.EventType)
		conditions = append(conditions, "event_type = $"+strconv.Itoa(len(args)))
	}
	if filters.Severity != "" {
		args = append(args, filters.Severity)
		conditions = append(conditions, "severity = $"+strconv.Itoa(len(args)))
	}
	if filters.TargetType != "" {
		args = append(args, filters.TargetType)
		conditions = append(conditions, "target_type = $"+strconv.Itoa(len(args)))
	}
	if filters.FileRelated {
		conditions = append(conditions, fileActivitySQL())
	}
	if filters.From != nil {
		args = append(args, *filters.From)
		conditions = append(conditions, "created_at >= $"+strconv.Itoa(len(args)))
	}
	if filters.To != nil {
		args = append(args, *filters.To)
		conditions = append(conditions, "created_at <= $"+strconv.Itoa(len(args)))
	}
	return "WHERE " + strings.Join(conditions, " AND "), args
}

func fileActivitySQL() string {
	return `(
  event_type IN (
    'archive.file.downloaded',
    'archive.permission.updated'
  )
  OR target_type IN ('file', 'protected_folder')
  OR details ? 'file_id'
  OR details ? 'file_name'
  OR details ? 'folder_id'
  OR details ? 'plaintext_sha256'
)`
}

func scanEvents(rows *sql.Rows) ([]Event, error) {
	events := []Event{}
	for rows.Next() {
		var event Event
		var tenantID sql.NullString
		var actorID sql.NullString
		var targetID sql.NullString
		var details []byte
		if err := rows.Scan(
			&event.ID,
			&tenantID,
			&actorID,
			&event.EventType,
			&event.TargetType,
			&targetID,
			&event.Severity,
			&event.IPAddress,
			&details,
			&event.CreatedAt,
		); err != nil {
			return nil, err
		}
		if tenantID.Valid {
			event.TenantID = tenantID.String
		}
		if actorID.Valid {
			event.ActorUserID = &actorID.String
		}
		if targetID.Valid {
			event.TargetID = &targetID.String
		}
		event.Details = normalizedJSON(details)
		events = append(events, event)
	}
	return events, rows.Err()
}

func deleteEventsTx(ctx context.Context, tx *sql.Tx, events []Event) error {
	if len(events) == 0 {
		return nil
	}
	args := make([]any, 0, len(events))
	placeholders := make([]string, 0, len(events))
	for i, event := range events {
		args = append(args, event.ID)
		placeholders = append(placeholders, "$"+strconv.Itoa(i+1))
	}
	_, err := tx.ExecContext(ctx, `DELETE FROM audit_events WHERE id IN (`+strings.Join(placeholders, ",")+`)`, args...)
	return err
}

func insertEventsTx(ctx context.Context, tx *sql.Tx, tenantID string, events []Event) (int, error) {
	restored := 0
	for _, event := range events {
		if event.TenantID != tenantID {
			return restored, errors.New("backup_tenant_mismatch")
		}
		result, err := tx.ExecContext(ctx, `
INSERT INTO audit_events (id, tenant_id, actor_user_id, event_type, target_type, target_id, severity, ip_address, details, created_at)
VALUES ($1, $2, $3, $4, nullif($5, ''), $6, $7, nullif($8, ''), $9::jsonb, $10)
ON CONFLICT (id) DO NOTHING`, event.ID, event.TenantID, event.ActorUserID, event.EventType, event.TargetType, event.TargetID, event.Severity, event.IPAddress, string(normalizedJSON(event.Details)), event.CreatedAt)
		if err != nil {
			return restored, err
		}
		affected, _ := result.RowsAffected()
		if affected > 0 {
			restored++
		}
	}
	return restored, nil
}

func encodeBackup(payload backupPayload) (string, []byte, error) {
	checksumPayload := backupChecksumPayload{
		Format:       payload.Format,
		BackupID:     payload.BackupID,
		TenantID:     payload.TenantID,
		CreatedAt:    payload.CreatedAt,
		CreatedBy:    payload.CreatedBy,
		CleanupScope: payload.CleanupScope,
		EventCount:   payload.EventCount,
		Events:       payload.Events,
	}
	raw, err := json.Marshal(checksumPayload)
	if err != nil {
		return "", nil, err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), raw, nil
}

func newUUIDTx(ctx context.Context, tx *sql.Tx) (string, error) {
	var id string
	err := tx.QueryRowContext(ctx, `SELECT gen_random_uuid()::text`).Scan(&id)
	return id, err
}

func backupFileName(backupID string) string {
	return "archivon-file-activity-backup-" + backupID + ".json"
}

func writeDownload(w http.ResponseWriter, status int, fileName string, raw []byte) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+strings.ReplaceAll(fileName, `"`, "")+`"`)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_, _ = w.Write(raw)
}

func normalizedJSON(raw []byte) json.RawMessage {
	if len(bytes.TrimSpace(raw)) == 0 {
		return json.RawMessage(`{}`)
	}
	return json.RawMessage(raw)
}

func (s *Service) insertAuditEvent(ctx context.Context, tenantID string, actorUserID string, eventType string, targetType string, targetID *string, severity string, ipAddress string, details map[string]any) error {
	rawDetails, err := json.Marshal(details)
	if err != nil {
		rawDetails = []byte(`{}`)
	}
	var target any
	if targetID != nil && *targetID != "" {
		target = *targetID
	}
	_, err = s.db.ExecContext(ctx, `
INSERT INTO audit_events (tenant_id, actor_user_id, event_type, target_type, target_id, severity, ip_address, details)
VALUES ($1, $2, $3, nullif($4, ''), $5, $6, nullif($7, ''), $8::jsonb)`,
		tenantID, actorUserID, eventType, targetType, target, severity, ipAddress, string(rawDetails),
	)
	return err
}

func insertAuditEventTx(ctx context.Context, tx *sql.Tx, tenantID string, actorUserID string, eventType string, targetType string, targetID *string, severity string, ipAddress string, details map[string]any) error {
	rawDetails, err := json.Marshal(details)
	if err != nil {
		rawDetails = []byte(`{}`)
	}
	var target any
	if targetID != nil && *targetID != "" {
		target = *targetID
	}
	_, err = tx.ExecContext(ctx, `
INSERT INTO audit_events (tenant_id, actor_user_id, event_type, target_type, target_id, severity, ip_address, details)
VALUES ($1, $2, $3, nullif($4, ''), $5, $6, nullif($7, ''), $8::jsonb)`,
		tenantID, actorUserID, eventType, targetType, target, severity, ipAddress, string(rawDetails),
	)
	return err
}

func decodeJSON(w http.ResponseWriter, r *http.Request, target any) bool {
	defer r.Body.Close()
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json")
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		slog.Error("failed to write response", "error", err)
	}
}

func writeError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"error": code})
}

func writeMethodNotAllowed(w http.ResponseWriter, allow string) {
	w.Header().Set("Allow", allow)
	writeError(w, http.StatusMethodNotAllowed, "method_not_allowed")
}

func clientIP(r *http.Request) string {
	forwarded := strings.TrimSpace(r.Header.Get("X-Forwarded-For"))
	if forwarded != "" {
		parts := strings.Split(forwarded, ",")
		if len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}
	host := strings.TrimSpace(r.RemoteAddr)
	if idx := strings.LastIndex(host, ":"); idx > -1 {
		return host[:idx]
	}
	return host
}

var (
	errNoClearAll            = errors.New("clear_all_not_allowed")
	errChecksumMismatch      = errors.New("checksum_mismatch")
	errBackupNotFound        = errors.New("backup_not_found")
	errBackupAlreadyRestored = errors.New("backup_already_restored")
)
