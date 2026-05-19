package access

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"archivon/backend/internal/auth"
	"archivon/backend/internal/kms"
	"archivon/backend/internal/policyseal"
	"golang.org/x/crypto/bcrypt"
)

const powPolicyKey = "pow_access_policy"

const (
	defaultProofWindowSeconds = 60
	defaultMaxProofAttempts   = 3
	defaultTolerancePercent   = 10
)

type Service struct {
	db               *sql.DB
	logger           *slog.Logger
	auth             *auth.Service
	kms              *kms.Service
	nodeLinkProvider NodeLinkProvider
}

type NodeLinkProvider interface {
	HasActiveConnection() bool
}

type Policy struct {
	RequiredHashrateTHs      float64 `json:"required_hashrate_ths"`
	MinWorkers               int     `json:"min_workers"`
	HashrateTolerancePercent float64 `json:"hashrate_tolerance_percent"`
	ProofWindowSeconds       int     `json:"proof_window_seconds"`
	MaxProofAttempts         int     `json:"max_proof_attempts"`
	JobTimeoutMinutes        int     `json:"job_timeout_minutes"`
	SessionTTLMinutes        int     `json:"session_ttl_minutes"`
	AllowedSessionTTLMinutes []int   `json:"allowed_session_ttl_minutes"`
	SingleActiveSession      bool    `json:"single_active_session"`
	HeartbeatEnabled         bool    `json:"heartbeat_enabled"`
	UploadPoWRequired        bool    `json:"upload_pow_required"`
}

type settingsResponse struct {
	Policy              Policy  `json:"policy"`
	RequiredWorkTH      float64 `json:"required_work_th"`
	AcceptedHashrateTHs float64 `json:"accepted_hashrate_ths"`
	EstimatedWindow     string  `json:"estimated_window"`
	UpdateRoleRequired  string  `json:"update_role_required"`
}

type updateSettingsRequest struct {
	RequiredHashrateTHs      float64 `json:"required_hashrate_ths"`
	MinWorkers               int     `json:"min_workers"`
	HashrateTolerancePercent float64 `json:"hashrate_tolerance_percent"`
	ProofWindowSeconds       int     `json:"proof_window_seconds"`
	MaxProofAttempts         int     `json:"max_proof_attempts"`
	JobTimeoutMinutes        int     `json:"job_timeout_minutes"`
	SessionTTLMinutes        int     `json:"session_ttl_minutes"`
}

type createJobRequest struct {
	FolderID string `json:"folder_id"`
}

type jobsResponse struct {
	Jobs []Job `json:"jobs"`
}

type jobResponse struct {
	Job     Job            `json:"job"`
	Session *AccessSession `json:"session,omitempty"`
}

type clientJobsResponse struct {
	Jobs []ClientJob `json:"jobs"`
}

type clientJobResponse struct {
	Job     ClientJob      `json:"job"`
	Session *AccessSession `json:"session,omitempty"`
}

type sessionsResponse struct {
	Sessions []AccessSession `json:"sessions"`
}

type terminalResponse struct {
	Lines      []TerminalLine `json:"lines"`
	NodeLinkOK bool           `json:"node_link_ok"`
	UpdatedAt  time.Time      `json:"updated_at"`
}

type nodeLinkResponse struct {
	NodeLinkOK bool      `json:"node_link_ok"`
	UpdatedAt  time.Time `json:"updated_at"`
}

type TerminalLine struct {
	At      time.Time `json:"at"`
	Source  string    `json:"source"`
	Level   string    `json:"level"`
	Message string    `json:"message"`
}

type queueResponse struct {
	Policy         Policy          `json:"policy"`
	Jobs           []Job           `json:"jobs"`
	ActiveSessions []AccessSession `json:"active_sessions"`
}

type Job struct {
	ID                       string     `json:"id"`
	UserID                   string     `json:"user_id"`
	Username                 string     `json:"username,omitempty"`
	FolderID                 string     `json:"folder_id"`
	Status                   string     `json:"status"`
	RequiredHashrateTHs      float64    `json:"required_hashrate_ths"`
	RequiredWorkTH           float64    `json:"required_work_th"`
	ObservedHashrateTHs      *float64   `json:"observed_hashrate_ths,omitempty"`
	MinWorkers               int        `json:"min_workers"`
	HashrateTolerancePercent float64    `json:"hashrate_tolerance_percent"`
	ProofWindowSeconds       int        `json:"proof_window_seconds"`
	MaxProofAttempts         int        `json:"max_proof_attempts"`
	TimeoutSeconds           int        `json:"timeout_seconds"`
	QueuePosition            int        `json:"queue_position"`
	FailureReason            string     `json:"failure_reason,omitempty"`
	ValidWorkTH              float64    `json:"valid_work_th"`
	ValidWorkerCount         int        `json:"valid_worker_count"`
	CreatedAt                time.Time  `json:"created_at"`
	StartedAt                *time.Time `json:"started_at,omitempty"`
	FinishedAt               *time.Time `json:"finished_at,omitempty"`
}

type ClientJob struct {
	ID            string     `json:"id"`
	FolderID      string     `json:"folder_id"`
	Status        string     `json:"status"`
	QueuePosition int        `json:"queue_position"`
	CreatedAt     time.Time  `json:"created_at"`
	StartedAt     *time.Time `json:"started_at,omitempty"`
	FinishedAt    *time.Time `json:"finished_at,omitempty"`
}

type AccessSession struct {
	ID          string     `json:"id"`
	UserID      string     `json:"user_id"`
	Username    string     `json:"username,omitempty"`
	FolderID    string     `json:"folder_id"`
	PoWJobID    *string    `json:"pow_job_id,omitempty"`
	Status      string     `json:"status"`
	OpenedAt    time.Time  `json:"opened_at"`
	ExpiresAt   time.Time  `json:"expires_at"`
	ClosedAt    *time.Time `json:"closed_at,omitempty"`
	CloseReason string     `json:"close_reason,omitempty"`
	DavURL      string     `json:"dav_url,omitempty"`
	DavUsername string     `json:"dav_username,omitempty"`
	DavPassword string     `json:"dav_password,omitempty"`
}

type runningJob struct {
	id                       string
	userID                   string
	folderID                 string
	requiredWorkTH           float64
	requiredHashrateTHs      float64
	minWorkers               int
	hashrateTolerancePercent float64
	proofWindowSeconds       int
	maxProofAttempts         int
	sessionTTLMinutes        int
	startedAt                time.Time
}

func NewService(db *sql.DB, logger *slog.Logger, authService *auth.Service, kmsService *kms.Service) *Service {
	return &Service{
		db:     db,
		logger: logger,
		auth:   authService,
		kms:    kmsService,
	}
}

func (s *Service) SetNodeLinkProvider(provider NodeLinkProvider) {
	s.nodeLinkProvider = provider
}

func (s *Service) Register(mux *http.ServeMux) {
	mux.Handle("/api/admin/access/settings", s.auth.RequireRole(http.HandlerFunc(s.handleSettings), "super_admin", "admin"))
	mux.Handle("/api/admin/access/queue", s.auth.RequireRole(http.HandlerFunc(s.handleQueue), "super_admin", "admin"))
	mux.Handle("/api/admin/access/sessions/", s.auth.RequireRole(http.HandlerFunc(s.handleAdminSessionAction), "super_admin", "admin"))
	mux.Handle("/api/client/access/jobs", s.auth.RequireRole(http.HandlerFunc(s.handleClientJobs), "client"))
	mux.Handle("/api/client/access/jobs/", s.auth.RequireRole(http.HandlerFunc(s.handleClientJobAction), "client"))
	mux.Handle("/api/client/access/sessions", s.auth.RequireRole(http.HandlerFunc(s.handleClientSessions), "client"))
	mux.Handle("/api/client/access/sessions/", s.auth.RequireRole(http.HandlerFunc(s.handleClientSessionAction), "client"))
	mux.Handle("/api/client/access/node-link", s.auth.RequireRole(http.HandlerFunc(s.handleClientNodeLink), "client"))
	mux.Handle("/api/client/access/terminal", s.auth.RequireRole(http.HandlerFunc(s.handleClientTerminal), "client"))
}

func (s *Service) Reconcile(ctx context.Context, tenantID string) error {
	return s.reconcile(ctx, tenantID)
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
			writeError(w, http.StatusInternalServerError, "policy_load_failed")
			return
		}
		writeJSON(w, http.StatusOK, settingsResponse{
			Policy:              policy,
			RequiredWorkTH:      requiredWorkTH(policy),
			AcceptedHashrateTHs: acceptedHashrateTHs(policy),
			EstimatedWindow:     time.Duration(policy.ProofWindowSeconds * int(time.Second)).String(),
			UpdateRoleRequired:  "super_admin",
		})
	case http.MethodPost:
		if user.Role != "super_admin" {
			writeError(w, http.StatusForbidden, "super_admin_required")
			return
		}
		var req updateSettingsRequest
		if !decodeJSON(w, r, &req) {
			return
		}
		policy := normalizePolicy(Policy{
			RequiredHashrateTHs:      req.RequiredHashrateTHs,
			MinWorkers:               1,
			HashrateTolerancePercent: req.HashrateTolerancePercent,
			ProofWindowSeconds:       req.ProofWindowSeconds,
			MaxProofAttempts:         req.MaxProofAttempts,
			JobTimeoutMinutes:        req.JobTimeoutMinutes,
			SessionTTLMinutes:        req.SessionTTLMinutes,
			AllowedSessionTTLMinutes: []int{10, 15, 30, 60},
			SingleActiveSession:      true,
			HeartbeatEnabled:         false,
			UploadPoWRequired:        false,
		})
		if err := validatePolicy(policy); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		raw, err := json.Marshal(policy)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "policy_encode_failed")
			return
		}
		if _, err := s.db.ExecContext(r.Context(), `
INSERT INTO system_settings (key, value, updated_by, updated_at)
VALUES ($1, $2::jsonb, $3, now())
ON CONFLICT (key) DO UPDATE
SET value = EXCLUDED.value,
    updated_by = EXCLUDED.updated_by,
    updated_at = now()`, powPolicyKey, string(raw), user.ID); err != nil {
			writeError(w, http.StatusInternalServerError, "policy_update_failed")
			return
		}
		if err := s.insertAuditEvent(r.Context(), user.TenantID, user.ID, "access.pow_policy.updated", "system_setting", nil, "warning", clientIP(r), map[string]any{
			"required_hashrate_ths":      policy.RequiredHashrateTHs,
			"accepted_hashrate_ths":      acceptedHashrateTHs(policy),
			"hashrate_tolerance_percent": policy.HashrateTolerancePercent,
			"min_workers":                policy.MinWorkers,
			"proof_window_seconds":       policy.ProofWindowSeconds,
			"max_proof_attempts":         policy.MaxProofAttempts,
			"job_timeout_minutes":        policy.JobTimeoutMinutes,
			"session_ttl_minutes":        policy.SessionTTLMinutes,
		}); err != nil {
			writeError(w, http.StatusInternalServerError, "audit_failed")
			return
		}
		writeJSON(w, http.StatusOK, settingsResponse{
			Policy:              policy,
			RequiredWorkTH:      requiredWorkTH(policy),
			AcceptedHashrateTHs: acceptedHashrateTHs(policy),
			EstimatedWindow:     time.Duration(policy.ProofWindowSeconds * int(time.Second)).String(),
			UpdateRoleRequired:  "super_admin",
		})
	default:
		writeMethodNotAllowed(w, "GET, POST")
	}
}

func (s *Service) handleQueue(w http.ResponseWriter, r *http.Request) {
	user, err := s.auth.CurrentUser(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "not_authenticated")
		return
	}
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, "GET")
		return
	}
	if err := s.reconcile(r.Context(), user.TenantID); err != nil {
		writeError(w, http.StatusInternalServerError, "reconcile_failed")
		return
	}
	policy, err := s.loadPolicy(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "policy_load_failed")
		return
	}
	jobs, err := s.listJobs(r.Context(), user.TenantID, "", true)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "jobs_query_failed")
		return
	}
	sessions, err := s.listActiveSessions(r.Context(), user.TenantID, "", true)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "sessions_query_failed")
		return
	}
	writeJSON(w, http.StatusOK, queueResponse{Policy: policy, Jobs: jobs, ActiveSessions: sessions})
}

func (s *Service) handleClientJobs(w http.ResponseWriter, r *http.Request) {
	user, err := s.auth.CurrentUser(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "not_authenticated")
		return
	}
	if err := s.reconcile(r.Context(), user.TenantID); err != nil {
		writeError(w, http.StatusInternalServerError, "reconcile_failed")
		return
	}
	switch r.Method {
	case http.MethodGet:
		jobs, err := s.listJobs(r.Context(), user.TenantID, user.ID, false)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "jobs_query_failed")
			return
		}
		writeJSON(w, http.StatusOK, clientJobsResponse{Jobs: toClientJobs(jobs)})
	case http.MethodPost:
		var req createJobRequest
		if !decodeJSON(w, r, &req) {
			return
		}
		job, session, err := s.createJob(r.Context(), user, strings.TrimSpace(req.FolderID), clientIP(r))
		if err != nil {
			s.writeAccessError(w, err)
			return
		}
		if session != nil {
			if err := s.enrichClientSessionDAV(r.Context(), r, user.TenantID, session); err != nil {
				writeError(w, http.StatusInternalServerError, "dav_credentials_failed")
				return
			}
		}
		writeJSON(w, http.StatusCreated, clientJobResponse{Job: toClientJob(job), Session: session})
	default:
		writeMethodNotAllowed(w, "GET, POST")
	}
}

func (s *Service) handleAdminSessionAction(w http.ResponseWriter, r *http.Request) {
	user, err := s.auth.CurrentUser(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "not_authenticated")
		return
	}
	pathValue := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/admin/access/sessions/"), "/")
	parts := strings.Split(pathValue, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] != "close" {
		writeError(w, http.StatusNotFound, "not_found")
		return
	}
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, "POST")
		return
	}
	if err := s.reconcile(r.Context(), user.TenantID); err != nil {
		writeError(w, http.StatusInternalServerError, "reconcile_failed")
		return
	}
	session, err := s.closeSessionAsAdmin(r.Context(), user, parts[0], clientIP(r))
	if err != nil {
		s.writeAccessError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]AccessSession{"session": session})
}

func (s *Service) handleClientJobAction(w http.ResponseWriter, r *http.Request) {
	user, err := s.auth.CurrentUser(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "not_authenticated")
		return
	}
	pathValue := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/client/access/jobs/"), "/")
	parts := strings.Split(pathValue, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] != "cancel" {
		writeError(w, http.StatusNotFound, "not_found")
		return
	}
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, "POST")
		return
	}
	if err := s.reconcile(r.Context(), user.TenantID); err != nil {
		writeError(w, http.StatusInternalServerError, "reconcile_failed")
		return
	}
	job, err := s.cancelJob(r.Context(), user, parts[0], clientIP(r))
	if err != nil {
		s.writeAccessError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, clientJobResponse{Job: toClientJob(job)})
}

func (s *Service) handleClientSessions(w http.ResponseWriter, r *http.Request) {
	user, err := s.auth.CurrentUser(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "not_authenticated")
		return
	}
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, "GET")
		return
	}
	if err := s.reconcile(r.Context(), user.TenantID); err != nil {
		writeError(w, http.StatusInternalServerError, "reconcile_failed")
		return
	}
	sessions, err := s.listActiveSessions(r.Context(), user.TenantID, user.ID, false)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "sessions_query_failed")
		return
	}
	for index := range sessions {
		if err := s.enrichClientSessionDAV(r.Context(), r, user.TenantID, &sessions[index]); err != nil {
			writeError(w, http.StatusInternalServerError, "dav_credentials_failed")
			return
		}
	}
	writeJSON(w, http.StatusOK, sessionsResponse{Sessions: sessions})
}

func (s *Service) handleClientTerminal(w http.ResponseWriter, r *http.Request) {
	user, err := s.auth.CurrentUser(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "not_authenticated")
		return
	}
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, "GET")
		return
	}
	if err := s.reconcile(r.Context(), user.TenantID); err != nil {
		writeError(w, http.StatusInternalServerError, "reconcile_failed")
		return
	}
	folderID := strings.TrimSpace(r.URL.Query().Get("folder_id"))
	if !isUUIDLike(folderID) {
		writeError(w, http.StatusNotFound, "folder_not_found")
		return
	}
	allowed, err := s.canUnlock(r.Context(), user.TenantID, user.ID, folderID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusForbidden, "unlock_not_allowed")
			return
		}
		writeError(w, http.StatusInternalServerError, "permission_query_failed")
		return
	}
	if !allowed {
		writeError(w, http.StatusForbidden, "unlock_not_allowed")
		return
	}
	lines, err := s.terminalLines(r.Context(), user, folderID)
	if err != nil {
		if s.logger != nil {
			s.logger.Warn("client terminal query failed", "user_id", user.ID, "folder_id", folderID, "error", err)
		}
		writeError(w, http.StatusInternalServerError, "terminal_query_failed")
		return
	}
	writeJSON(w, http.StatusOK, terminalResponse{Lines: lines, NodeLinkOK: s.nodeLinkOK(), UpdatedAt: time.Now().UTC()})
}

func (s *Service) handleClientNodeLink(w http.ResponseWriter, r *http.Request) {
	if _, err := s.auth.CurrentUser(r); err != nil {
		writeError(w, http.StatusUnauthorized, "not_authenticated")
		return
	}
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, "GET")
		return
	}
	writeJSON(w, http.StatusOK, nodeLinkResponse{NodeLinkOK: s.nodeLinkOK(), UpdatedAt: time.Now().UTC()})
}

func (s *Service) nodeLinkOK() bool {
	if s.nodeLinkProvider != nil {
		return s.nodeLinkProvider.HasActiveConnection()
	}
	return false
}

func (s *Service) handleClientSessionAction(w http.ResponseWriter, r *http.Request) {
	user, err := s.auth.CurrentUser(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "not_authenticated")
		return
	}
	pathValue := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/client/access/sessions/"), "/")
	parts := strings.Split(pathValue, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] != "close" {
		writeError(w, http.StatusNotFound, "not_found")
		return
	}
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, "POST")
		return
	}
	if err := s.reconcile(r.Context(), user.TenantID); err != nil {
		writeError(w, http.StatusInternalServerError, "reconcile_failed")
		return
	}
	session, err := s.closeSession(r.Context(), user, parts[0], clientIP(r))
	if err != nil {
		s.writeAccessError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]AccessSession{"session": session})
}

func (s *Service) createJob(ctx context.Context, user auth.User, folderID string, ip string) (Job, *AccessSession, error) {
	if !isUUIDLike(folderID) {
		return Job{}, nil, accessError{code: http.StatusNotFound, key: "folder_not_found"}
	}
	allowed, err := s.canUnlock(ctx, user.TenantID, user.ID, folderID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Job{}, nil, accessError{code: http.StatusNotFound, key: "folder_not_found"}
		}
		return Job{}, nil, err
	}
	if !allowed {
		return Job{}, nil, accessError{code: http.StatusForbidden, key: "unlock_not_allowed"}
	}
	policy, err := s.loadFolderPolicy(ctx, user.TenantID, folderID)
	if err != nil {
		return Job{}, nil, err
	}
	if session, err := s.activeSessionForFolder(ctx, user.TenantID, user.ID, folderID); err == nil {
		job := Job{UserID: user.ID, FolderID: folderID, Status: "succeeded"}
		return job, &session, nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return Job{}, nil, err
	}
	if job, err := s.existingOpenJob(ctx, user.TenantID, user.ID, folderID); err == nil {
		return job, nil, nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return Job{}, nil, err
	}
	requiredWork := requiredWorkTH(policy)
	timeoutSeconds := policy.ProofWindowSeconds * policy.MaxProofAttempts
	if timeoutSeconds <= 0 {
		timeoutSeconds = defaultProofWindowSeconds * defaultMaxProofAttempts
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Job{}, nil, err
	}
	defer func() {
		_ = tx.Rollback()
	}()
	if activeSession, err := s.activeSessionExistsTx(ctx, tx, user.TenantID); err != nil {
		return Job{}, nil, err
	} else if activeSession {
		return Job{}, nil, accessError{code: http.StatusConflict, key: "active_session_must_be_closed"}
	}
	status := "queued"
	var startedAt any
	if canStart, err := s.canStartJobTx(ctx, tx, user.TenantID); err != nil {
		return Job{}, nil, err
	} else if canStart {
		status = "running"
		startedAt = time.Now().UTC()
	} else if activeSession, err := s.activeSessionExistsTx(ctx, tx, user.TenantID); err != nil {
		return Job{}, nil, err
	} else if activeSession {
		return Job{}, nil, accessError{code: http.StatusConflict, key: "active_session_must_be_closed"}
	}
	var jobID string
	if err := tx.QueryRowContext(ctx, `
INSERT INTO pow_jobs (
  tenant_id, user_id, protected_folder_id, status, required_hashrate_ths, required_work_th,
  min_workers, proof_window_seconds, hashrate_tolerance_percent, max_proof_attempts,
  timeout_seconds, session_ttl_minutes, started_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
RETURNING id::text`,
		user.TenantID,
		user.ID,
		folderID,
		status,
		policy.RequiredHashrateTHs,
		requiredWork,
		policy.MinWorkers,
		policy.ProofWindowSeconds,
		policy.HashrateTolerancePercent,
		policy.MaxProofAttempts,
		timeoutSeconds,
		policy.SessionTTLMinutes,
		startedAt,
	).Scan(&jobID); err != nil {
		return Job{}, nil, err
	}
	if err := insertAuditEventTx(ctx, tx, user.TenantID, user.ID, "access.pow_job.created", "pow_job", &jobID, "info", ip, map[string]any{
		"folder_id":                  folderID,
		"status":                     status,
		"required_hashrate_ths":      policy.RequiredHashrateTHs,
		"accepted_hashrate_ths":      acceptedHashrateTHs(policy),
		"hashrate_tolerance_percent": policy.HashrateTolerancePercent,
		"required_work_th":           requiredWork,
		"min_workers":                policy.MinWorkers,
		"proof_window_seconds":       policy.ProofWindowSeconds,
		"max_proof_attempts":         policy.MaxProofAttempts,
		"timeout_seconds":            timeoutSeconds,
		"single_active_session":      true,
		"heartbeat_enabled":          false,
		"upload_pow_required":        false,
	}); err != nil {
		return Job{}, nil, err
	}
	if err := tx.Commit(); err != nil {
		return Job{}, nil, err
	}
	job, err := s.jobByID(ctx, user.TenantID, jobID, false)
	return job, nil, err
}

func (s *Service) cancelJob(ctx context.Context, user auth.User, jobID string, ip string) (Job, error) {
	if !isUUIDLike(jobID) {
		return Job{}, accessError{code: http.StatusNotFound, key: "job_not_found"}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Job{}, err
	}
	defer func() {
		_ = tx.Rollback()
	}()
	var previousStatus string
	if err := tx.QueryRowContext(ctx, `
UPDATE pow_jobs
SET status = 'canceled',
    finished_at = now(),
    failure_reason = 'client_canceled'
WHERE tenant_id = $1
  AND user_id = $2
  AND id = $3
  AND status IN ('queued', 'running')
RETURNING status`, user.TenantID, user.ID, jobID).Scan(&previousStatus); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Job{}, accessError{code: http.StatusNotFound, key: "job_not_found_or_closed"}
		}
		return Job{}, err
	}
	if err := insertAuditEventTx(ctx, tx, user.TenantID, user.ID, "access.pow_job.canceled", "pow_job", &jobID, "warning", ip, map[string]any{
		"previous_status": previousStatus,
	}); err != nil {
		return Job{}, err
	}
	if err := s.promoteNextQueuedTx(ctx, tx, user.TenantID); err != nil {
		return Job{}, err
	}
	if err := tx.Commit(); err != nil {
		return Job{}, err
	}
	return s.jobByID(ctx, user.TenantID, jobID, false)
}

func (s *Service) closeSession(ctx context.Context, user auth.User, sessionID string, ip string) (AccessSession, error) {
	if !isUUIDLike(sessionID) {
		return AccessSession{}, accessError{code: http.StatusNotFound, key: "session_not_found"}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return AccessSession{}, err
	}
	defer func() {
		_ = tx.Rollback()
	}()
	result, err := tx.ExecContext(ctx, `
UPDATE access_sessions
SET status = 'closed',
    closed_at = now(),
    close_reason = 'client_closed'
WHERE tenant_id = $1
  AND user_id = $2
  AND id = $3
  AND status = 'active'`, user.TenantID, user.ID, sessionID)
	if err != nil {
		return AccessSession{}, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return AccessSession{}, err
	}
	if affected == 0 {
		return AccessSession{}, accessError{code: http.StatusNotFound, key: "session_not_found"}
	}
	if err := insertAuditEventTx(ctx, tx, user.TenantID, user.ID, "access.session.closed", "access_session", &sessionID, "info", ip, map[string]any{
		"close_reason": "client_closed",
	}); err != nil {
		return AccessSession{}, err
	}
	if err := s.promoteNextQueuedTx(ctx, tx, user.TenantID); err != nil {
		return AccessSession{}, err
	}
	if err := tx.Commit(); err != nil {
		return AccessSession{}, err
	}
	return s.sessionByID(ctx, user.TenantID, sessionID, false)
}

func (s *Service) closeSessionAsAdmin(ctx context.Context, user auth.User, sessionID string, ip string) (AccessSession, error) {
	if !isUUIDLike(sessionID) {
		return AccessSession{}, accessError{code: http.StatusNotFound, key: "session_not_found"}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return AccessSession{}, err
	}
	defer func() {
		_ = tx.Rollback()
	}()
	var closedUserID string
	var folderID string
	if err := tx.QueryRowContext(ctx, `
UPDATE access_sessions
SET status = 'closed',
    closed_at = now(),
    close_reason = 'admin_closed'
WHERE tenant_id = $1
  AND id = $2
  AND status = 'active'
  AND expires_at > now()
RETURNING user_id::text, protected_folder_id::text`, user.TenantID, sessionID).Scan(&closedUserID, &folderID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return AccessSession{}, accessError{code: http.StatusNotFound, key: "session_not_found"}
		}
		return AccessSession{}, err
	}
	if err := insertAuditEventTx(ctx, tx, user.TenantID, user.ID, "access.session.admin_closed", "access_session", &sessionID, "warning", ip, map[string]any{
		"close_reason":        "admin_closed",
		"closed_user_id":      closedUserID,
		"protected_folder_id": folderID,
	}); err != nil {
		return AccessSession{}, err
	}
	if err := s.promoteNextQueuedTx(ctx, tx, user.TenantID); err != nil {
		return AccessSession{}, err
	}
	if err := tx.Commit(); err != nil {
		return AccessSession{}, err
	}
	return s.sessionByID(ctx, user.TenantID, sessionID, true)
}

func (s *Service) reconcile(ctx context.Context, tenantID string) error {
	if err := s.expireSessions(ctx, tenantID); err != nil {
		return err
	}
	if err := s.timeoutJobs(ctx, tenantID); err != nil {
		return err
	}
	if err := s.completeRunningJobs(ctx, tenantID); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		_ = tx.Rollback()
	}()
	if err := s.promoteNextQueuedTx(ctx, tx, tenantID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Service) expireSessions(ctx context.Context, tenantID string) error {
	_, err := s.db.ExecContext(ctx, `
UPDATE access_sessions
SET status = 'expired',
    closed_at = now(),
    close_reason = 'ttl_expired'
WHERE tenant_id = $1
  AND status = 'active'
  AND expires_at <= now()`, tenantID)
	return err
}

func (s *Service) timeoutJobs(ctx context.Context, tenantID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		_ = tx.Rollback()
	}()
	if _, err := tx.ExecContext(ctx, `
UPDATE pow_jobs
SET status = 'timeout',
    finished_at = now(),
    failure_reason = 'timeout'
WHERE tenant_id = $1
  AND (
    (status = 'running' AND started_at IS NOT NULL AND started_at + (timeout_seconds * interval '1 second') <= now())
    OR
    (status = 'running' AND started_at IS NULL AND created_at + (timeout_seconds * interval '1 second') <= now())
    OR
    (status = 'queued' AND created_at + (timeout_seconds * interval '1 second') <= now())
  )`, tenantID); err != nil {
		return err
	}
	if err := s.promoteNextQueuedTx(ctx, tx, tenantID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Service) completeRunningJobs(ctx context.Context, tenantID string) error {
	rows, err := s.db.QueryContext(ctx, `
SELECT id::text, user_id::text, protected_folder_id::text,
       required_work_th::float8, required_hashrate_ths::float8, min_workers,
       hashrate_tolerance_percent::float8, proof_window_seconds, max_proof_attempts,
       session_ttl_minutes, started_at
FROM pow_jobs
WHERE tenant_id = $1 AND status = 'running' AND started_at IS NOT NULL
ORDER BY started_at`, tenantID)
	if err != nil {
		return err
	}
	defer rows.Close()

	var jobs []runningJob
	for rows.Next() {
		var job runningJob
		if err := rows.Scan(
			&job.id,
			&job.userID,
			&job.folderID,
			&job.requiredWorkTH,
			&job.requiredHashrateTHs,
			&job.minWorkers,
			&job.hashrateTolerancePercent,
			&job.proofWindowSeconds,
			&job.maxProofAttempts,
			&job.sessionTTLMinutes,
			&job.startedAt,
		); err != nil {
			return err
		}
		jobs = append(jobs, job)
	}
	if err := rows.Err(); err != nil {
		return err
	}

	for _, job := range jobs {
		validWork, _, _, err := s.bestAttemptProgress(ctx, tenantID, job.id, job.startedAt, job.proofWindowSeconds, job.maxProofAttempts)
		if err != nil {
			return err
		}
		if validWork < job.requiredWorkTH {
			continue
		}
		if err := s.openSessionForCompletedJob(ctx, tenantID, job, validWork); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) openSessionForCompletedJob(ctx context.Context, tenantID string, job runningJob, validWork float64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		_ = tx.Rollback()
	}()
	activeSession, err := s.activeSessionExistsTx(ctx, tx, tenantID)
	if err != nil {
		return err
	}
	if activeSession {
		if _, err := tx.ExecContext(ctx, `
UPDATE pow_jobs
SET status = 'canceled',
    finished_at = now(),
    failure_reason = 'active_session_opened'
WHERE tenant_id = $1
  AND id = $2
  AND status = 'running'`, tenantID, job.id); err != nil {
			return err
		}
		return nil
	}
	proofWindowSeconds := normalizePositiveInt(job.proofWindowSeconds, defaultProofWindowSeconds)
	sessionTTLMinutes := normalizePositiveInt(job.sessionTTLMinutes, 30)
	observedHashrate := validWork / float64(proofWindowSeconds)
	if _, err := tx.ExecContext(ctx, `
UPDATE pow_jobs
SET status = 'succeeded',
    observed_hashrate_ths = $1,
    finished_at = now()
WHERE tenant_id = $2 AND id = $3 AND status = 'running'`, observedHashrate, tenantID, job.id); err != nil {
		return err
	}
	var sessionID string
	if err := tx.QueryRowContext(ctx, `
INSERT INTO access_sessions (tenant_id, user_id, protected_folder_id, pow_job_id, status, expires_at)
VALUES ($1, $2, $3, $4, 'active', now() + ($5::int * interval '1 minute'))
RETURNING id::text`, tenantID, job.userID, job.folderID, job.id, sessionTTLMinutes).Scan(&sessionID); err != nil {
		return err
	}
	if err := s.assignDAVCredentialsTx(ctx, tx, tenantID, sessionID); err != nil {
		return err
	}
	canceledQueuedJobs, err := s.cancelQueuedJobsForActiveSessionTx(ctx, tx, tenantID, job.id)
	if err != nil {
		return err
	}
	if err := insertAuditEventTx(ctx, tx, tenantID, job.userID, "access.session.opened", "access_session", &sessionID, "critical", "", map[string]any{
		"pow_job_id":                 job.id,
		"folder_id":                  job.folderID,
		"observed_hashrate_ths":      observedHashrate,
		"valid_work_th":              validWork,
		"required_hashrate_ths":      job.requiredHashrateTHs,
		"required_work_th":           job.requiredWorkTH,
		"hashrate_tolerance_percent": job.hashrateTolerancePercent,
		"proof_window_seconds":       proofWindowSeconds,
		"max_proof_attempts":         normalizePositiveInt(job.maxProofAttempts, defaultMaxProofAttempts),
		"session_ttl_minutes":        sessionTTLMinutes,
		"canceled_queued_jobs":       canceledQueuedJobs,
	}); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Service) cancelQueuedJobsForActiveSessionTx(ctx context.Context, tx *sql.Tx, tenantID string, activeJobID string) (int64, error) {
	result, err := tx.ExecContext(ctx, `
UPDATE pow_jobs
SET status = 'canceled',
    finished_at = now(),
    failure_reason = 'active_session_opened'
WHERE tenant_id = $1
  AND status = 'queued'
  AND id <> $2`, tenantID, activeJobID)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func (s *Service) assignDAVCredentialsTx(ctx context.Context, tx *sql.Tx, tenantID string, sessionID string) error {
	if s.kms == nil {
		return errors.New("kms_not_configured")
	}
	username := "dav_" + strings.ReplaceAll(sessionID, "-", "")
	password, err := newDAVPassword()
	if err != nil {
		return err
	}
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	nonce, ciphertext, err := s.kms.EncryptMetadata(ctx, []byte(password), davPasswordAAD(tenantID, sessionID))
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `
UPDATE access_sessions
SET dav_username = $1,
    dav_password_hash = $2,
    dav_password_ciphertext = $3,
    dav_password_nonce = $4
WHERE tenant_id = $5 AND id = $6`, username, string(passwordHash), ciphertext, nonce, tenantID, sessionID)
	return err
}

func (s *Service) enrichClientSessionDAV(ctx context.Context, r *http.Request, tenantID string, session *AccessSession) error {
	if session == nil || session.ID == "" || s.kms == nil {
		return nil
	}
	var username sql.NullString
	var ciphertext []byte
	var nonce []byte
	err := s.db.QueryRowContext(ctx, `
SELECT dav_username, dav_password_ciphertext, dav_password_nonce
FROM access_sessions
WHERE tenant_id = $1
  AND user_id = $2
  AND id = $3
  AND status = 'active'
  AND expires_at > now()`, tenantID, session.UserID, session.ID).Scan(&username, &ciphertext, &nonce)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		return err
	}
	if !username.Valid || username.String == "" || len(ciphertext) == 0 || len(nonce) == 0 {
		return nil
	}
	password, err := s.kms.DecryptMetadata(ctx, nonce, ciphertext, davPasswordAAD(tenantID, session.ID))
	if err != nil {
		return err
	}
	session.DavUsername = username.String
	session.DavPassword = string(password)
	session.DavURL = davURLFromRequest(r, username.String)
	return nil
}

func (s *Service) canStartJobTx(ctx context.Context, tx *sql.Tx, tenantID string) (bool, error) {
	var blocking int
	if err := tx.QueryRowContext(ctx, `
SELECT count(*)
FROM (
  SELECT id FROM pow_jobs WHERE tenant_id = $1 AND status = 'running'
  UNION ALL
  SELECT id FROM access_sessions WHERE tenant_id = $1 AND status = 'active' AND expires_at > now()
) blockers`, tenantID).Scan(&blocking); err != nil {
		return false, err
	}
	return blocking == 0, nil
}

func (s *Service) activeSessionExistsTx(ctx context.Context, tx *sql.Tx, tenantID string) (bool, error) {
	var active int
	if err := tx.QueryRowContext(ctx, `
SELECT count(*)
FROM access_sessions
WHERE tenant_id = $1
  AND status = 'active'
  AND expires_at > now()`, tenantID).Scan(&active); err != nil {
		return false, err
	}
	return active > 0, nil
}

func (s *Service) promoteNextQueuedTx(ctx context.Context, tx *sql.Tx, tenantID string) error {
	canStart, err := s.canStartJobTx(ctx, tx, tenantID)
	if err != nil {
		return err
	}
	if !canStart {
		return nil
	}
	_, err = tx.ExecContext(ctx, `
UPDATE pow_jobs
SET status = 'running',
    started_at = now()
WHERE id = (
  SELECT id
  FROM pow_jobs
  WHERE tenant_id = $1 AND status = 'queued'
  ORDER BY created_at
  LIMIT 1
)`, tenantID)
	return err
}

func (s *Service) validShareProgress(ctx context.Context, tenantID string, jobID string, startedAt time.Time, proofWindowSeconds int) (float64, int, error) {
	var validWork float64
	var workerCount int
	proofWindowSeconds = normalizePositiveInt(proofWindowSeconds, defaultProofWindowSeconds)
	err := s.db.QueryRowContext(ctx, `
SELECT coalesce(sum(work_th), 0)::float8, count(DISTINCT compute_worker_id)::int
FROM pow_shares
WHERE tenant_id = $1
  AND pow_job_id = $2
  AND is_valid = true
  AND submitted_at >= $3
  AND submitted_at <= $3 + ($4::int * interval '1 second')`, tenantID, jobID, startedAt, proofWindowSeconds).Scan(&validWork, &workerCount)
	return validWork, workerCount, err
}

func (s *Service) bestAttemptProgress(ctx context.Context, tenantID string, jobID string, startedAt time.Time, proofWindowSeconds int, maxAttempts int) (float64, int, int, error) {
	proofWindowSeconds = normalizePositiveInt(proofWindowSeconds, defaultProofWindowSeconds)
	maxAttempts = normalizePositiveInt(maxAttempts, defaultMaxProofAttempts)
	now := time.Now().UTC()
	bestWork := 0.0
	bestWorkers := 0
	bestAttempt := 1
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		attemptStart := startedAt.Add(time.Duration((attempt-1)*proofWindowSeconds) * time.Second)
		if attemptStart.After(now) {
			break
		}
		validWork, workerCount, err := s.validShareProgress(ctx, tenantID, jobID, attemptStart, proofWindowSeconds)
		if err != nil {
			return 0, 0, 0, err
		}
		if validWork > bestWork {
			bestWork = validWork
			bestWorkers = workerCount
			bestAttempt = attempt
		}
	}
	return bestWork, bestWorkers, bestAttempt, nil
}

func (s *Service) canUnlock(ctx context.Context, tenantID string, userID string, folderID string) (bool, error) {
	var allowed bool
	err := s.db.QueryRowContext(ctx, `
SELECT fp.can_unlock_and_access
FROM folder_permissions fp
JOIN protected_folders pf ON pf.id = fp.protected_folder_id
WHERE fp.tenant_id = $1
  AND fp.user_id = $2
  AND fp.protected_folder_id = $3
  AND pf.status = 'active'
  AND (fp.expires_at IS NULL OR fp.expires_at > now())`, tenantID, userID, folderID).Scan(&allowed)
	return allowed, err
}

func (s *Service) terminalLines(ctx context.Context, user auth.User, folderID string) ([]TerminalLine, error) {
	now := time.Now().UTC()
	lines := []TerminalLine{}
	appendLine := func(at time.Time, source string, level string, message string) {
		if at.IsZero() {
			at = now
		}
		lines = append(lines, TerminalLine{
			At:      at.UTC(),
			Source:  source,
			Level:   level,
			Message: message,
		})
	}

	var activeSession *AccessSession
	if session, err := s.activeSessionForFolder(ctx, user.TenantID, user.ID, folderID); err == nil {
		activeSession = &session
		appendLine(session.OpenedAt, "proxy", "ok", "open")
	} else if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}

	job, err := s.latestJobForFolder(ctx, user.TenantID, user.ID, folderID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			appendLine(now, "terminal", "muted", "closed")
			return lines, nil
		}
		return nil, err
	}

	switch job.Status {
	case "queued":
		appendLine(job.CreatedAt, "proxy", "warn", "verification running")
	case "running":
		startedAt := job.CreatedAt
		if job.StartedAt != nil {
			startedAt = *job.StartedAt
		}
		appendLine(startedAt, "proxy", "info", "verification running")
		if job.ValidWorkTH > 0 || job.ValidWorkerCount > 0 {
			for _, line := range safeClientProofFragmentLines(job, startedAt, now) {
				appendLine(line.At, line.Source, line.Level, line.Message)
			}
			appendLine(now, "proxy", "ok", "verification running")
		} else {
			appendLine(now, "asic", "muted", "waiting for hash fragments")
		}
	case "succeeded":
		if activeSession == nil || activeSession.PoWJobID == nil || *activeSession.PoWJobID != job.ID {
			appendLine(now, "terminal", "muted", "closed")
			break
		}
		finishedAt := now
		if job.FinishedAt != nil {
			finishedAt = *job.FinishedAt
		}
		appendLine(finishedAt, "proxy", "ok", "sufficient")
	case "timeout":
		appendLine(terminalFinishedAt(job, now), "proxy", "error", "insufficient")
	case "canceled":
		appendLine(terminalFinishedAt(job, now), "client", "warn", "closed")
	case "failed":
		appendLine(terminalFinishedAt(job, now), "proxy", "error", "error")
	default:
		appendLine(now, "proxy", "info", "status: "+job.Status)
	}

	sort.SliceStable(lines, func(i, j int) bool {
		return lines[i].At.Before(lines[j].At)
	})
	if len(lines) > 80 {
		lines = lines[len(lines)-80:]
	}
	return lines, nil
}

func safeClientProofFragmentLines(job Job, startedAt time.Time, now time.Time) []TerminalLine {
	if startedAt.IsZero() || now.Before(startedAt) {
		return nil
	}
	const (
		cadenceSeconds = 1
		maxVisible     = 14
	)
	elapsedSlots := int(now.Sub(startedAt).Seconds()) / cadenceSeconds
	if elapsedSlots <= 0 {
		return nil
	}
	firstSlot := elapsedSlots - maxVisible + 1
	if firstSlot < 1 {
		firstSlot = 1
	}
	lines := make([]TerminalLine, 0, elapsedSlots-firstSlot+1)
	for slot := firstSlot; slot <= elapsedSlots; slot++ {
		at := startedAt.Add(time.Duration(slot*cadenceSeconds) * time.Second)
		if at.After(now) {
			continue
		}
		digest := safeClientFragmentDigest(job.ID, at)
		lines = append(lines, TerminalLine{
			At:      at,
			Source:  "asic",
			Level:   "ok",
			Message: "received hash fragment " + digest,
		})
	}
	return lines
}

func safeClientFragmentDigest(jobID string, at time.Time) string {
	sum := sha256.Sum256([]byte(jobID + ":" + at.UTC().Format(time.RFC3339)))
	encoded := hex.EncodeToString(sum[:])
	return encoded[:10] + "..." + encoded[len(encoded)-8:]
}

func (s *Service) latestJobForFolder(ctx context.Context, tenantID string, userID string, folderID string) (Job, error) {
	row := s.db.QueryRowContext(ctx, jobSelectSQL()+`
WHERE pj.tenant_id = $1
  AND pj.user_id = $2
  AND pj.protected_folder_id = $3
GROUP BY pj.id, u.username
ORDER BY pj.created_at DESC
LIMIT 1`, tenantID, userID, folderID)
	return s.scanJobWithProgress(ctx, row, tenantID)
}

func (s *Service) workerTerminalLines(ctx context.Context, tenantID string) ([]TerminalLine, error) {
	if !s.nodeLinkOK() {
		return []TerminalLine{{
			At:      time.Now().UTC(),
			Source:  "proxy",
			Level:   "warn",
			Message: "compute node link is unavailable",
		}}, nil
	}

	rows, err := s.db.QueryContext(ctx, `
SELECT worker_name, status, last_seen_at, last_error
FROM compute_workers
WHERE tenant_id = $1
  AND (status IN ('connected', 'conflict', 'blocked') OR last_seen_at >= now() - interval '10 minutes')
ORDER BY last_seen_at DESC NULLS LAST
LIMIT 4`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	lines := []TerminalLine{}
	for rows.Next() {
		var workerName string
		var status string
		var lastSeen sql.NullTime
		var lastError sql.NullString
		if err := rows.Scan(&workerName, &status, &lastSeen, &lastError); err != nil {
			return nil, err
		}
		level := "ok"
		message := "compute node connected to gateway"
		if status == "conflict" {
			level = "warn"
			message = "compute node has multiple connections"
		}
		if status == "blocked" || lastError.Valid {
			level = "error"
			message = "compute node rejected by gateway"
		}
		at := time.Now().UTC()
		if lastSeen.Valid {
			at = lastSeen.Time
		}
		lines = append(lines, TerminalLine{At: at.UTC(), Source: "proxy", Level: level, Message: message})
	}
	return lines, rows.Err()
}

func (s *Service) shareTerminalLines(ctx context.Context, tenantID string, jobID string) ([]TerminalLine, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT ps.submitted_at, coalesce(cw.worker_name, 'unknown'), ps.is_valid, ps.work_th::float8,
       coalesce(ps.rejection_reason, ''), ps.share_hash
FROM pow_shares ps
LEFT JOIN compute_workers cw ON cw.id = ps.compute_worker_id
WHERE ps.tenant_id = $1 AND ps.pow_job_id = $2
ORDER BY ps.submitted_at DESC
LIMIT 30`, tenantID, jobID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	lines := []TerminalLine{}
	for rows.Next() {
		var submittedAt time.Time
		var workerName string
		var valid bool
		var workTH float64
		var reason string
		var hash string
		if err := rows.Scan(&submittedAt, &workerName, &valid, &workTH, &reason, &hash); err != nil {
			return nil, err
		}
		level := "ok"
		_ = workerName
		_ = workTH
		_ = hash
		message := "share accepted"
		if !valid {
			level = "warn"
			_ = reason
			message = "share rejected"
		}
		lines = append(lines, TerminalLine{At: submittedAt.UTC(), Source: "asic", Level: level, Message: message})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for left, right := 0, len(lines)-1; left < right; left, right = left+1, right-1 {
		lines[left], lines[right] = lines[right], lines[left]
	}
	return lines, nil
}

func (s *Service) activeSessionForFolder(ctx context.Context, tenantID string, userID string, folderID string) (AccessSession, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT s.id::text, s.user_id::text, u.username, s.protected_folder_id::text, s.pow_job_id::text, s.status,
       s.opened_at, s.expires_at, s.closed_at, s.close_reason
FROM access_sessions s
JOIN users u ON u.id = s.user_id
WHERE s.tenant_id = $1
  AND s.user_id = $2
  AND s.protected_folder_id = $3
  AND s.status = 'active'
  AND s.expires_at > now()
LIMIT 1`, tenantID, userID, folderID)
	return scanSession(row)
}

func (s *Service) existingOpenJob(ctx context.Context, tenantID string, userID string, folderID string) (Job, error) {
	row := s.db.QueryRowContext(ctx, jobSelectSQL()+`
WHERE pj.tenant_id = $1
  AND pj.user_id = $2
  AND pj.protected_folder_id = $3
  AND pj.status IN ('queued', 'running')
GROUP BY pj.id, u.username
ORDER BY pj.created_at
LIMIT 1`, tenantID, userID, folderID)
	return s.scanJobWithProgress(ctx, row, tenantID)
}

func terminalFinishedAt(job Job, fallback time.Time) time.Time {
	if job.FinishedAt != nil {
		return *job.FinishedAt
	}
	return fallback
}

func terminalShort(value string, length int) string {
	if length <= 0 || len(value) <= length {
		return value
	}
	return value[:length]
}

func (s *Service) jobByID(ctx context.Context, tenantID string, jobID string, includeUsername bool) (Job, error) {
	_ = includeUsername
	row := s.db.QueryRowContext(ctx, jobSelectSQL()+`
WHERE pj.tenant_id = $1 AND pj.id = $2
GROUP BY pj.id, u.username`, tenantID, jobID)
	return s.scanJobWithProgress(ctx, row, tenantID)
}

func (s *Service) sessionByID(ctx context.Context, tenantID string, sessionID string, includeUsername bool) (AccessSession, error) {
	_ = includeUsername
	row := s.db.QueryRowContext(ctx, `
SELECT s.id::text, s.user_id::text, u.username, s.protected_folder_id::text, s.pow_job_id::text, s.status,
       s.opened_at, s.expires_at, s.closed_at, s.close_reason
FROM access_sessions s
JOIN users u ON u.id = s.user_id
WHERE s.tenant_id = $1 AND s.id = $2`, tenantID, sessionID)
	return scanSession(row)
}

func (s *Service) listJobs(ctx context.Context, tenantID string, userID string, includeClosed bool) ([]Job, error) {
	where := `WHERE pj.tenant_id = $1`
	args := []any{tenantID}
	if userID != "" {
		where += ` AND pj.user_id = $2`
		args = append(args, userID)
	}
	if !includeClosed {
		where += ` AND pj.status IN ('queued', 'running', 'succeeded', 'timeout', 'canceled')`
	}
	rows, err := s.db.QueryContext(ctx, jobSelectSQL()+where+`
GROUP BY pj.id, u.username
ORDER BY
  CASE pj.status WHEN 'running' THEN 0 WHEN 'queued' THEN 1 WHEN 'succeeded' THEN 2 ELSE 3 END,
  pj.created_at DESC
LIMIT 50`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	jobs := []Job{}
	for rows.Next() {
		job, err := s.scanJobWithProgress(ctx, rows, tenantID)
		if err != nil {
			return nil, err
		}
		jobs = append(jobs, job)
	}
	return jobs, rows.Err()
}

func (s *Service) listActiveSessions(ctx context.Context, tenantID string, userID string, includeUsername bool) ([]AccessSession, error) {
	_ = includeUsername
	where := `WHERE s.tenant_id = $1 AND s.status = 'active' AND s.expires_at > now()`
	args := []any{tenantID}
	if userID != "" {
		where += ` AND s.user_id = $2`
		args = append(args, userID)
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT s.id::text, s.user_id::text, u.username, s.protected_folder_id::text, s.pow_job_id::text, s.status,
       s.opened_at, s.expires_at, s.closed_at, s.close_reason
FROM access_sessions s
JOIN users u ON u.id = s.user_id
`+where+`
ORDER BY s.expires_at`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	sessions := []AccessSession{}
	for rows.Next() {
		session, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		sessions = append(sessions, session)
	}
	return sessions, rows.Err()
}

func toClientJobs(jobs []Job) []ClientJob {
	items := make([]ClientJob, 0, len(jobs))
	for _, job := range jobs {
		items = append(items, toClientJob(job))
	}
	return items
}

func toClientJob(job Job) ClientJob {
	return ClientJob{
		ID:            job.ID,
		FolderID:      job.FolderID,
		Status:        job.Status,
		QueuePosition: job.QueuePosition,
		CreatedAt:     job.CreatedAt,
		StartedAt:     job.StartedAt,
		FinishedAt:    job.FinishedAt,
	}
}

func (s *Service) scanJobWithProgress(ctx context.Context, scanner interface{ Scan(dest ...any) error }, tenantID string) (Job, error) {
	var job Job
	var observed sql.NullFloat64
	var startedAt sql.NullTime
	var finishedAt sql.NullTime
	var failureReason sql.NullString
	if err := scanner.Scan(
		&job.ID,
		&job.UserID,
		&job.Username,
		&job.FolderID,
		&job.Status,
		&job.RequiredHashrateTHs,
		&job.RequiredWorkTH,
		&observed,
		&job.MinWorkers,
		&job.HashrateTolerancePercent,
		&job.ProofWindowSeconds,
		&job.MaxProofAttempts,
		&job.TimeoutSeconds,
		&failureReason,
		&job.CreatedAt,
		&startedAt,
		&finishedAt,
		&job.QueuePosition,
	); err != nil {
		return Job{}, err
	}
	if observed.Valid {
		job.ObservedHashrateTHs = &observed.Float64
	}
	if startedAt.Valid {
		job.StartedAt = &startedAt.Time
		job.ProofWindowSeconds = normalizePositiveInt(job.ProofWindowSeconds, defaultProofWindowSeconds)
		job.MaxProofAttempts = normalizePositiveInt(job.MaxProofAttempts, defaultMaxProofAttempts)
		validWork, workerCount, _, err := s.bestAttemptProgress(ctx, tenantID, job.ID, startedAt.Time, job.ProofWindowSeconds, job.MaxProofAttempts)
		if err == nil {
			job.ValidWorkTH = validWork
			job.ValidWorkerCount = workerCount
		}
	}
	job.ProofWindowSeconds = normalizePositiveInt(job.ProofWindowSeconds, defaultProofWindowSeconds)
	job.MaxProofAttempts = normalizePositiveInt(job.MaxProofAttempts, defaultMaxProofAttempts)
	if finishedAt.Valid {
		job.FinishedAt = &finishedAt.Time
	}
	if failureReason.Valid {
		job.FailureReason = failureReason.String
	}
	return job, nil
}

func scanSession(scanner interface{ Scan(dest ...any) error }) (AccessSession, error) {
	var session AccessSession
	var powJobID sql.NullString
	var closedAt sql.NullTime
	var closeReason sql.NullString
	if err := scanner.Scan(
		&session.ID,
		&session.UserID,
		&session.Username,
		&session.FolderID,
		&powJobID,
		&session.Status,
		&session.OpenedAt,
		&session.ExpiresAt,
		&closedAt,
		&closeReason,
	); err != nil {
		return AccessSession{}, err
	}
	if powJobID.Valid {
		session.PoWJobID = &powJobID.String
	}
	if closedAt.Valid {
		session.ClosedAt = &closedAt.Time
	}
	if closeReason.Valid {
		session.CloseReason = closeReason.String
	}
	return session, nil
}

func jobSelectSQL() string {
	return `
SELECT
  pj.id::text,
  pj.user_id::text,
  u.username,
  pj.protected_folder_id::text,
  pj.status,
  pj.required_hashrate_ths::float8,
  pj.required_work_th::float8,
  pj.observed_hashrate_ths::float8,
  pj.min_workers,
  pj.hashrate_tolerance_percent::float8,
  pj.proof_window_seconds,
  pj.max_proof_attempts,
  pj.timeout_seconds,
  pj.failure_reason,
  pj.created_at,
  pj.started_at,
  pj.finished_at,
  CASE WHEN pj.status = 'queued'
    THEN count(*) FILTER (WHERE q.status = 'queued' AND q.created_at <= pj.created_at)::int
    ELSE 0
  END AS queue_position
FROM pow_jobs pj
JOIN users u ON u.id = pj.user_id
LEFT JOIN pow_jobs q ON q.tenant_id = pj.tenant_id
`
}

func (s *Service) loadPolicy(ctx context.Context) (Policy, error) {
	var raw []byte
	if err := s.db.QueryRowContext(ctx, `SELECT value FROM system_settings WHERE key = $1`, powPolicyKey).Scan(&raw); err != nil {
		return Policy{}, err
	}
	var policy Policy
	if err := json.Unmarshal(raw, &policy); err != nil {
		return Policy{}, err
	}
	return normalizePolicy(policy), nil
}

func (s *Service) loadFolderPolicy(ctx context.Context, tenantID string, folderID string) (Policy, error) {
	policy, err := s.loadPolicy(ctx)
	if err != nil {
		return Policy{}, err
	}
	var policySeal sql.NullString
	err = s.db.QueryRowContext(ctx, `
	SELECT
	  pow_required_hashrate_ths::float8,
	  pow_hashrate_tolerance_percent::float8,
	  pow_proof_window_seconds,
	  pow_max_proof_attempts,
	  pow_policy_seal
	FROM protected_folders
	WHERE tenant_id = $1 AND id = $2 AND status = 'active'`, tenantID, folderID).Scan(
		&policy.RequiredHashrateTHs,
		&policy.HashrateTolerancePercent,
		&policy.ProofWindowSeconds,
		&policy.MaxProofAttempts,
		&policySeal,
	)
	if err != nil {
		return Policy{}, err
	}
	policy = normalizePolicy(policy)
	if err := s.ensureFolderPoWPolicySeal(ctx, tenantID, folderID, policy, policySeal); err != nil {
		return Policy{}, err
	}
	return policy, nil
}

func normalizePolicy(policy Policy) Policy {
	if policy.RequiredHashrateTHs <= 0 {
		policy.RequiredHashrateTHs = 1
	}
	policy.MinWorkers = 1
	if policy.ProofWindowSeconds <= 0 {
		policy.ProofWindowSeconds = defaultProofWindowSeconds
	}
	if policy.MaxProofAttempts <= 0 {
		policy.MaxProofAttempts = defaultMaxProofAttempts
	}
	if policy.JobTimeoutMinutes <= 0 {
		policy.JobTimeoutMinutes = 15
	}
	if policy.SessionTTLMinutes <= 0 {
		policy.SessionTTLMinutes = 30
	}
	if len(policy.AllowedSessionTTLMinutes) == 0 {
		policy.AllowedSessionTTLMinutes = []int{10, 15, 30, 60}
	}
	policy.SingleActiveSession = true
	policy.HeartbeatEnabled = false
	policy.UploadPoWRequired = false
	return policy
}

func validatePolicy(policy Policy) error {
	switch {
	case policy.RequiredHashrateTHs <= 0:
		return errors.New("required_hashrate_invalid")
	case policy.HashrateTolerancePercent < 0 || policy.HashrateTolerancePercent > 50:
		return errors.New("hashrate_tolerance_invalid")
	case policy.ProofWindowSeconds < 5 || policy.ProofWindowSeconds > 600:
		return errors.New("proof_window_invalid")
	case policy.MaxProofAttempts < 1 || policy.MaxProofAttempts > 10:
		return errors.New("max_proof_attempts_invalid")
	case policy.JobTimeoutMinutes != 5 && policy.JobTimeoutMinutes != 10 && policy.JobTimeoutMinutes != 15 && policy.JobTimeoutMinutes != 30:
		return errors.New("job_timeout_invalid")
	case policy.SessionTTLMinutes != 10 && policy.SessionTTLMinutes != 15 && policy.SessionTTLMinutes != 30 && policy.SessionTTLMinutes != 60:
		return errors.New("session_ttl_invalid")
	default:
		return nil
	}
}

func (s *Service) ensureFolderPoWPolicySeal(ctx context.Context, tenantID string, folderID string, policy Policy, storedSeal sql.NullString) error {
	if s.kms == nil {
		return errors.New("kms_not_configured")
	}
	expectedSeal, err := s.kms.Seal(ctx, policyseal.FolderPoWPurpose, policyseal.FolderPoWPolicyPayload(tenantID, folderID, policyseal.FolderPoWPolicy{
		RequiredHashrateTHs:      policy.RequiredHashrateTHs,
		HashrateTolerancePercent: policy.HashrateTolerancePercent,
		ProofWindowSeconds:       policy.ProofWindowSeconds,
		MaxProofAttempts:         policy.MaxProofAttempts,
	}))
	if err != nil {
		return err
	}

	seal := strings.TrimSpace(storedSeal.String)
	if !storedSeal.Valid || seal == "" {
		_, err := s.db.ExecContext(ctx, `
UPDATE protected_folders
SET pow_policy_seal = $1
WHERE tenant_id = $2
  AND id = $3
  AND status = 'active'
  AND (pow_policy_seal IS NULL OR pow_policy_seal = '')`, expectedSeal, tenantID, folderID)
		return err
	}
	if seal != expectedSeal {
		return errors.New("folder_pow_policy_seal_mismatch")
	}
	return nil
}

func requiredWorkTH(policy Policy) float64 {
	return acceptedHashrateTHs(policy) * float64(policy.ProofWindowSeconds)
}

func acceptedHashrateTHs(policy Policy) float64 {
	tolerance := policy.HashrateTolerancePercent
	if tolerance < 0 {
		tolerance = 0
	}
	if tolerance > 90 {
		tolerance = 90
	}
	return policy.RequiredHashrateTHs * (1 - tolerance/100)
}

func normalizePositiveInt(value int, fallback int) int {
	if value > 0 {
		return value
	}
	return fallback
}

func newDAVPassword() (string, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return "Dav1-" + base64.RawURLEncoding.EncodeToString(raw), nil
}

func davPasswordAAD(tenantID string, sessionID string) []byte {
	return []byte("archivon:metadata:v1:dav-password:" + tenantID + ":" + sessionID)
}

func davURLFromRequest(r *http.Request, username string) string {
	scheme := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto"))
	if scheme == "" {
		scheme = "http"
		if r.TLS != nil {
			scheme = "https"
		}
	}
	host := strings.TrimSpace(r.Header.Get("X-Forwarded-Host"))
	if host == "" {
		host = strings.TrimSpace(r.Host)
	}
	if host == "" {
		host = "localhost"
	}
	prefix := forwardedPrefix(r)
	return scheme + "://" + host + prefix + "/dav/" + url.PathEscape(username) + "/"
}

func forwardedPrefix(r *http.Request) string {
	prefix := strings.TrimRight(strings.TrimSpace(r.Header.Get("X-Forwarded-Prefix")), "/")
	if prefix == "" || prefix == "/" {
		return ""
	}
	if !strings.HasPrefix(prefix, "/") {
		prefix = "/" + prefix
	}
	return prefix
}

type accessError struct {
	code int
	key  string
}

func (e accessError) Error() string {
	return e.key
}

func (s *Service) writeAccessError(w http.ResponseWriter, err error) {
	var typed accessError
	if errors.As(err, &typed) {
		writeError(w, typed.code, typed.key)
		return
	}
	if s.logger != nil {
		s.logger.Warn("access request failed", "error", err)
	}
	writeError(w, http.StatusInternalServerError, "access_failed")
}

func (s *Service) insertAuditEvent(ctx context.Context, tenantID string, actorUserID string, eventType string, targetType string, targetID *string, severity string, ipAddress string, details map[string]any) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		_ = tx.Rollback()
	}()
	if err := insertAuditEventTx(ctx, tx, tenantID, actorUserID, eventType, targetType, targetID, severity, ipAddress, details); err != nil {
		return err
	}
	return tx.Commit()
}

func insertAuditEventTx(ctx context.Context, tx *sql.Tx, tenantID string, actorUserID string, eventType string, targetType string, targetID *string, severity string, ipAddress string, details map[string]any) error {
	rawDetails, err := json.Marshal(details)
	if err != nil {
		rawDetails = []byte(`{}`)
	}
	var actor any
	if actorUserID != "" {
		actor = actorUserID
	}
	var target any
	if targetID != nil && *targetID != "" {
		target = *targetID
	}
	_, err = tx.ExecContext(ctx, `
INSERT INTO audit_events (tenant_id, actor_user_id, event_type, target_type, target_id, severity, ip_address, details)
VALUES ($1, $2, $3, nullif($4, ''), $5, $6, nullif($7, ''), $8::jsonb)`,
		tenantID, actor, eventType, targetType, target, severity, ipAddress, string(rawDetails),
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
	_ = json.NewEncoder(w).Encode(payload)
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
		if idx := strings.Index(forwarded, ","); idx >= 0 {
			return strings.TrimSpace(forwarded[:idx])
		}
		return forwarded
	}
	return strings.TrimSpace(r.RemoteAddr)
}

func isUUIDLike(value string) bool {
	if len(value) != 36 {
		return false
	}
	for i, char := range value {
		switch i {
		case 8, 13, 18, 23:
			if char != '-' {
				return false
			}
		default:
			if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f') || (char >= 'A' && char <= 'F')) {
				return false
			}
		}
	}
	return true
}
