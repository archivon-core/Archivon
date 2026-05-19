package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	SessionCookieName    = "archivon_session"
	minPasswordLength    = 10
	authSessionPolicyKey = "auth_single_active_session"
)

var allowedAuthSessionTTLHours = []int{1, 4, 8, 12, 24, 72, 168}

type Service struct {
	db           *sql.DB
	logger       *slog.Logger
	sessionTTL   time.Duration
	cookieSecure bool
}

type Options struct {
	SessionTTL   time.Duration
	CookieSecure bool
}

type User struct {
	ID                 string     `json:"id"`
	TenantID           string     `json:"tenant_id"`
	Role               string     `json:"role"`
	Username           string     `json:"username"`
	MustChangePassword bool       `json:"must_change_password"`
	IsBlocked          bool       `json:"is_blocked"`
	Description        *string    `json:"description,omitempty"`
	CreatedAt          time.Time  `json:"created_at"`
	LastLoginAt        *time.Time `json:"last_login_at,omitempty"`
}

type bootstrapStatusResponse struct {
	Required        bool   `json:"required"`
	SuperAdminCount int    `json:"super_admin_count"`
	DefaultTenantID string `json:"default_tenant_id,omitempty"`
	MinPasswordLen  int    `json:"min_password_length"`
}

type createSuperAdminRequest struct {
	Username    string `json:"username"`
	Password    string `json:"password"`
	Description string `json:"description"`
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type authResponse struct {
	User      User       `json:"user"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

type authSessionPolicy struct {
	Enabled             bool   `json:"enabled"`
	ClientMode          string `json:"client_mode"`
	AdminMode           string `json:"admin_mode"`
	SuperAdminMode      string `json:"super_admin_mode"`
	AuthTTLHours        int    `json:"auth_ttl_hours"`
	AllowedAuthTTLHours []int  `json:"allowed_auth_ttl_hours"`
}

type authSettingsResponse struct {
	Policy             authSessionPolicy `json:"policy"`
	UpdateRoleRequired string            `json:"update_role_required"`
}

type updateAuthSettingsRequest struct {
	AuthTTLHours int `json:"auth_ttl_hours"`
}

type usersResponse struct {
	Users []User `json:"users"`
}

type createUserRequest struct {
	Username    string `json:"username"`
	Role        string `json:"role"`
	Description string `json:"description"`
}

type createUserResponse struct {
	User              User   `json:"user"`
	TemporaryPassword string `json:"temporary_password"`
}

type changePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

type updateUserStatusRequest struct {
	Blocked bool `json:"blocked"`
}

type resetPasswordResponse struct {
	User              User   `json:"user"`
	TemporaryPassword string `json:"temporary_password"`
}

type deleteUserResponse struct {
	DeletedUserID   string `json:"deleted_user_id"`
	Username        string `json:"username"`
	Role            string `json:"role"`
	RevokedSessions int64  `json:"revoked_sessions"`
	CanceledJobs    int64  `json:"canceled_jobs"`
	DeletedPoWJobs  int64  `json:"deleted_pow_jobs"`
	DeletedRights   int64  `json:"deleted_rights"`
}

func NewService(db *sql.DB, logger *slog.Logger, opts Options) *Service {
	if opts.SessionTTL <= 0 {
		opts.SessionTTL = 12 * time.Hour
	}
	return &Service{
		db:           db,
		logger:       logger,
		sessionTTL:   opts.SessionTTL,
		cookieSecure: opts.CookieSecure,
	}
}

func (s *Service) Register(mux *http.ServeMux) {
	mux.HandleFunc("/api/bootstrap/status", s.handleBootstrapStatus)
	mux.HandleFunc("/api/bootstrap/super-admin", s.handleCreateSuperAdmin)
	mux.HandleFunc("/api/auth/login", s.handleLogin)
	mux.HandleFunc("/api/auth/logout", s.handleLogout)
	mux.HandleFunc("/api/auth/me", s.handleMe)
	mux.HandleFunc("/api/auth/change-password", s.handleChangePassword)
	mux.Handle("/api/admin/auth/settings", s.RequireRole(http.HandlerFunc(s.handleAuthSettings), "super_admin", "admin"))
	mux.Handle("/api/admin/users", s.RequireRole(http.HandlerFunc(s.handleUsersCollection), "super_admin", "admin"))
	mux.Handle("/api/admin/users/", s.RequireRole(http.HandlerFunc(s.handleUserAction), "super_admin", "admin"))
}

func (s *Service) BootstrapState(ctx context.Context) string {
	count, _, err := s.bootstrapState(ctx)
	if err != nil {
		return "error"
	}
	if count == 0 {
		return "required"
	}
	return "complete"
}

func (s *Service) handleBootstrapStatus(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	count, tenantID, err := s.bootstrapState(r.Context())
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "bootstrap_status_failed")
		return
	}
	writeJSON(w, http.StatusOK, bootstrapStatusResponse{
		Required:        count == 0,
		SuperAdminCount: count,
		DefaultTenantID: tenantID,
		MinPasswordLen:  minPasswordLength,
	})
}

func (s *Service) handleCreateSuperAdmin(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	var req createSuperAdminRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	username := strings.TrimSpace(req.Username)
	password := strings.TrimSpace(req.Password)
	if username == "" {
		s.writeError(w, http.StatusBadRequest, "username_required")
		return
	}
	if len(password) < minPasswordLength {
		s.writeError(w, http.StatusBadRequest, "password_too_short")
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "password_hash_failed")
		return
	}

	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "transaction_failed")
		return
	}
	defer func() {
		_ = tx.Rollback()
	}()

	if _, err := tx.ExecContext(r.Context(), `SELECT pg_advisory_xact_lock(110011101)`); err != nil {
		s.writeError(w, http.StatusInternalServerError, "bootstrap_lock_failed")
		return
	}

	tenantID, err := defaultTenantIDTx(r.Context(), tx)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "tenant_not_found")
		return
	}

	var count int
	if err := tx.QueryRowContext(r.Context(), `SELECT count(*) FROM users WHERE tenant_id = $1 AND role = 'super_admin'`, tenantID).Scan(&count); err != nil {
		s.writeError(w, http.StatusInternalServerError, "super_admin_check_failed")
		return
	}
	if count > 0 {
		s.writeError(w, http.StatusConflict, "bootstrap_already_completed")
		return
	}

	user, err := insertUserTx(r.Context(), tx, tenantID, "super_admin", username, string(hash), false, nullableString(req.Description))
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "super_admin_create_failed")
		return
	}

	if err := insertAuditEventTx(r.Context(), tx, tenantID, &user.ID, "auth.bootstrap.super_admin_created", "user", &user.ID, "info", clientIP(r), map[string]any{"username": user.Username}); err != nil {
		s.writeError(w, http.StatusInternalServerError, "audit_failed")
		return
	}

	if err := tx.Commit(); err != nil {
		s.writeError(w, http.StatusInternalServerError, "transaction_commit_failed")
		return
	}

	writeJSON(w, http.StatusCreated, authResponse{User: user})
}

func (s *Service) handleLogin(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	var req loginRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	user, passwordHash, err := s.findLoginUser(r.Context(), req.Username)
	if err != nil {
		_ = s.insertAuditEvent(r.Context(), "", nil, "auth.login.failed", "", nil, "warning", clientIP(r), map[string]any{"reason": "invalid_credentials"})
		s.writeError(w, http.StatusUnauthorized, "invalid_credentials")
		return
	}
	if user.IsBlocked {
		_ = s.insertAuditEvent(r.Context(), user.TenantID, &user.ID, "auth.login.failed", "user", &user.ID, "warning", clientIP(r), map[string]any{"reason": "blocked"})
		s.writeError(w, http.StatusForbidden, "user_blocked")
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(req.Password)) != nil {
		_ = s.insertAuditEvent(r.Context(), user.TenantID, &user.ID, "auth.login.failed", "user", &user.ID, "warning", clientIP(r), map[string]any{"reason": "invalid_credentials"})
		s.writeError(w, http.StatusUnauthorized, "invalid_credentials")
		return
	}

	token, tokenHash, err := newSessionToken()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "session_token_failed")
		return
	}
	sessionTTL, err := s.currentAuthSessionTTL(r.Context())
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "auth_policy_load_failed")
		return
	}
	expiresAt := time.Now().UTC().Add(sessionTTL)

	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "transaction_failed")
		return
	}
	defer func() {
		_ = tx.Rollback()
	}()

	var lockedUser int
	if err := tx.QueryRowContext(r.Context(), `
SELECT 1
FROM users
WHERE tenant_id = $1 AND id = $2
FOR UPDATE`, user.TenantID, user.ID).Scan(&lockedUser); err != nil {
		s.writeError(w, http.StatusInternalServerError, "user_lock_failed")
		return
	}
	if _, err := tx.ExecContext(r.Context(), `
UPDATE user_sessions
SET status = 'expired'
WHERE tenant_id = $1
  AND user_id = $2
  AND status = 'active'
  AND expires_at <= now()`, user.TenantID, user.ID); err != nil {
		s.writeError(w, http.StatusInternalServerError, "session_expire_failed")
		return
	}

	var existingSessionID string
	var existingExpiresAt time.Time
	var existingIP sql.NullString
	err = tx.QueryRowContext(r.Context(), `
SELECT id::text, expires_at, ip_address
FROM user_sessions
WHERE tenant_id = $1
  AND user_id = $2
  AND status = 'active'
  AND expires_at > now()
ORDER BY created_at DESC
LIMIT 1`, user.TenantID, user.ID).Scan(&existingSessionID, &existingExpiresAt, &existingIP)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		s.writeError(w, http.StatusInternalServerError, "session_check_failed")
		return
	}
	if err == nil {
		if user.Role == "client" {
			result, err := tx.ExecContext(r.Context(), `
UPDATE user_sessions
SET status = 'revoked',
    revoked_at = now()
WHERE tenant_id = $1
  AND user_id = $2
  AND status = 'active'
  AND expires_at > now()`, user.TenantID, user.ID)
			if err != nil {
				s.writeError(w, http.StatusInternalServerError, "session_revoke_failed")
				return
			}
			revokedSessions, _ := result.RowsAffected()
			if err := insertAuditEventTx(r.Context(), tx, user.TenantID, &user.ID, "auth.login.previous_session_revoked", "user", &user.ID, "warning", clientIP(r), map[string]any{
				"username":             user.Username,
				"revoked_sessions":     revokedSessions,
				"previous_session_id":  existingSessionID,
				"previous_ip":          existingIP.String,
				"previous_expires_at":  existingExpiresAt.UTC().Format(time.RFC3339),
				"replacement_behavior": "latest_login_wins",
			}); err != nil {
				s.writeError(w, http.StatusInternalServerError, "audit_failed")
				return
			}
		}
	}

	if _, err := tx.ExecContext(r.Context(), `
		INSERT INTO user_sessions (tenant_id, user_id, token_hash, status, ip_address, user_agent, expires_at, role_at_login)
		VALUES ($1, $2, $3, 'active', $4, $5, $6, $7)`,
		user.TenantID, user.ID, tokenHash, clientIP(r), r.UserAgent(), expiresAt, user.Role,
	); err != nil {
		if isUniqueViolation(err) {
			s.writeError(w, http.StatusConflict, "user_session_already_active")
			return
		}
		s.writeError(w, http.StatusInternalServerError, "session_create_failed")
		return
	}
	if _, err := tx.ExecContext(r.Context(), `UPDATE users SET last_login_at = now(), updated_at = now() WHERE id = $1`, user.ID); err != nil {
		s.writeError(w, http.StatusInternalServerError, "last_login_update_failed")
		return
	}
	loginDetails := map[string]any{"username": user.Username, "role": user.Role}
	if err == nil && user.Role != "client" {
		loginDetails["parallel_session"] = true
		loginDetails["existing_session_id"] = existingSessionID
		loginDetails["existing_ip"] = existingIP.String
		loginDetails["existing_expires_at"] = existingExpiresAt.UTC().Format(time.RFC3339)
	}
	if err := insertAuditEventTx(r.Context(), tx, user.TenantID, &user.ID, "auth.login.succeeded", "user", &user.ID, "info", clientIP(r), loginDetails); err != nil {
		s.writeError(w, http.StatusInternalServerError, "audit_failed")
		return
	}
	if err := tx.Commit(); err != nil {
		s.writeError(w, http.StatusInternalServerError, "transaction_commit_failed")
		return
	}

	setSessionCookie(w, token, expiresAt, s.cookieSecure)
	writeJSON(w, http.StatusOK, authResponse{User: user, ExpiresAt: &expiresAt})
}

func (s *Service) handleLogout(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	token, ok := sessionTokenFromRequest(r)
	if ok {
		tokenHash := hashToken(token)
		user, err := s.userBySessionHash(r.Context(), tokenHash)
		if err == nil {
			_, _ = s.db.ExecContext(r.Context(), `UPDATE user_sessions SET status = 'revoked', revoked_at = now() WHERE token_hash = $1 AND status = 'active'`, tokenHash)
			_ = s.insertAuditEvent(r.Context(), user.TenantID, &user.ID, "auth.logout", "user", &user.ID, "info", clientIP(r), map[string]any{"username": user.Username})
		}
	}
	clearSessionCookie(w, s.cookieSecure)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Service) handleMe(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	user, err := s.CurrentUser(r)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, "not_authenticated")
		return
	}
	writeJSON(w, http.StatusOK, authResponse{User: user})
}

func (s *Service) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	user, err := s.CurrentUser(r)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, "not_authenticated")
		return
	}

	var req changePasswordRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.CurrentPassword == "" {
		s.writeError(w, http.StatusBadRequest, "current_password_required")
		return
	}
	if len(req.NewPassword) < minPasswordLength {
		s.writeError(w, http.StatusBadRequest, "password_too_short")
		return
	}

	passwordHash, err := s.passwordHashForUser(r.Context(), user.ID)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "password_check_failed")
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(req.CurrentPassword)) != nil {
		_ = s.insertAuditEvent(r.Context(), user.TenantID, &user.ID, "auth.password.change_failed", "user", &user.ID, "warning", clientIP(r), map[string]any{"reason": "invalid_current_password"})
		s.writeError(w, http.StatusForbidden, "invalid_current_password")
		return
	}

	newHash, err := hashPassword(req.NewPassword)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "password_hash_failed")
		return
	}

	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "transaction_failed")
		return
	}
	defer func() {
		_ = tx.Rollback()
	}()

	if _, err := tx.ExecContext(r.Context(), `
UPDATE users
SET password_hash = $1, must_change_password = false, updated_at = now()
WHERE id = $2`, newHash, user.ID); err != nil {
		s.writeError(w, http.StatusInternalServerError, "password_update_failed")
		return
	}
	if err := insertAuditEventTx(r.Context(), tx, user.TenantID, &user.ID, "auth.password.changed", "user", &user.ID, "info", clientIP(r), map[string]any{"username": user.Username}); err != nil {
		s.writeError(w, http.StatusInternalServerError, "audit_failed")
		return
	}
	if err := tx.Commit(); err != nil {
		s.writeError(w, http.StatusInternalServerError, "transaction_commit_failed")
		return
	}

	updated, err := s.userByID(r.Context(), user.ID)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "user_reload_failed")
		return
	}
	writeJSON(w, http.StatusOK, authResponse{User: updated})
}

func (s *Service) handleAuthSettings(w http.ResponseWriter, r *http.Request) {
	user, err := s.CurrentUser(r)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, "not_authenticated")
		return
	}
	switch r.Method {
	case http.MethodGet:
		policy, err := s.loadAuthSessionPolicy(r.Context())
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "auth_policy_load_failed")
			return
		}
		writeJSON(w, http.StatusOK, authSettingsResponse{Policy: policy, UpdateRoleRequired: "super_admin"})
	case http.MethodPost:
		if user.Role != "super_admin" {
			s.writeError(w, http.StatusForbidden, "super_admin_required")
			return
		}
		var req updateAuthSettingsRequest
		if !decodeJSON(w, r, &req) {
			return
		}
		policy, err := s.loadAuthSessionPolicy(r.Context())
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "auth_policy_load_failed")
			return
		}
		if !isAllowedAuthSessionTTL(req.AuthTTLHours) {
			s.writeError(w, http.StatusBadRequest, "auth_ttl_invalid")
			return
		}
		policy.AuthTTLHours = req.AuthTTLHours
		policy = s.normalizeAuthSessionPolicy(policy)
		raw, err := json.Marshal(policy)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "auth_policy_encode_failed")
			return
		}
		if _, err := s.db.ExecContext(r.Context(), `
INSERT INTO system_settings (key, value, updated_by, updated_at)
VALUES ($1, $2::jsonb, $3, now())
ON CONFLICT (key) DO UPDATE
SET value = EXCLUDED.value,
    updated_by = EXCLUDED.updated_by,
    updated_at = now()`, authSessionPolicyKey, string(raw), user.ID); err != nil {
			s.writeError(w, http.StatusInternalServerError, "auth_policy_update_failed")
			return
		}
		if err := s.insertAuditEvent(r.Context(), user.TenantID, &user.ID, "auth.session_policy.updated", "system_setting", nil, "warning", clientIP(r), map[string]any{
			"auth_ttl_hours": policy.AuthTTLHours,
			"client_mode":    policy.ClientMode,
			"admin_mode":     policy.AdminMode,
		}); err != nil {
			s.writeError(w, http.StatusInternalServerError, "audit_failed")
			return
		}
		writeJSON(w, http.StatusOK, authSettingsResponse{Policy: policy, UpdateRoleRequired: "super_admin"})
	default:
		writeMethodNotAllowed(w, "GET, POST")
	}
}

func (s *Service) handleUsersCollection(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleListUsers(w, r)
	case http.MethodPost:
		s.handleCreateUser(w, r)
	default:
		writeMethodNotAllowed(w, "GET, POST")
	}
}

func (s *Service) handleListUsers(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	rows, err := s.db.QueryContext(r.Context(), `
SELECT id::text, tenant_id::text, role, username, must_change_password, is_blocked, description, created_at, last_login_at
FROM users
ORDER BY created_at ASC`)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "users_query_failed")
		return
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		user, err := scanUser(rows)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "users_scan_failed")
			return
		}
		users = append(users, user)
	}
	if err := rows.Err(); err != nil {
		s.writeError(w, http.StatusInternalServerError, "users_rows_failed")
		return
	}
	writeJSON(w, http.StatusOK, usersResponse{Users: users})
}

func (s *Service) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	actor, err := s.CurrentUser(r)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, "not_authenticated")
		return
	}

	var req createUserRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	username := strings.TrimSpace(req.Username)
	role := strings.TrimSpace(req.Role)
	if username == "" {
		s.writeError(w, http.StatusBadRequest, "username_required")
		return
	}
	if !canCreateRole(actor.Role, role) {
		s.writeError(w, http.StatusForbidden, "role_not_allowed")
		return
	}

	temporaryPassword, err := newTemporaryPassword()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "temporary_password_failed")
		return
	}
	passwordHash, err := hashPassword(temporaryPassword)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "password_hash_failed")
		return
	}

	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "transaction_failed")
		return
	}
	defer func() {
		_ = tx.Rollback()
	}()

	tenantID, err := defaultTenantIDTx(r.Context(), tx)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "tenant_not_found")
		return
	}
	user, err := insertUserTx(r.Context(), tx, tenantID, role, username, passwordHash, true, nullableString(req.Description))
	if err != nil {
		if isUniqueViolation(err) {
			s.writeError(w, http.StatusConflict, "username_already_exists")
			return
		}
		s.writeError(w, http.StatusInternalServerError, "user_create_failed")
		return
	}
	if err := insertAuditEventTx(r.Context(), tx, tenantID, &actor.ID, "auth.user.created", "user", &user.ID, "info", clientIP(r), map[string]any{"username": user.Username, "role": user.Role}); err != nil {
		s.writeError(w, http.StatusInternalServerError, "audit_failed")
		return
	}
	if err := tx.Commit(); err != nil {
		s.writeError(w, http.StatusInternalServerError, "transaction_commit_failed")
		return
	}

	writeJSON(w, http.StatusCreated, createUserResponse{User: user, TemporaryPassword: temporaryPassword})
}

func (s *Service) handleUserAction(w http.ResponseWriter, r *http.Request) {
	path := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/admin/users/"), "/")
	parts := strings.Split(path, "/")
	if len(parts) == 1 && parts[0] != "" {
		if r.Method != http.MethodDelete {
			writeMethodNotAllowed(w, "DELETE")
			return
		}
		s.handleDeleteUser(w, r, parts[0])
		return
	}
	if r.Method != http.MethodPatch {
		writeMethodNotAllowed(w, "PATCH, DELETE")
		return
	}
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		s.writeError(w, http.StatusNotFound, "not_found")
		return
	}
	switch parts[1] {
	case "password":
		s.handleResetUserPassword(w, r, parts[0])
	case "status":
		s.handleUpdateUserStatus(w, r, parts[0])
	default:
		s.writeError(w, http.StatusNotFound, "not_found")
	}
}

func (s *Service) handleResetUserPassword(w http.ResponseWriter, r *http.Request, targetUserID string) {
	actor, err := s.CurrentUser(r)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, "not_authenticated")
		return
	}
	target, err := s.userByID(r.Context(), targetUserID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			s.writeError(w, http.StatusNotFound, "user_not_found")
			return
		}
		s.writeError(w, http.StatusInternalServerError, "user_lookup_failed")
		return
	}
	if !canManageUser(actor, target) {
		s.writeError(w, http.StatusForbidden, "target_not_allowed")
		return
	}

	temporaryPassword, err := newTemporaryPassword()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "temporary_password_failed")
		return
	}
	passwordHash, err := hashPassword(temporaryPassword)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "password_hash_failed")
		return
	}

	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "transaction_failed")
		return
	}
	defer func() {
		_ = tx.Rollback()
	}()

	if _, err := tx.ExecContext(r.Context(), `
UPDATE users
SET password_hash = $1, must_change_password = true, updated_at = now()
WHERE id = $2`, passwordHash, target.ID); err != nil {
		s.writeError(w, http.StatusInternalServerError, "password_reset_failed")
		return
	}
	if err := revokeUserSessionsTx(r.Context(), tx, target.ID); err != nil {
		s.writeError(w, http.StatusInternalServerError, "session_revoke_failed")
		return
	}
	if err := insertAuditEventTx(r.Context(), tx, target.TenantID, &actor.ID, "auth.user.password_reset", "user", &target.ID, "warning", clientIP(r), map[string]any{"username": target.Username, "role": target.Role}); err != nil {
		s.writeError(w, http.StatusInternalServerError, "audit_failed")
		return
	}
	if err := tx.Commit(); err != nil {
		s.writeError(w, http.StatusInternalServerError, "transaction_commit_failed")
		return
	}

	updated, err := s.userByID(r.Context(), target.ID)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "user_reload_failed")
		return
	}
	writeJSON(w, http.StatusOK, resetPasswordResponse{User: updated, TemporaryPassword: temporaryPassword})
}

func (s *Service) handleUpdateUserStatus(w http.ResponseWriter, r *http.Request, targetUserID string) {
	actor, err := s.CurrentUser(r)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, "not_authenticated")
		return
	}
	var req updateUserStatusRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	target, err := s.userByID(r.Context(), targetUserID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			s.writeError(w, http.StatusNotFound, "user_not_found")
			return
		}
		s.writeError(w, http.StatusInternalServerError, "user_lookup_failed")
		return
	}
	if !canManageUser(actor, target) {
		s.writeError(w, http.StatusForbidden, "target_not_allowed")
		return
	}

	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "transaction_failed")
		return
	}
	defer func() {
		_ = tx.Rollback()
	}()

	if _, err := tx.ExecContext(r.Context(), `
UPDATE users
SET is_blocked = $1, updated_at = now()
WHERE id = $2`, req.Blocked, target.ID); err != nil {
		s.writeError(w, http.StatusInternalServerError, "user_status_update_failed")
		return
	}
	if req.Blocked {
		if err := revokeUserSessionsTx(r.Context(), tx, target.ID); err != nil {
			s.writeError(w, http.StatusInternalServerError, "session_revoke_failed")
			return
		}
	}
	eventType := "auth.user.unblocked"
	severity := "info"
	if req.Blocked {
		eventType = "auth.user.blocked"
		severity = "warning"
	}
	if err := insertAuditEventTx(r.Context(), tx, target.TenantID, &actor.ID, eventType, "user", &target.ID, severity, clientIP(r), map[string]any{"username": target.Username, "role": target.Role}); err != nil {
		s.writeError(w, http.StatusInternalServerError, "audit_failed")
		return
	}
	if err := tx.Commit(); err != nil {
		s.writeError(w, http.StatusInternalServerError, "transaction_commit_failed")
		return
	}

	updated, err := s.userByID(r.Context(), target.ID)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "user_reload_failed")
		return
	}
	writeJSON(w, http.StatusOK, authResponse{User: updated})
}

func (s *Service) handleDeleteUser(w http.ResponseWriter, r *http.Request, targetUserID string) {
	actor, err := s.CurrentUser(r)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, "not_authenticated")
		return
	}
	if !isUUIDLike(targetUserID) {
		s.writeError(w, http.StatusNotFound, "user_not_found")
		return
	}
	target, err := s.userByID(r.Context(), targetUserID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			s.writeError(w, http.StatusNotFound, "user_not_found")
			return
		}
		s.writeError(w, http.StatusInternalServerError, "user_lookup_failed")
		return
	}
	if !canManageUser(actor, target) {
		s.writeError(w, http.StatusForbidden, "target_not_allowed")
		return
	}

	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "transaction_failed")
		return
	}
	defer func() {
		_ = tx.Rollback()
	}()

	sessionResult, err := tx.ExecContext(r.Context(), `
UPDATE access_sessions
SET status = 'revoked',
    closed_at = now(),
    close_reason = 'user_deleted'
WHERE tenant_id = $1
  AND user_id = $2
  AND status = 'active'`, target.TenantID, target.ID)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "access_session_revoke_failed")
		return
	}
	revokedSessions, _ := sessionResult.RowsAffected()

	jobResult, err := tx.ExecContext(r.Context(), `
UPDATE pow_jobs
SET status = 'canceled',
    finished_at = now(),
    failure_reason = 'user_deleted'
WHERE tenant_id = $1
  AND user_id = $2
  AND status IN ('queued', 'running')`, target.TenantID, target.ID)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "pow_job_cancel_failed")
		return
	}
	canceledJobs, _ := jobResult.RowsAffected()

	rightsResult, err := tx.ExecContext(r.Context(), `DELETE FROM folder_permissions WHERE tenant_id = $1 AND user_id = $2`, target.TenantID, target.ID)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "permission_delete_failed")
		return
	}
	deletedRights, _ := rightsResult.RowsAffected()

	if _, err := tx.ExecContext(r.Context(), `DELETE FROM user_sessions WHERE tenant_id = $1 AND user_id = $2`, target.TenantID, target.ID); err != nil {
		s.writeError(w, http.StatusInternalServerError, "user_session_delete_failed")
		return
	}
	if _, err := tx.ExecContext(r.Context(), `DELETE FROM access_sessions WHERE tenant_id = $1 AND user_id = $2`, target.TenantID, target.ID); err != nil {
		s.writeError(w, http.StatusInternalServerError, "access_session_delete_failed")
		return
	}
	powJobsResult, err := tx.ExecContext(r.Context(), `DELETE FROM pow_jobs WHERE tenant_id = $1 AND user_id = $2`, target.TenantID, target.ID)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "pow_job_delete_failed")
		return
	}
	deletedPoWJobs, _ := powJobsResult.RowsAffected()

	if err := promoteNextQueuedAccessJobTx(r.Context(), tx, target.TenantID); err != nil {
		s.writeError(w, http.StatusInternalServerError, "queue_promote_failed")
		return
	}

	targetID := target.ID
	if err := insertAuditEventTx(r.Context(), tx, target.TenantID, &actor.ID, "auth.user.deleted", "user", &targetID, "critical", clientIP(r), map[string]any{
		"username":         target.Username,
		"role":             target.Role,
		"revoked_sessions": revokedSessions,
		"canceled_jobs":    canceledJobs,
		"deleted_pow_jobs": deletedPoWJobs,
		"deleted_rights":   deletedRights,
	}); err != nil {
		s.writeError(w, http.StatusInternalServerError, "audit_failed")
		return
	}
	result, err := tx.ExecContext(r.Context(), `DELETE FROM users WHERE tenant_id = $1 AND id = $2`, target.TenantID, target.ID)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "user_delete_failed")
		return
	}
	affected, err := result.RowsAffected()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "user_delete_failed")
		return
	}
	if affected == 0 {
		s.writeError(w, http.StatusNotFound, "user_not_found")
		return
	}
	if err := tx.Commit(); err != nil {
		s.writeError(w, http.StatusInternalServerError, "transaction_commit_failed")
		return
	}

	writeJSON(w, http.StatusOK, deleteUserResponse{
		DeletedUserID:   target.ID,
		Username:        target.Username,
		Role:            target.Role,
		RevokedSessions: revokedSessions,
		CanceledJobs:    canceledJobs,
		DeletedPoWJobs:  deletedPoWJobs,
		DeletedRights:   deletedRights,
	})
}

func (s *Service) RequireRole(next http.Handler, roles ...string) http.Handler {
	allowed := map[string]bool{}
	for _, role := range roles {
		allowed[role] = true
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, err := s.CurrentUser(r)
		if err != nil {
			s.writeError(w, http.StatusUnauthorized, "not_authenticated")
			return
		}
		if !allowed[user.Role] {
			s.writeError(w, http.StatusForbidden, "forbidden")
			return
		}
		if user.MustChangePassword {
			s.writeError(w, http.StatusForbidden, "password_change_required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Service) CurrentUser(r *http.Request) (User, error) {
	token, ok := sessionTokenFromRequest(r)
	if !ok {
		return User{}, errors.New("session cookie missing")
	}
	return s.userBySessionHash(r.Context(), hashToken(token))
}

func (s *Service) userBySessionHash(ctx context.Context, tokenHash string) (User, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT u.id::text, u.tenant_id::text, u.role, u.username, u.must_change_password, u.is_blocked, u.description, u.created_at, u.last_login_at
FROM user_sessions s
JOIN users u ON u.id = s.user_id
WHERE s.token_hash = $1
  AND s.status = 'active'
  AND s.expires_at > now()
  AND u.is_blocked = false`, tokenHash)
	return scanUser(row)
}

func (s *Service) findLoginUser(ctx context.Context, username string) (User, string, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT u.id::text, u.tenant_id::text, u.role, u.username, u.must_change_password, u.is_blocked, u.description, u.created_at, u.last_login_at, u.password_hash
FROM users u
JOIN tenants t ON t.id = u.tenant_id
WHERE t.slug = 'default' AND u.lower_username = lower($1)`, strings.TrimSpace(username))

	var user User
	var description sql.NullString
	var lastLogin sql.NullTime
	var passwordHash sql.NullString
	err := row.Scan(&user.ID, &user.TenantID, &user.Role, &user.Username, &user.MustChangePassword, &user.IsBlocked, &description, &user.CreatedAt, &lastLogin, &passwordHash)
	if err != nil {
		return User{}, "", err
	}
	if description.Valid {
		user.Description = &description.String
	}
	if lastLogin.Valid {
		user.LastLoginAt = &lastLogin.Time
	}
	if !passwordHash.Valid || passwordHash.String == "" {
		return User{}, "", errors.New("password hash missing")
	}
	return user, passwordHash.String, nil
}

func (s *Service) userByID(ctx context.Context, userID string) (User, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT id::text, tenant_id::text, role, username, must_change_password, is_blocked, description, created_at, last_login_at
FROM users
WHERE id = $1`, userID)
	return scanUser(row)
}

func (s *Service) passwordHashForUser(ctx context.Context, userID string) (string, error) {
	var passwordHash sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT password_hash FROM users WHERE id = $1 AND is_blocked = false`, userID).Scan(&passwordHash)
	if err != nil {
		return "", err
	}
	if !passwordHash.Valid || passwordHash.String == "" {
		return "", errors.New("password hash missing")
	}
	return passwordHash.String, nil
}

func (s *Service) currentAuthSessionTTL(ctx context.Context) (time.Duration, error) {
	policy, err := s.loadAuthSessionPolicy(ctx)
	if err != nil {
		return 0, err
	}
	return time.Duration(policy.AuthTTLHours) * time.Hour, nil
}

func (s *Service) loadAuthSessionPolicy(ctx context.Context) (authSessionPolicy, error) {
	policy := s.normalizeAuthSessionPolicy(authSessionPolicy{})
	var raw []byte
	if err := s.db.QueryRowContext(ctx, `SELECT value FROM system_settings WHERE key = $1`, authSessionPolicyKey).Scan(&raw); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return policy, nil
		}
		return authSessionPolicy{}, err
	}
	if err := json.Unmarshal(raw, &policy); err != nil {
		return authSessionPolicy{}, err
	}
	return s.normalizeAuthSessionPolicy(policy), nil
}

func (s *Service) normalizeAuthSessionPolicy(policy authSessionPolicy) authSessionPolicy {
	if policy.ClientMode == "" {
		policy.ClientMode = "latest_login_wins"
	}
	if policy.AdminMode == "" {
		policy.AdminMode = "parallel_allowed"
	}
	if policy.SuperAdminMode == "" {
		policy.SuperAdminMode = "parallel_allowed"
	}
	if !policy.Enabled {
		policy.Enabled = true
	}
	if policy.AuthTTLHours <= 0 || !isAllowedAuthSessionTTL(policy.AuthTTLHours) {
		fallback := int(s.sessionTTL / time.Hour)
		if fallback <= 0 || !isAllowedAuthSessionTTL(fallback) {
			fallback = 12
		}
		policy.AuthTTLHours = fallback
	}
	policy.AllowedAuthTTLHours = append([]int(nil), allowedAuthSessionTTLHours...)
	return policy
}

func isAllowedAuthSessionTTL(hours int) bool {
	for _, allowed := range allowedAuthSessionTTLHours {
		if hours == allowed {
			return true
		}
	}
	return false
}

func (s *Service) bootstrapState(ctx context.Context) (int, string, error) {
	var tenantID string
	if err := s.db.QueryRowContext(ctx, `SELECT id::text FROM tenants WHERE slug = 'default'`).Scan(&tenantID); err != nil {
		return 0, "", err
	}
	var count int
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM users WHERE tenant_id = $1 AND role = 'super_admin'`, tenantID).Scan(&count); err != nil {
		return 0, "", err
	}
	return count, tenantID, nil
}

func (s *Service) insertAuditEvent(ctx context.Context, tenantID string, actorUserID *string, eventType string, targetType string, targetID *string, severity string, ipAddress string, details map[string]any) error {
	if tenantID == "" {
		var err error
		tenantID, err = defaultTenantID(ctx, s.db)
		if err != nil {
			return err
		}
	}
	_, err := s.db.ExecContext(ctx, `
INSERT INTO audit_events (tenant_id, actor_user_id, event_type, target_type, target_id, severity, ip_address, details)
VALUES ($1, $2, $3, nullif($4, ''), $5, $6, nullif($7, ''), $8::jsonb)`,
		tenantID, actorUserID, eventType, targetType, targetID, severity, ipAddress, string(mustJSON(details)),
	)
	return err
}

func insertAuditEventTx(ctx context.Context, tx *sql.Tx, tenantID string, actorUserID *string, eventType string, targetType string, targetID *string, severity string, ipAddress string, details map[string]any) error {
	_, err := tx.ExecContext(ctx, `
INSERT INTO audit_events (tenant_id, actor_user_id, event_type, target_type, target_id, severity, ip_address, details)
VALUES ($1, $2, $3, nullif($4, ''), $5, $6, nullif($7, ''), $8::jsonb)`,
		tenantID, actorUserID, eventType, targetType, targetID, severity, ipAddress, string(mustJSON(details)),
	)
	return err
}

func insertUserTx(ctx context.Context, tx *sql.Tx, tenantID string, role string, username string, passwordHash string, mustChangePassword bool, description sql.NullString) (User, error) {
	row := tx.QueryRowContext(ctx, `
INSERT INTO users (tenant_id, role, username, lower_username, password_hash, must_change_password, description)
VALUES ($1, $2, $3, lower($3), $4, $5, $6)
RETURNING id::text, tenant_id::text, role, username, must_change_password, is_blocked, description, created_at, last_login_at`,
		tenantID, role, username, passwordHash, mustChangePassword, description,
	)
	return scanUser(row)
}

func revokeUserSessionsTx(ctx context.Context, tx *sql.Tx, userID string) error {
	_, err := tx.ExecContext(ctx, `
UPDATE user_sessions
SET status = 'revoked', revoked_at = now()
WHERE user_id = $1 AND status = 'active'`, userID)
	return err
}

func promoteNextQueuedAccessJobTx(ctx context.Context, tx *sql.Tx, tenantID string) error {
	_, err := tx.ExecContext(ctx, `
UPDATE pow_jobs
SET status = 'running',
    started_at = now()
WHERE id = (
  SELECT id
  FROM pow_jobs
  WHERE tenant_id = $1
    AND status = 'queued'
    AND NOT EXISTS (
      SELECT 1 FROM pow_jobs WHERE tenant_id = $1 AND status = 'running'
    )
    AND NOT EXISTS (
      SELECT 1 FROM access_sessions WHERE tenant_id = $1 AND status = 'active' AND expires_at > now()
    )
  ORDER BY created_at
  LIMIT 1
)`, tenantID)
	return err
}

func defaultTenantID(ctx context.Context, db *sql.DB) (string, error) {
	var tenantID string
	err := db.QueryRowContext(ctx, `SELECT id::text FROM tenants WHERE slug = 'default'`).Scan(&tenantID)
	return tenantID, err
}

func defaultTenantIDTx(ctx context.Context, tx *sql.Tx) (string, error) {
	var tenantID string
	err := tx.QueryRowContext(ctx, `SELECT id::text FROM tenants WHERE slug = 'default'`).Scan(&tenantID)
	return tenantID, err
}

type userScanner interface {
	Scan(dest ...any) error
}

func scanUser(scanner userScanner) (User, error) {
	var user User
	var description sql.NullString
	var lastLogin sql.NullTime
	if err := scanner.Scan(&user.ID, &user.TenantID, &user.Role, &user.Username, &user.MustChangePassword, &user.IsBlocked, &description, &user.CreatedAt, &lastLogin); err != nil {
		return User{}, err
	}
	if description.Valid {
		user.Description = &description.String
	}
	if lastLogin.Valid {
		user.LastLoginAt = &lastLogin.Time
	}
	return user, nil
}

func canCreateRole(actorRole string, targetRole string) bool {
	switch actorRole {
	case "super_admin":
		return targetRole == "admin" || targetRole == "client"
	case "admin":
		return targetRole == "client"
	default:
		return false
	}
}

func canManageUser(actor User, target User) bool {
	if target.Role == "super_admin" {
		return false
	}
	if actor.ID == target.ID {
		return false
	}
	switch actor.Role {
	case "super_admin":
		return target.Role == "admin" || target.Role == "client"
	case "admin":
		return target.Role == "client"
	default:
		return false
	}
}

func isUUIDLike(value string) bool {
	if len(value) != 36 {
		return false
	}
	for index, char := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			if char != '-' {
				return false
			}
			continue
		}
		if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f') || (char >= 'A' && char <= 'F')) {
			return false
		}
	}
	return true
}

func newTemporaryPassword() (string, error) {
	raw := make([]byte, 18)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return "Av1-" + base64.RawURLEncoding.EncodeToString(raw), nil
}

func hashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func newSessionToken() (string, string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	return token, hashToken(token), nil
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func sessionTokenFromRequest(r *http.Request) (string, bool) {
	cookie, err := r.Cookie(SessionCookieName)
	if err != nil || strings.TrimSpace(cookie.Value) == "" {
		return "", false
	}
	return cookie.Value, true
}

func setSessionCookie(w http.ResponseWriter, token string, expiresAt time.Time, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   secure,
		Expires:  expiresAt,
	})
}

func clearSessionCookie(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   secure,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
	})
}

func decodeJSON(w http.ResponseWriter, r *http.Request, target any) bool {
	defer r.Body.Close()
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json"})
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func (s *Service) writeError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"error": code})
}

func requireMethod(w http.ResponseWriter, r *http.Request, method string) bool {
	if r.Method != method {
		w.Header().Set("Allow", method)
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		return false
	}
	return true
}

func writeMethodNotAllowed(w http.ResponseWriter, allow string) {
	w.Header().Set("Allow", allow)
	writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
}

func clientIP(r *http.Request) string {
	forwarded := strings.TrimSpace(r.Header.Get("X-Forwarded-For"))
	if forwarded != "" {
		return strings.TrimSpace(strings.Split(forwarded, ",")[0])
	}
	return r.RemoteAddr
}

func nullableString(value string) sql.NullString {
	value = strings.TrimSpace(value)
	return sql.NullString{String: value, Valid: value != ""}
}

func mustJSON(value map[string]any) []byte {
	if value == nil {
		value = map[string]any{}
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return []byte(`{}`)
	}
	return raw
}

func isUniqueViolation(err error) bool {
	return err != nil && strings.Contains(err.Error(), "duplicate key")
}

func (u User) String() string {
	return fmt.Sprintf("%s:%s", u.Role, u.Username)
}
