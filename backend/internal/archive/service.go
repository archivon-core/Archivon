package archive

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"archivon/backend/internal/auth"
	"archivon/backend/internal/kms"
	"archivon/backend/internal/policyseal"
	"golang.org/x/crypto/bcrypt"
)

const powAccessPolicyKey = "pow_access_policy"
const maxUploadPathLength = 1024
const maxUploadPathSegments = 64
const adminDAVSessionTTL = 12 * time.Hour
const folderBackupManifestName = "archivon-folder-backup.json"
const folderBackupFormat = "archivon-folder-backup"
const folderBackupVersion = 1

type Service struct {
	db          *sql.DB
	logger      *slog.Logger
	storagePath string
	kms         *kms.Service
	auth        *auth.Service
}

type Options struct {
	StoragePath string
}

type Folder struct {
	ID              string          `json:"id"`
	Name            string          `json:"name"`
	Description     string          `json:"description,omitempty"`
	Status          string          `json:"status"`
	CreatedAt       time.Time       `json:"created_at"`
	UpdatedAt       time.Time       `json:"updated_at"`
	FileCount       int             `json:"file_count"`
	TotalBytes      int64           `json:"total_bytes"`
	UnlockUsernames []string        `json:"unlock_usernames"`
	Access          *Access         `json:"access,omitempty"`
	PoWPolicy       FolderPoWPolicy `json:"pow_policy"`
}

type ClientFolder struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Description string  `json:"description,omitempty"`
	Status      string  `json:"status"`
	FileCount   int     `json:"file_count"`
	TotalBytes  int64   `json:"total_bytes"`
	Access      *Access `json:"access,omitempty"`
}

type FolderPoWPolicy struct {
	RequiredHashrateTHs      float64 `json:"required_hashrate_ths"`
	HashrateTolerancePercent float64 `json:"hashrate_tolerance_percent"`
	ProofWindowSeconds       int     `json:"proof_window_seconds"`
	MaxProofAttempts         int     `json:"max_proof_attempts"`
}

type File struct {
	ID              string    `json:"id"`
	FolderID        string    `json:"folder_id"`
	Name            string    `json:"name"`
	SizeBytes       int64     `json:"size_bytes"`
	PlaintextSHA256 string    `json:"plaintext_sha256"`
	StorageObjectID string    `json:"storage_object_id"`
	Path            string    `json:"path"`
	ChunkCount      int       `json:"chunk_count"`
	Status          string    `json:"status"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

type fileRecord struct {
	File
	TenantID string
}

type foldersResponse struct {
	Folders []Folder `json:"folders"`
}

type clientFoldersResponse struct {
	Folders []ClientFolder `json:"folders"`
}

type filesResponse struct {
	Files []File `json:"files"`
}

type clientFilesResponse struct {
	Files []ClientFile `json:"files"`
}

type createFolderRequest struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	PoWPolicy   FolderPoWPolicy `json:"pow_policy"`
}

type createFolderResponse struct {
	Folder Folder `json:"folder"`
}

type deleteFolderResponse struct {
	DeletedFolderID string `json:"deleted_folder_id"`
	DeletedFiles    int    `json:"deleted_files"`
	DeletedBytes    int64  `json:"deleted_bytes"`
}

type deleteFileResponse struct {
	DeletedFileID string `json:"deleted_file_id"`
	FolderID      string `json:"folder_id"`
}

type uploadFileResponse struct {
	File File `json:"file"`
}

type importFolderBackupResponse struct {
	Folder              Folder `json:"folder"`
	ImportedFiles       int    `json:"imported_files"`
	ImportedCollections int    `json:"imported_collections"`
}

type folderBackupManifest struct {
	Format    string             `json:"format"`
	Version   int                `json:"version"`
	ExportedAt time.Time          `json:"exported_at"`
	Folder    folderBackupFolder `json:"folder"`
	Collections []string           `json:"collections"`
	Files     []folderBackupFile  `json:"files"`
}

type folderBackupFolder struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
	PoWPolicy   FolderPoWPolicy `json:"pow_policy"`
}

type folderBackupFile struct {
	Path            string `json:"path"`
	Name            string `json:"name"`
	ArchivePath     string `json:"archive_path"`
	SizeBytes       int64  `json:"size_bytes"`
	PlaintextSHA256 string `json:"plaintext_sha256"`
}

type Access struct {
	CanUnlockAndAccess bool       `json:"can_unlock_and_access"`
	ExpiresAt          *time.Time `json:"expires_at,omitempty"`
}

type FolderPermission struct {
	UserID             string     `json:"user_id"`
	Username           string     `json:"username"`
	Role               string     `json:"role"`
	CanUnlockAndAccess bool       `json:"can_unlock_and_access"`
	ExpiresAt          *time.Time `json:"expires_at,omitempty"`
	UpdatedAt          *time.Time `json:"updated_at,omitempty"`
}

type permissionsResponse struct {
	Permissions []FolderPermission `json:"permissions"`
}

type updatePermissionRequest struct {
	UserID             string `json:"user_id"`
	CanUnlockAndAccess bool   `json:"can_unlock_and_access"`
	ExpiresAt          string `json:"expires_at"`
}

type updatePermissionResponse struct {
	Permission FolderPermission `json:"permission"`
}

type ClientFile struct {
	ID              string `json:"id"`
	FolderID        string `json:"folder_id"`
	Name            string `json:"name"`
	Path            string `json:"path"`
	SizeBytes       int64  `json:"size_bytes"`
	PlaintextSHA256 string `json:"plaintext_sha256"`
	Status          string `json:"status"`
}

type davSession struct {
	ID           string
	TenantID     string
	UserID       string
	FolderID     string
	DavUsername  string
	PasswordHash string
	ExpiresAt    time.Time
}

type adminDAVSession struct {
	ID           string
	TenantID     string
	UserID       string
	FolderID     string
	DavUsername  string
	PasswordHash string
	ExpiresAt    time.Time
}

type adminDAVCredentials struct {
	DavURL      string    `json:"dav_url"`
	DavUsername string    `json:"dav_username"`
	DavPassword string    `json:"dav_password"`
	ExpiresAt   time.Time `json:"expires_at"`
}

type adminDAVSessionResponse struct {
	Session adminDAVCredentials `json:"session"`
}

type davHTTPError struct {
	status int
	code   string
}

func (e davHTTPError) Error() string {
	return e.code
}

func NewService(db *sql.DB, logger *slog.Logger, kmsService *kms.Service, authService *auth.Service, opts Options) *Service {
	return &Service{
		db:          db,
		logger:      logger,
		storagePath: filepath.Clean(opts.StoragePath),
		kms:         kmsService,
		auth:        authService,
	}
}

func (s *Service) BackfillFolderPoWPolicySeals(ctx context.Context) error {
	type candidate struct {
		tenantID string
		folderID string
		policy   FolderPoWPolicy
		seal     sql.NullString
	}

	rows, err := s.db.QueryContext(ctx, `
SELECT
  tenant_id::text,
  id::text,
  pow_required_hashrate_ths::float8,
  pow_hashrate_tolerance_percent::float8,
  pow_proof_window_seconds,
  pow_max_proof_attempts,
  pow_policy_seal
FROM protected_folders
WHERE status = 'active'`)
	if err != nil {
		return err
	}

	candidates := []candidate{}
	for rows.Next() {
		var item candidate
		if err := rows.Scan(
			&item.tenantID,
			&item.folderID,
			&item.policy.RequiredHashrateTHs,
			&item.policy.HashrateTolerancePercent,
			&item.policy.ProofWindowSeconds,
			&item.policy.MaxProofAttempts,
			&item.seal,
		); err != nil {
			_ = rows.Close()
			return err
		}
		candidates = append(candidates, item)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}

	for _, item := range candidates {
		if _, err := s.ensureFolderPoWPolicySeal(ctx, item.tenantID, item.folderID, item.policy, item.seal); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) Register(mux *http.ServeMux) {
	mux.Handle("/api/admin/folders", s.auth.RequireRole(http.HandlerFunc(s.handleFoldersCollection), "super_admin", "admin"))
	mux.Handle("/api/admin/folders/", s.auth.RequireRole(http.HandlerFunc(s.handleFolderAction), "super_admin", "admin"))
	mux.Handle("/api/admin/folder-backups", s.auth.RequireRole(http.HandlerFunc(s.handleFolderBackupsCollection), "super_admin", "admin"))
	mux.Handle("/api/admin/files/", s.auth.RequireRole(http.HandlerFunc(s.handleAdminFileAction), "super_admin", "admin"))
	mux.Handle("/api/client/folders", s.auth.RequireRole(http.HandlerFunc(s.handleClientFoldersCollection), "client"))
	mux.Handle("/api/client/folders/", s.auth.RequireRole(http.HandlerFunc(s.handleClientFolderAction), "client"))
	mux.Handle("/api/client/files/", s.auth.RequireRole(http.HandlerFunc(s.handleClientFileAction), "client"))
	mux.Handle("/dav/", http.HandlerFunc(s.handleWebDAV))
	mux.Handle("/admin-dav/", http.HandlerFunc(s.handleAdminWebDAV))
}

func (s *Service) handleFoldersCollection(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleListFolders(w, r)
	case http.MethodPost:
		s.handleCreateFolder(w, r)
	default:
		writeMethodNotAllowed(w, "GET, POST")
	}
}

func (s *Service) handleFolderBackupsCollection(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, "POST")
		return
	}
	s.handleImportFolderBackup(w, r)
}

func (s *Service) handleFolderAction(w http.ResponseWriter, r *http.Request) {
	pathValue := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/admin/folders/"), "/")
	parts := strings.Split(pathValue, "/")
	if len(parts) == 1 && parts[0] != "" {
		if r.Method != http.MethodDelete {
			writeMethodNotAllowed(w, "DELETE")
			return
		}
		s.handleDeleteFolder(w, r, parts[0])
		return
	}
	if len(parts) != 2 || parts[0] == "" {
		s.writeError(w, http.StatusNotFound, "not_found")
		return
	}
	switch parts[1] {
	case "files":
		switch r.Method {
		case http.MethodGet:
			s.handleListFiles(w, r, parts[0])
		case http.MethodPost:
			s.handleUploadFile(w, r, parts[0])
		default:
			writeMethodNotAllowed(w, "GET, POST")
		}
	case "permissions":
		switch r.Method {
		case http.MethodGet:
			s.handleListFolderPermissions(w, r, parts[0])
		case http.MethodPost:
			s.handleUpdateFolderPermission(w, r, parts[0])
		default:
			writeMethodNotAllowed(w, "GET, POST")
		}
	case "pow-policy":
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w, "POST")
			return
		}
		s.handleUpdateFolderPoWPolicy(w, r, parts[0])
	case "admin-dav":
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w, "POST")
			return
		}
		s.handleCreateAdminDAVSession(w, r, parts[0])
	case "backup":
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, "GET")
			return
		}
		s.handleExportFolderBackup(w, r, parts[0])
	default:
		s.writeError(w, http.StatusNotFound, "not_found")
	}
}

func (s *Service) handleAdminFileAction(w http.ResponseWriter, r *http.Request) {
	pathValue := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/admin/files/"), "/")
	parts := strings.Split(pathValue, "/")
	if len(parts) == 1 && parts[0] != "" {
		if r.Method != http.MethodDelete {
			writeMethodNotAllowed(w, "DELETE")
			return
		}
		s.handleDeleteFile(w, r, parts[0])
		return
	}
	if len(parts) != 2 || parts[0] == "" {
		s.writeError(w, http.StatusNotFound, "not_found")
		return
	}
	s.writeError(w, http.StatusNotFound, "not_found")
}

func (s *Service) handleClientFoldersCollection(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, "GET")
		return
	}
	s.handleListClientFolders(w, r)
}

func (s *Service) handleClientFolderAction(w http.ResponseWriter, r *http.Request) {
	pathValue := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/client/folders/"), "/")
	parts := strings.Split(pathValue, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] != "files" {
		s.writeError(w, http.StatusNotFound, "not_found")
		return
	}
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, "GET")
		return
	}
	s.handleListClientFiles(w, r, parts[0])
}

func (s *Service) handleClientFileAction(w http.ResponseWriter, r *http.Request) {
	pathValue := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/client/files/"), "/")
	parts := strings.Split(pathValue, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] != "download" {
		s.writeError(w, http.StatusNotFound, "not_found")
		return
	}
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, "GET")
		return
	}
	s.handleDownloadClientFile(w, r, parts[0])
}

func (s *Service) handleWebDAV(w http.ResponseWriter, r *http.Request) {
	setDAVHeaders(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if !davMethodAllowed(r.Method) {
		writeDAVError(w, http.StatusMethodNotAllowed, "read_only")
		return
	}
	if !s.kms.Ready(r.Context()) {
		writeDAVError(w, http.StatusServiceUnavailable, "kms_not_ready")
		return
	}
	session, ok := s.authenticateDAV(r.Context(), w, r)
	if !ok {
		return
	}
	parts, ok := davPathParts(r, "/dav/", session.DavUsername)
	if !ok {
		writeDAVError(w, http.StatusNotFound, "not_found")
		return
	}
	switch r.Method {
	case "PROPFIND":
		s.handleDAVPropfind(w, r, session, parts)
	case http.MethodGet, http.MethodHead:
		s.handleDAVRead(w, r, session, parts)
	default:
		writeDAVError(w, http.StatusMethodNotAllowed, "method_not_allowed")
	}
}

func (s *Service) handleAdminWebDAV(w http.ResponseWriter, r *http.Request) {
	setAdminDAVHeaders(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if !adminDAVMethodAllowed(r.Method) {
		writeDAVError(w, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	if !s.kms.Ready(r.Context()) {
		writeDAVError(w, http.StatusServiceUnavailable, "kms_not_ready")
		return
	}
	session, ok := s.authenticateAdminDAV(r.Context(), w, r)
	if !ok {
		return
	}
	parts, ok := davPathParts(r, "/admin-dav/", session.DavUsername)
	if !ok {
		writeDAVError(w, http.StatusNotFound, "not_found")
		return
	}
	switch r.Method {
	case "PROPFIND":
		s.handleAdminDAVPropfind(w, r, session, parts)
	case http.MethodGet, http.MethodHead:
		s.handleAdminDAVRead(w, r, session, parts)
	case http.MethodPut:
		s.handleAdminDAVPut(w, r, session, parts)
	case "MKCOL":
		s.handleAdminDAVMkcol(w, r, session, parts)
	case "LOCK":
		writeAdminDAVLock(w, r)
	case "UNLOCK":
		w.WriteHeader(http.StatusNoContent)
	default:
		writeDAVError(w, http.StatusMethodNotAllowed, "method_not_allowed")
	}
}

func (s *Service) handleCreateFolder(w http.ResponseWriter, r *http.Request) {
	actor, err := s.auth.CurrentUser(r)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, "not_authenticated")
		return
	}
	if !s.kmsReady(r.Context(), w) {
		return
	}

	var req createFolderRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		s.writeError(w, http.StatusBadRequest, "folder_name_required")
		return
	}
	if len([]rune(name)) > 180 {
		s.writeError(w, http.StatusBadRequest, "folder_name_too_long")
		return
	}
	description := strings.TrimSpace(req.Description)
	if len([]rune(description)) > 1000 {
		s.writeError(w, http.StatusBadRequest, "folder_description_too_long")
		return
	}
	defaultPoWPolicy, err := s.defaultFolderPoWPolicy(r.Context())
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "pow_policy_load_failed")
		return
	}
	powPolicy := normalizeFolderPoWPolicy(req.PoWPolicy, defaultPoWPolicy)
	if err := validateFolderPoWPolicy(powPolicy); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	folderID, err := newUUID()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "folder_id_failed")
		return
	}
	policySeal, err := s.folderPoWPolicySeal(r.Context(), actor.TenantID, folderID, powPolicy)
	if err != nil {
		s.writeError(w, http.StatusServiceUnavailable, "folder_pow_policy_seal_failed")
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
	INSERT INTO protected_folders (
	  id, tenant_id, name, description,
	  pow_required_hashrate_ths, pow_hashrate_tolerance_percent, pow_proof_window_seconds,
	  pow_max_proof_attempts, pow_policy_seal, created_by
	)
	VALUES ($1, $2, $3, nullif($4, ''), $5, $6, $7, $8, $9, $10)`,
		folderID,
		actor.TenantID,
		name,
		description,
		powPolicy.RequiredHashrateTHs,
		powPolicy.HashrateTolerancePercent,
		powPolicy.ProofWindowSeconds,
		powPolicy.MaxProofAttempts,
		policySeal,
		actor.ID,
	); err != nil {
		s.writeError(w, http.StatusInternalServerError, "folder_create_failed")
		return
	}
	if err := insertAuditEventTx(r.Context(), tx, actor.TenantID, actor.ID, "archive.folder.created", "protected_folder", folderID, "info", clientIP(r), map[string]any{
		"name":       name,
		"pow_policy": powPolicy,
	}); err != nil {
		s.writeError(w, http.StatusInternalServerError, "audit_failed")
		return
	}
	if err := tx.Commit(); err != nil {
		s.writeError(w, http.StatusInternalServerError, "transaction_commit_failed")
		return
	}

	folder, err := s.folderByID(r.Context(), actor.TenantID, folderID)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "folder_reload_failed")
		return
	}
	writeJSON(w, http.StatusCreated, createFolderResponse{Folder: folder})
}

func (s *Service) handleListFolders(w http.ResponseWriter, r *http.Request) {
	actor, err := s.auth.CurrentUser(r)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, "not_authenticated")
		return
	}
	if !s.kmsReady(r.Context(), w) {
		return
	}

	rows, err := s.db.QueryContext(r.Context(), `
SELECT
  pf.id::text,
  pf.name,
  coalesce(pf.description, ''),
  pf.status,
  pf.created_at,
  pf.updated_at,
	  pf.pow_required_hashrate_ths::float8,
	  pf.pow_hashrate_tolerance_percent::float8,
	  pf.pow_proof_window_seconds,
	  pf.pow_max_proof_attempts,
  pf.pow_policy_seal,
  (
    SELECT count(f.id)::int
    FROM files f
    WHERE f.protected_folder_id = pf.id AND f.status = 'active'
  ) AS file_count,
  (
    SELECT coalesce(sum(f.size_bytes), 0)::bigint
    FROM files f
    WHERE f.protected_folder_id = pf.id AND f.status = 'active'
  ) AS total_bytes,
  (
    SELECT coalesce(jsonb_agg(unlock_users.username ORDER BY unlock_users.username), '[]'::jsonb)::text
    FROM (
      SELECT DISTINCT u.username
      FROM folder_permissions fp
      JOIN users u ON u.id = fp.user_id
      WHERE fp.tenant_id = pf.tenant_id
        AND fp.protected_folder_id = pf.id
        AND fp.can_unlock_and_access = true
        AND (fp.expires_at IS NULL OR fp.expires_at > now())
        AND u.role = 'client'
        AND u.is_blocked = false
    ) unlock_users
  ) AS unlock_usernames
FROM protected_folders pf
WHERE pf.tenant_id = $1 AND pf.status = 'active'
ORDER BY pf.name ASC, pf.id DESC`, actor.TenantID)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "folders_query_failed")
		return
	}
	defer rows.Close()

	folders := []Folder{}
	for rows.Next() {
		folder, err := s.scanFolder(r.Context(), actor.TenantID, rows)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "folders_scan_failed")
			return
		}
		folders = append(folders, folder)
	}
	if err := rows.Err(); err != nil {
		s.writeError(w, http.StatusInternalServerError, "folders_rows_failed")
		return
	}
	writeJSON(w, http.StatusOK, foldersResponse{Folders: folders})
}

func (s *Service) handleUpdateFolderPoWPolicy(w http.ResponseWriter, r *http.Request, folderID string) {
	actor, err := s.auth.CurrentUser(r)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, "not_authenticated")
		return
	}
	if !isUUIDLike(folderID) {
		s.writeError(w, http.StatusNotFound, "folder_not_found")
		return
	}
	_ = insertAuditEvent(r.Context(), s.db, actor.TenantID, actor.ID, "archive.folder_pow_policy.change_rejected", "protected_folder", folderID, "warning", clientIP(r), map[string]any{
		"reason": "immutable_after_create",
	})
	s.writeError(w, http.StatusConflict, "folder_pow_policy_immutable")
}

func (s *Service) handleExportFolderBackup(w http.ResponseWriter, r *http.Request, folderID string) {
	actor, err := s.auth.CurrentUser(r)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, "not_authenticated")
		return
	}
	if !s.kmsReady(r.Context(), w) {
		return
	}
	if !isUUIDLike(folderID) {
		s.writeError(w, http.StatusNotFound, "folder_not_found")
		return
	}
	folder, err := s.folderByID(r.Context(), actor.TenantID, folderID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			s.writeError(w, http.StatusNotFound, "folder_not_found")
			return
		}
		s.writeError(w, http.StatusInternalServerError, "folder_lookup_failed")
		return
	}
	files, err := s.filesForFolder(r.Context(), actor.TenantID, folderID)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "files_query_failed")
		return
	}
	collections, err := s.folderCollections(r.Context(), actor.TenantID, folderID)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "folder_collections_query_failed")
		return
	}

	manifest := folderBackupManifest{
		Format:      folderBackupFormat,
		Version:     folderBackupVersion,
		ExportedAt:  time.Now().UTC(),
		Collections: collections,
		Files:       make([]folderBackupFile, 0, len(files)),
		Folder: folderBackupFolder{
			Name:        folder.Name,
			Description: folder.Description,
			CreatedAt:   folder.CreatedAt,
			UpdatedAt:   folder.UpdatedAt,
			PoWPolicy:   folder.PoWPolicy,
		},
	}
	displayPaths := davDisplayPaths(files)
	for _, file := range files {
		displayPath := displayPaths[file.ID]
		manifest.Files = append(manifest.Files, folderBackupFile{
			Path:            displayPath,
			Name:            file.Name,
			ArchivePath:     backupArchivePath(displayPath, file),
			SizeBytes:       file.SizeBytes,
			PlaintextSHA256: file.PlaintextSHA256,
		})
	}
	if err := insertAuditEvent(r.Context(), s.db, actor.TenantID, actor.ID, "archive.folder.backup_exported", "protected_folder", folderID, "warning", clientIP(r), map[string]any{
		"folder_name": folder.Name,
		"file_count":  len(files),
	}); err != nil {
		s.writeError(w, http.StatusInternalServerError, "audit_failed")
		return
	}

	filename := backupDownloadName(folder.Name)
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": filename}))
	w.Header().Set("X-Content-Type-Options", "nosniff")

	archive := zip.NewWriter(w)
	manifestWriter, err := archive.Create(folderBackupManifestName)
	if err != nil {
		if s.logger != nil {
			s.logger.Warn("folder backup manifest create failed", "folder_id", folderID, "error", err)
		}
		return
	}
	encoder := json.NewEncoder(manifestWriter)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(manifest); err != nil {
		if s.logger != nil {
			s.logger.Warn("folder backup manifest write failed", "folder_id", folderID, "error", err)
		}
		return
	}
	for _, collection := range collections {
		collection = strings.Trim(collection, "/")
		if collection == "" {
			continue
		}
		_, _ = archive.Create("content/" + collection + "/")
	}
	for index, file := range files {
		record, err := s.fileRecordByID(r.Context(), actor.TenantID, file.ID)
		if err != nil {
			if s.logger != nil {
				s.logger.Warn("folder backup file lookup failed", "folder_id", folderID, "file_id", file.ID, "error", err)
			}
			return
		}
		fileWriter, err := archive.Create(manifest.Files[index].ArchivePath)
		if err != nil {
			if s.logger != nil {
				s.logger.Warn("folder backup file entry create failed", "folder_id", folderID, "file_id", file.ID, "error", err)
			}
			return
		}
		if err := s.copyStoredFileToWriter(r.Context(), record, fileWriter); err != nil {
			if s.logger != nil {
				s.logger.Warn("folder backup file copy failed", "folder_id", folderID, "file_id", file.ID, "error", err)
			}
			return
		}
	}
	if err := archive.Close(); err != nil && s.logger != nil {
		s.logger.Warn("folder backup close failed", "folder_id", folderID, "error", err)
	}
}

func (s *Service) handleImportFolderBackup(w http.ResponseWriter, r *http.Request) {
	actor, err := s.auth.CurrentUser(r)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, "not_authenticated")
		return
	}
	if !s.kmsReady(r.Context(), w) {
		return
	}
	source, header, err := r.FormFile("file")
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "backup_file_required")
		return
	}
	defer source.Close()

	result, err := s.importFolderBackup(r.Context(), actor, source, header, clientIP(r))
	if err != nil {
		var typed davHTTPError
		if errors.As(err, &typed) {
			s.writeError(w, typed.status, typed.code)
			return
		}
		if s.logger != nil {
			s.logger.Warn("folder backup import failed", "error", err)
		}
		s.writeError(w, http.StatusInternalServerError, "folder_backup_import_failed")
		return
	}
	writeJSON(w, http.StatusCreated, result)
}

func (s *Service) handleCreateAdminDAVSession(w http.ResponseWriter, r *http.Request, folderID string) {
	actor, err := s.auth.CurrentUser(r)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, "not_authenticated")
		return
	}
	if !s.kmsReady(r.Context(), w) {
		return
	}
	if !isUUIDLike(folderID) {
		s.writeError(w, http.StatusNotFound, "folder_not_found")
		return
	}
	if err := s.ensureFolderActive(r.Context(), actor.TenantID, folderID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			s.writeError(w, http.StatusNotFound, "folder_not_found")
			return
		}
		s.writeError(w, http.StatusInternalServerError, "folder_lookup_failed")
		return
	}

	sessionID, err := newUUID()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "admin_dav_session_id_failed")
		return
	}
	username := "admindav_" + strings.ReplaceAll(sessionID, "-", "")
	password, err := newAdminDAVPassword()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "admin_dav_password_failed")
		return
	}
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "admin_dav_password_hash_failed")
		return
	}
	expiresAt := time.Now().UTC().Add(adminDAVSessionTTL)

	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "transaction_failed")
		return
	}
	defer func() {
		_ = tx.Rollback()
	}()
	if _, err := tx.ExecContext(r.Context(), `
UPDATE admin_dav_sessions
SET status = 'revoked',
    revoked_at = now()
WHERE tenant_id = $1
  AND user_id = $2
  AND protected_folder_id = $3
  AND status = 'active'`, actor.TenantID, actor.ID, folderID); err != nil {
		s.writeError(w, http.StatusInternalServerError, "admin_dav_revoke_failed")
		return
	}
	if _, err := tx.ExecContext(r.Context(), `
INSERT INTO admin_dav_sessions (
  id, tenant_id, user_id, protected_folder_id, dav_username, dav_password_hash, expires_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		sessionID, actor.TenantID, actor.ID, folderID, username, string(passwordHash), expiresAt,
	); err != nil {
		s.writeError(w, http.StatusInternalServerError, "admin_dav_session_create_failed")
		return
	}
	if err := insertAuditEventTx(r.Context(), tx, actor.TenantID, actor.ID, "archive.admin_dav.created", "protected_folder", folderID, "warning", clientIP(r), map[string]any{
		"admin_dav_username": username,
		"expires_at":         expiresAt,
	}); err != nil {
		s.writeError(w, http.StatusInternalServerError, "audit_failed")
		return
	}
	if err := tx.Commit(); err != nil {
		s.writeError(w, http.StatusInternalServerError, "transaction_commit_failed")
		return
	}

	writeJSON(w, http.StatusCreated, adminDAVSessionResponse{Session: adminDAVCredentials{
		DavURL:      adminDAVURLFromRequest(r, username),
		DavUsername: username,
		DavPassword: password,
		ExpiresAt:   expiresAt,
	}})
}

func (s *Service) handleDeleteFile(w http.ResponseWriter, r *http.Request, fileID string) {
	actor, err := s.auth.CurrentUser(r)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, "not_authenticated")
		return
	}
	if !isUUIDLike(fileID) {
		s.writeError(w, http.StatusNotFound, "file_not_found")
		return
	}

	var folderID string
	var storageObjectID string
	var sizeBytes int64
	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "transaction_failed")
		return
	}
	defer func() {
		_ = tx.Rollback()
	}()
	if err := tx.QueryRowContext(r.Context(), `
UPDATE files
SET status = 'deleted'
WHERE tenant_id = $1 AND id = $2 AND status = 'active'
RETURNING protected_folder_id::text, storage_object_id, size_bytes`, actor.TenantID, fileID).Scan(&folderID, &storageObjectID, &sizeBytes); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			s.writeError(w, http.StatusNotFound, "file_not_found")
			return
		}
		s.writeError(w, http.StatusInternalServerError, "file_delete_failed")
		return
	}
	if _, err := tx.ExecContext(r.Context(), `DELETE FROM folder_entries WHERE tenant_id = $1 AND file_id = $2`, actor.TenantID, fileID); err != nil {
		s.writeError(w, http.StatusInternalServerError, "folder_entry_delete_failed")
		return
	}
	if err := insertAuditEventTx(r.Context(), tx, actor.TenantID, actor.ID, "archive.file.deleted", "file", fileID, "warning", clientIP(r), map[string]any{
		"folder_id":         folderID,
		"size_bytes":        sizeBytes,
		"storage_object_id": storageObjectID,
		"without_unlock":    true,
	}); err != nil {
		s.writeError(w, http.StatusInternalServerError, "audit_failed")
		return
	}
	if err := tx.Commit(); err != nil {
		s.writeError(w, http.StatusInternalServerError, "transaction_commit_failed")
		return
	}
	s.removeStorageObjects([]string{storageObjectID})
	writeJSON(w, http.StatusOK, deleteFileResponse{DeletedFileID: fileID, FolderID: folderID})
}

func (s *Service) handleDeleteFolder(w http.ResponseWriter, r *http.Request, folderID string) {
	actor, err := s.auth.CurrentUser(r)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, "not_authenticated")
		return
	}
	if !isUUIDLike(folderID) {
		s.writeError(w, http.StatusNotFound, "folder_not_found")
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

	var exists int
	if err := tx.QueryRowContext(r.Context(), `
SELECT 1
FROM protected_folders
WHERE tenant_id = $1 AND id = $2 AND status = 'active'
FOR UPDATE`, actor.TenantID, folderID).Scan(&exists); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			s.writeError(w, http.StatusNotFound, "folder_not_found")
			return
		}
		s.writeError(w, http.StatusInternalServerError, "folder_lookup_failed")
		return
	}

	rows, err := tx.QueryContext(r.Context(), `
SELECT storage_object_id, size_bytes
FROM files
WHERE tenant_id = $1 AND protected_folder_id = $2 AND status = 'active'`, actor.TenantID, folderID)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "files_query_failed")
		return
	}
	storageObjectIDs := []string{}
	deletedFiles := 0
	var deletedBytes int64
	for rows.Next() {
		var storageObjectID string
		var sizeBytes int64
		if err := rows.Scan(&storageObjectID, &sizeBytes); err != nil {
			_ = rows.Close()
			s.writeError(w, http.StatusInternalServerError, "files_scan_failed")
			return
		}
		storageObjectIDs = append(storageObjectIDs, storageObjectID)
		deletedFiles++
		deletedBytes += sizeBytes
	}
	if err := rows.Close(); err != nil {
		s.writeError(w, http.StatusInternalServerError, "files_close_failed")
		return
	}
	if err := rows.Err(); err != nil {
		s.writeError(w, http.StatusInternalServerError, "files_rows_failed")
		return
	}

	sessionResult, err := tx.ExecContext(r.Context(), `
UPDATE access_sessions
SET status = 'revoked',
    closed_at = now(),
    close_reason = 'folder_deleted'
WHERE tenant_id = $1
  AND protected_folder_id = $2
  AND status = 'active'`, actor.TenantID, folderID)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "session_revoke_failed")
		return
	}
	revokedSessions, _ := sessionResult.RowsAffected()

	jobResult, err := tx.ExecContext(r.Context(), `
UPDATE pow_jobs
SET status = 'canceled',
    finished_at = now(),
    failure_reason = 'folder_deleted'
WHERE tenant_id = $1
  AND protected_folder_id = $2
  AND status IN ('queued', 'running')`, actor.TenantID, folderID)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "job_cancel_failed")
		return
	}
	canceledJobs, _ := jobResult.RowsAffected()

	if _, err := tx.ExecContext(r.Context(), `DELETE FROM folder_entries WHERE tenant_id = $1 AND protected_folder_id = $2`, actor.TenantID, folderID); err != nil {
		s.writeError(w, http.StatusInternalServerError, "folder_entry_delete_failed")
		return
	}
	if _, err := tx.ExecContext(r.Context(), `DELETE FROM folder_permissions WHERE tenant_id = $1 AND protected_folder_id = $2`, actor.TenantID, folderID); err != nil {
		s.writeError(w, http.StatusInternalServerError, "permission_delete_failed")
		return
	}
	if _, err := tx.ExecContext(r.Context(), `
UPDATE files
SET status = 'deleted'
WHERE tenant_id = $1 AND protected_folder_id = $2 AND status = 'active'`, actor.TenantID, folderID); err != nil {
		s.writeError(w, http.StatusInternalServerError, "files_delete_failed")
		return
	}
	if _, err := tx.ExecContext(r.Context(), `
UPDATE protected_folders
SET status = 'deleted'
WHERE tenant_id = $1 AND id = $2 AND status = 'active'`, actor.TenantID, folderID); err != nil {
		s.writeError(w, http.StatusInternalServerError, "folder_delete_failed")
		return
	}
	if err := insertAuditEventTx(r.Context(), tx, actor.TenantID, actor.ID, "archive.folder.deleted", "protected_folder", folderID, "critical", clientIP(r), map[string]any{
		"deleted_files":    deletedFiles,
		"deleted_bytes":    deletedBytes,
		"revoked_sessions": revokedSessions,
		"canceled_jobs":    canceledJobs,
		"without_unlock":   true,
	}); err != nil {
		s.writeError(w, http.StatusInternalServerError, "audit_failed")
		return
	}
	if err := promoteNextQueuedAccessJobTx(r.Context(), tx, actor.TenantID); err != nil {
		s.writeError(w, http.StatusInternalServerError, "queue_promote_failed")
		return
	}
	if err := tx.Commit(); err != nil {
		s.writeError(w, http.StatusInternalServerError, "transaction_commit_failed")
		return
	}
	s.removeStorageObjects(storageObjectIDs)
	writeJSON(w, http.StatusOK, deleteFolderResponse{DeletedFolderID: folderID, DeletedFiles: deletedFiles, DeletedBytes: deletedBytes})
}

func deleteFileTx(ctx context.Context, tx *sql.Tx, tenantID string, fileID string) (string, error) {
	var storageObjectID string
	if err := tx.QueryRowContext(ctx, `
UPDATE files
SET status = 'deleted'
WHERE tenant_id = $1 AND id = $2 AND status = 'active'
RETURNING storage_object_id`, tenantID, fileID).Scan(&storageObjectID); err != nil {
		return "", err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM folder_entries WHERE tenant_id = $1 AND file_id = $2`, tenantID, fileID); err != nil {
		return "", err
	}
	return storageObjectID, nil
}

func (s *Service) handleUploadFile(w http.ResponseWriter, r *http.Request, folderID string) {
	actor, err := s.auth.CurrentUser(r)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, "not_authenticated")
		return
	}
	if !s.kmsReady(r.Context(), w) {
		return
	}
	if !isUUIDLike(folderID) {
		s.writeError(w, http.StatusNotFound, "folder_not_found")
		return
	}
	if err := s.ensureFolderActive(r.Context(), actor.TenantID, folderID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			s.writeError(w, http.StatusNotFound, "folder_not_found")
			return
		}
		s.writeError(w, http.StatusInternalServerError, "folder_lookup_failed")
		return
	}

	source, header, err := r.FormFile("file")
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "file_required")
		return
	}
	defer source.Close()

	uploadPath, err := cleanUploadPath(r.FormValue("relative_path"), header.Filename)
	if err != nil {
		if s.logger != nil {
			s.logger.Warn("upload path rejected", "filename", header.Filename, "relative_path", r.FormValue("relative_path"), "error", err)
		}
		s.writeError(w, http.StatusBadRequest, "invalid_upload_path")
		return
	}
	originalName := uploadPath[len(uploadPath)-1]
	parentSegments := uploadPath[:len(uploadPath)-1]
	entryPath := strings.Join(uploadPath, "/")
	if originalName == "" {
		s.writeError(w, http.StatusBadRequest, "file_name_required")
		return
	}

	fileID, err := newUUID()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "file_id_failed")
		return
	}
	entryID, err := newUUID()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "entry_id_failed")
		return
	}
	storageObjectID, err := newStorageObjectID()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "storage_object_id_failed")
		return
	}
	objectDir := s.objectDir(storageObjectID)
	if err := os.MkdirAll(objectDir, 0700); err != nil {
		if s.logger != nil {
			s.logger.Warn("storage object directory create failed", "file_name", originalName, "relative_path", entryPath, "error", err)
		}
		s.writeError(w, http.StatusInternalServerError, "storage_object_create_failed")
		return
	}
	cleanupObject := true
	defer func() {
		if cleanupObject {
			_ = os.RemoveAll(objectDir)
		}
	}()

	plaintextSHA, sizeBytes, err := s.writeUploadToStorage(r.Context(), source, objectDir)
	if err != nil {
		if s.logger != nil {
			s.logger.Warn("file storage write failed", "file_name", originalName, "relative_path", entryPath, "error", err)
		}
		s.writeError(w, http.StatusInternalServerError, "file_store_failed")
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

	parentEntryID, err := ensureFolderEntryPathTx(r.Context(), tx, actor.TenantID, folderID, parentSegments)
	if err != nil {
		if s.logger != nil {
			s.logger.Warn("folder path create failed", "file_name", originalName, "relative_path", entryPath, "error", err)
		}
		s.writeError(w, http.StatusInternalServerError, "folder_path_create_failed")
		return
	}

	if _, err := tx.ExecContext(r.Context(), `
	INSERT INTO files (
	  id, tenant_id, protected_folder_id, storage_object_id, original_name,
	  plaintext_sha256, size_bytes, created_by
	)
	VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		fileID, actor.TenantID, folderID, storageObjectID, originalName, plaintextSHA, sizeBytes, actor.ID,
	); err != nil {
		if s.logger != nil {
			s.logger.Warn("file record create failed", "file_name", originalName, "relative_path", entryPath, "size_bytes", sizeBytes, "error", err)
		}
		s.writeError(w, http.StatusInternalServerError, "file_record_create_failed")
		return
	}
	if _, err := tx.ExecContext(r.Context(), `
	INSERT INTO folder_entries (
	  id, tenant_id, protected_folder_id, parent_entry_id, entry_type, name, file_id
	)
	VALUES ($1, $2, $3, $4, 'file', $5, $6)`,
		entryID, actor.TenantID, folderID, nullableStringPtr(parentEntryID), originalName, fileID,
	); err != nil {
		if s.logger != nil {
			s.logger.Warn("folder entry create failed", "file_name", originalName, "relative_path", entryPath, "error", err)
		}
		s.writeError(w, http.StatusInternalServerError, "folder_entry_create_failed")
		return
	}
	if err := insertAuditEventTx(r.Context(), tx, actor.TenantID, actor.ID, "archive.file.uploaded", "file", fileID, "info", clientIP(r), map[string]any{
		"folder_id":         folderID,
		"file_name":         originalName,
		"relative_path":     entryPath,
		"size_bytes":        sizeBytes,
		"plaintext_sha256":  plaintextSHA,
		"storage_object_id": storageObjectID,
	}); err != nil {
		s.writeError(w, http.StatusInternalServerError, "audit_failed")
		return
	}
	if err := tx.Commit(); err != nil {
		s.writeError(w, http.StatusInternalServerError, "transaction_commit_failed")
		return
	}
	cleanupObject = false

	file, err := s.fileByID(r.Context(), actor.TenantID, fileID)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "file_reload_failed")
		return
	}
	writeJSON(w, http.StatusCreated, uploadFileResponse{File: file})
}

func (s *Service) handleListFiles(w http.ResponseWriter, r *http.Request, folderID string) {
	actor, err := s.auth.CurrentUser(r)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, "not_authenticated")
		return
	}
	if !s.kmsReady(r.Context(), w) {
		return
	}
	if !isUUIDLike(folderID) {
		s.writeError(w, http.StatusNotFound, "folder_not_found")
		return
	}
	if err := s.ensureFolderActive(r.Context(), actor.TenantID, folderID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			s.writeError(w, http.StatusNotFound, "folder_not_found")
			return
		}
		s.writeError(w, http.StatusInternalServerError, "folder_lookup_failed")
		return
	}

	files, err := s.filesForFolder(r.Context(), actor.TenantID, folderID)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "files_query_failed")
		return
	}
	writeJSON(w, http.StatusOK, filesResponse{Files: files})
}

func (s *Service) filesForFolder(ctx context.Context, tenantID string, folderID string) ([]File, error) {
	rows, err := s.db.QueryContext(ctx, `
WITH RECURSIVE entry_paths AS (
  SELECT id, file_id, parent_entry_id, entry_type, name, name::text AS path
  FROM folder_entries
  WHERE tenant_id = $1 AND protected_folder_id = $2 AND parent_entry_id IS NULL
  UNION ALL
  SELECT child.id, child.file_id, child.parent_entry_id, child.entry_type, child.name, entry_paths.path || '/' || child.name
  FROM folder_entries child
  JOIN entry_paths ON entry_paths.id = child.parent_entry_id
  WHERE child.tenant_id = $1 AND child.protected_folder_id = $2
)
SELECT f.id::text, f.protected_folder_id::text, f.storage_object_id, f.original_name,
       f.plaintext_sha256, f.size_bytes, f.status, f.created_at, f.updated_at,
       coalesce(ep.path, f.original_name) AS path
FROM files f
LEFT JOIN entry_paths ep ON ep.file_id = f.id AND ep.entry_type = 'file'
WHERE f.tenant_id = $1 AND f.protected_folder_id = $2 AND f.status = 'active'
ORDER BY coalesce(ep.path, f.original_name) ASC, f.id DESC`, tenantID, folderID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	files := []File{}
	for rows.Next() {
		file, err := s.scanFile(ctx, tenantID, rows)
		if err != nil {
			return nil, err
		}
		files = append(files, file)
	}
	return files, rows.Err()
}

func (s *Service) folderCollections(ctx context.Context, tenantID string, folderID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `
WITH RECURSIVE entry_paths AS (
  SELECT id, parent_entry_id, entry_type, name, name::text AS path
  FROM folder_entries
  WHERE tenant_id = $1 AND protected_folder_id = $2 AND parent_entry_id IS NULL
  UNION ALL
  SELECT child.id, child.parent_entry_id, child.entry_type, child.name, entry_paths.path || '/' || child.name
  FROM folder_entries child
  JOIN entry_paths ON entry_paths.id = child.parent_entry_id
  WHERE child.tenant_id = $1 AND child.protected_folder_id = $2
)
SELECT path
FROM entry_paths
WHERE entry_type = 'folder'
ORDER BY path ASC`, tenantID, folderID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	collections := []string{}
	for rows.Next() {
		var collection string
		if err := rows.Scan(&collection); err != nil {
			return nil, err
		}
		collection = strings.Trim(collection, "/")
		if collection != "" {
			collections = append(collections, collection)
		}
	}
	return collections, rows.Err()
}

func (s *Service) handleListFolderPermissions(w http.ResponseWriter, r *http.Request, folderID string) {
	actor, err := s.auth.CurrentUser(r)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, "not_authenticated")
		return
	}
	if !isUUIDLike(folderID) {
		s.writeError(w, http.StatusNotFound, "folder_not_found")
		return
	}
	if err := s.ensureFolderActive(r.Context(), actor.TenantID, folderID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			s.writeError(w, http.StatusNotFound, "folder_not_found")
			return
		}
		s.writeError(w, http.StatusInternalServerError, "folder_lookup_failed")
		return
	}
	permissions, err := s.folderPermissions(r.Context(), actor.TenantID, folderID)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "permissions_query_failed")
		return
	}
	writeJSON(w, http.StatusOK, permissionsResponse{Permissions: permissions})
}

func (s *Service) handleUpdateFolderPermission(w http.ResponseWriter, r *http.Request, folderID string) {
	actor, err := s.auth.CurrentUser(r)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, "not_authenticated")
		return
	}
	if !isUUIDLike(folderID) {
		s.writeError(w, http.StatusNotFound, "folder_not_found")
		return
	}
	if err := s.ensureFolderActive(r.Context(), actor.TenantID, folderID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			s.writeError(w, http.StatusNotFound, "folder_not_found")
			return
		}
		s.writeError(w, http.StatusInternalServerError, "folder_lookup_failed")
		return
	}

	var req updatePermissionRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	userID := strings.TrimSpace(req.UserID)
	if !isUUIDLike(userID) {
		s.writeError(w, http.StatusBadRequest, "user_id_required")
		return
	}
	if _, err := s.ensureClientUser(r.Context(), actor.TenantID, userID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			s.writeError(w, http.StatusNotFound, "client_user_not_found")
			return
		}
		s.writeError(w, http.StatusInternalServerError, "client_user_lookup_failed")
		return
	}
	access, err := normalizeAccess(req.CanUnlockAndAccess, req.ExpiresAt)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "expires_at_invalid")
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
INSERT INTO folder_permissions (
  tenant_id, user_id, protected_folder_id, can_unlock_and_access, expires_at, created_by
)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (user_id, protected_folder_id) DO UPDATE
SET can_unlock_and_access = EXCLUDED.can_unlock_and_access,
    expires_at = EXCLUDED.expires_at,
    created_by = EXCLUDED.created_by,
    updated_at = now()`,
		actor.TenantID, userID, folderID, access.CanUnlockAndAccess, access.ExpiresAt, actor.ID,
	); err != nil {
		s.writeError(w, http.StatusInternalServerError, "permission_update_failed")
		return
	}
	revokedSessions, canceledJobs, err := revokeAccessOnPermissionLossTx(r.Context(), tx, actor.TenantID, userID, folderID, access)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "permission_revoke_failed")
		return
	}
	if revokedSessions > 0 || canceledJobs > 0 {
		if err := promoteNextQueuedAccessJobTx(r.Context(), tx, actor.TenantID); err != nil {
			s.writeError(w, http.StatusInternalServerError, "queue_promote_failed")
			return
		}
	}
	if err := insertAuditEventTx(r.Context(), tx, actor.TenantID, actor.ID, "archive.permission.updated", "protected_folder", folderID, "info", clientIP(r), map[string]any{
		"user_id":               userID,
		"can_unlock_and_access": access.CanUnlockAndAccess,
		"expires_at_set":        access.ExpiresAt != nil,
		"revoked_sessions":      revokedSessions,
		"canceled_open_jobs":    canceledJobs,
	}); err != nil {
		s.writeError(w, http.StatusInternalServerError, "audit_failed")
		return
	}
	if err := tx.Commit(); err != nil {
		s.writeError(w, http.StatusInternalServerError, "transaction_commit_failed")
		return
	}

	permission, err := s.folderPermissionForUser(r.Context(), actor.TenantID, folderID, userID)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "permission_reload_failed")
		return
	}
	writeJSON(w, http.StatusOK, updatePermissionResponse{Permission: permission})
}

func (s *Service) handleListClientFolders(w http.ResponseWriter, r *http.Request) {
	user, err := s.auth.CurrentUser(r)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, "not_authenticated")
		return
	}
	if !s.kmsReady(r.Context(), w) {
		return
	}
	rows, err := s.db.QueryContext(r.Context(), `
SELECT
  pf.id::text,
  pf.name,
  coalesce(pf.description, ''),
  pf.status,
	  pf.pow_required_hashrate_ths::float8,
	  pf.pow_hashrate_tolerance_percent::float8,
	  pf.pow_proof_window_seconds,
	  pf.pow_max_proof_attempts,
  pf.pow_policy_seal,
  count(f.id)::int AS file_count,
  coalesce(sum(f.size_bytes), 0)::bigint AS total_bytes,
  fp.can_unlock_and_access,
  fp.expires_at
FROM folder_permissions fp
JOIN protected_folders pf ON pf.id = fp.protected_folder_id
LEFT JOIN files f ON f.protected_folder_id = pf.id
  AND f.status = 'active'
WHERE fp.tenant_id = $1
  AND fp.user_id = $2
  AND pf.status = 'active'
  AND fp.can_unlock_and_access = true
  AND (fp.expires_at IS NULL OR fp.expires_at > now())
GROUP BY pf.id, fp.can_unlock_and_access, fp.expires_at
ORDER BY pf.name ASC, pf.id DESC`, user.TenantID, user.ID)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "client_folders_query_failed")
		return
	}
	defer rows.Close()

	folders := []ClientFolder{}
	for rows.Next() {
		folder, err := s.scanClientFolder(r.Context(), user.TenantID, rows)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "client_folders_scan_failed")
			return
		}
		if _, err := s.activeAccessSessionID(r.Context(), user.TenantID, user.ID, folder.ID); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				folder.FileCount = 0
				folder.TotalBytes = 0
			} else {
				s.writeError(w, http.StatusInternalServerError, "access_session_lookup_failed")
				return
			}
		}
		folders = append(folders, folder)
	}
	if err := rows.Err(); err != nil {
		s.writeError(w, http.StatusInternalServerError, "client_folders_rows_failed")
		return
	}
	writeJSON(w, http.StatusOK, clientFoldersResponse{Folders: folders})
}

func (s *Service) handleListClientFiles(w http.ResponseWriter, r *http.Request, folderID string) {
	user, err := s.auth.CurrentUser(r)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, "not_authenticated")
		return
	}
	if !s.kmsReady(r.Context(), w) {
		return
	}
	if !isUUIDLike(folderID) {
		s.writeError(w, http.StatusNotFound, "folder_not_found")
		return
	}
	access, err := s.effectiveAccess(r.Context(), user.TenantID, user.ID, folderID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			s.writeError(w, http.StatusNotFound, "folder_not_found")
			return
		}
		s.writeError(w, http.StatusInternalServerError, "permission_lookup_failed")
		return
	}
	if !access.CanUnlockAndAccess {
		s.writeError(w, http.StatusNotFound, "folder_not_found")
		return
	}
	if _, err := s.activeAccessSessionID(r.Context(), user.TenantID, user.ID, folderID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			s.writeError(w, http.StatusForbidden, "access_session_required")
			return
		}
		s.writeError(w, http.StatusInternalServerError, "access_session_lookup_failed")
		return
	}

	rows, err := s.db.QueryContext(r.Context(), `
WITH RECURSIVE entry_paths AS (
  SELECT id, file_id, parent_entry_id, entry_type, name, name::text AS path
  FROM folder_entries
  WHERE tenant_id = $1 AND protected_folder_id = $2 AND parent_entry_id IS NULL
  UNION ALL
  SELECT child.id, child.file_id, child.parent_entry_id, child.entry_type, child.name, entry_paths.path || '/' || child.name
  FROM folder_entries child
  JOIN entry_paths ON entry_paths.id = child.parent_entry_id
  WHERE child.tenant_id = $1 AND child.protected_folder_id = $2
)
SELECT f.id::text, f.protected_folder_id::text, f.storage_object_id, f.original_name,
       f.plaintext_sha256, f.size_bytes, f.status, f.created_at, f.updated_at,
       coalesce(ep.path, f.original_name) AS path
FROM files f
LEFT JOIN entry_paths ep ON ep.file_id = f.id AND ep.entry_type = 'file'
WHERE f.tenant_id = $1
  AND f.protected_folder_id = $2
  AND f.status = 'active'
ORDER BY coalesce(ep.path, f.original_name) ASC, f.id DESC`, user.TenantID, folderID)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "client_files_query_failed")
		return
	}
	defer rows.Close()

	files := []ClientFile{}
	for rows.Next() {
		file, err := s.scanFile(r.Context(), user.TenantID, rows)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "client_files_scan_failed")
			return
		}
		files = append(files, ClientFile{
			ID:              file.ID,
			FolderID:        file.FolderID,
			Name:            file.Name,
			Path:            file.Path,
			SizeBytes:       file.SizeBytes,
			PlaintextSHA256: file.PlaintextSHA256,
			Status:          file.Status,
		})
	}
	if err := rows.Err(); err != nil {
		s.writeError(w, http.StatusInternalServerError, "client_files_rows_failed")
		return
	}
	writeJSON(w, http.StatusOK, clientFilesResponse{Files: files})
}

func (s *Service) handleDownloadClientFile(w http.ResponseWriter, r *http.Request, fileID string) {
	user, err := s.auth.CurrentUser(r)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, "not_authenticated")
		return
	}
	if !s.kmsReady(r.Context(), w) {
		return
	}
	if !isUUIDLike(fileID) {
		s.writeError(w, http.StatusNotFound, "file_not_found")
		return
	}
	record, err := s.fileRecordByID(r.Context(), user.TenantID, fileID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			s.writeError(w, http.StatusNotFound, "file_not_found")
			return
		}
		s.writeError(w, http.StatusInternalServerError, "file_lookup_failed")
		return
	}
	access, err := s.effectiveAccess(r.Context(), user.TenantID, user.ID, record.FolderID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			s.writeError(w, http.StatusNotFound, "file_not_found")
			return
		}
		s.writeError(w, http.StatusInternalServerError, "permission_lookup_failed")
		return
	}
	if !access.CanUnlockAndAccess {
		s.writeError(w, http.StatusForbidden, "download_not_allowed")
		return
	}
	sessionID, err := s.activeAccessSessionID(r.Context(), user.TenantID, user.ID, record.FolderID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			s.writeError(w, http.StatusForbidden, "access_session_required")
			return
		}
		s.writeError(w, http.StatusInternalServerError, "access_session_lookup_failed")
		return
	}

	temp, err := os.CreateTemp("", "archivon-download-*")
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "download_temp_create_failed")
		return
	}
	tempPath := temp.Name()
	defer func() {
		_ = temp.Close()
		_ = os.Remove(tempPath)
	}()
	if err := s.copyStoredFileToWriter(r.Context(), record, temp); err != nil {
		if s.logger != nil {
			s.logger.Warn("file read failed", "file_id", fileID, "error", err)
		}
		s.writeError(w, http.StatusInternalServerError, "file_read_failed")
		return
	}
	if _, err := temp.Seek(0, io.SeekStart); err != nil {
		s.writeError(w, http.StatusInternalServerError, "download_temp_seek_failed")
		return
	}
	if err := insertAuditEvent(r.Context(), s.db, user.TenantID, user.ID, "archive.file.downloaded", "file", fileID, "critical", clientIP(r), map[string]any{
		"folder_id":         record.FolderID,
		"access_session_id": sessionID,
		"size_bytes":        record.SizeBytes,
		"plaintext_sha256":  record.PlaintextSHA256,
	}); err != nil {
		s.writeError(w, http.StatusInternalServerError, "audit_failed")
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": record.Name}))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", record.SizeBytes))
	if _, err := io.Copy(w, temp); err != nil && s.logger != nil {
		s.logger.Warn("file download stream failed", "file_id", fileID, "error", err)
	}
}

func (s *Service) handleDAVPropfind(w http.ResponseWriter, r *http.Request, session davSession, parts []string) {
	files, err := s.davFiles(r.Context(), session)
	if err != nil {
		s.writeDAVError(w, err)
		return
	}
	rootHref := davRootHref(r, "/dav/", session.DavUsername)
	displayPaths := davDisplayPaths(files)
	relativePath := strings.Join(parts, "/")
	if relativePath != "" {
		file, displayPath, found := davFindFile(files, displayPaths, relativePath)
		if found {
			writeDAVMultiStatus(w, []davXMLResponse{davFileXMLResponse(davResourceHref(rootHref, displayPath, false), path.Base(displayPath), file)})
			return
		}
		if !davCollectionExists(displayPaths, relativePath) {
			writeDAVError(w, http.StatusNotFound, "not_found")
			return
		}
	}

	responses := []davXMLResponse{davCollectionXMLResponse(davResourceHref(rootHref, relativePath, true), davCollectionDisplayName(relativePath))}
	if strings.TrimSpace(r.Header.Get("Depth")) != "0" {
		childCollections, childFiles := davImmediateChildren(files, displayPaths, relativePath)
		for _, child := range childCollections {
			responses = append(responses, davCollectionXMLResponse(davResourceHref(rootHref, child, true), path.Base(child)))
		}
		for _, file := range childFiles {
			displayPath := displayPaths[file.ID]
			responses = append(responses, davFileXMLResponse(davResourceHref(rootHref, displayPath, false), path.Base(displayPath), file))
		}
	}
	writeDAVMultiStatus(w, responses)
}

func (s *Service) handleDAVRead(w http.ResponseWriter, r *http.Request, session davSession, parts []string) {
	if len(parts) == 0 {
		writeDAVError(w, http.StatusNotFound, "not_found")
		return
	}
	files, err := s.davFiles(r.Context(), session)
	if err != nil {
		s.writeDAVError(w, err)
		return
	}
	displayPaths := davDisplayPaths(files)
	requestedPath := strings.Join(parts, "/")
	file, displayPath, found := davFindFile(files, displayPaths, requestedPath)
	if !found {
		writeDAVError(w, http.StatusNotFound, "not_found")
		return
	}
	record, err := s.fileRecordByID(r.Context(), session.TenantID, file.ID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeDAVError(w, http.StatusNotFound, "not_found")
			return
		}
		writeDAVError(w, http.StatusInternalServerError, "file_lookup_failed")
		return
	}
	etag := `"` + record.PlaintextSHA256 + `"`
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("ETag", etag)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.Method == http.MethodHead {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", record.SizeBytes))
		w.WriteHeader(http.StatusOK)
		return
	}
	temp, err := os.CreateTemp("", "archivon-webdav-*")
	if err != nil {
		writeDAVError(w, http.StatusInternalServerError, "webdav_temp_create_failed")
		return
	}
	tempPath := temp.Name()
	defer func() {
		_ = temp.Close()
		_ = os.Remove(tempPath)
	}()
	if err := s.copyStoredFileToWriter(r.Context(), record, temp); err != nil {
		if s.logger != nil {
			s.logger.Warn("webdav file read failed", "file_id", record.ID, "error", err)
		}
		writeDAVError(w, http.StatusInternalServerError, "file_read_failed")
		return
	}
	if _, err := temp.Seek(0, io.SeekStart); err != nil {
		writeDAVError(w, http.StatusInternalServerError, "webdav_temp_seek_failed")
		return
	}
	if err := insertAuditEvent(r.Context(), s.db, session.TenantID, session.UserID, "archive.file.downloaded", "file", record.ID, "critical", clientIP(r), map[string]any{
		"folder_id":         record.FolderID,
		"access_session_id": session.ID,
		"size_bytes":        record.SizeBytes,
		"plaintext_sha256":  record.PlaintextSHA256,
		"via":               "webdav",
	}); err != nil {
		writeDAVError(w, http.StatusInternalServerError, "audit_failed")
		return
	}
	http.ServeContent(w, r, path.Base(displayPath), time.Time{}, temp)
}

func (s *Service) handleAdminDAVPropfind(w http.ResponseWriter, r *http.Request, session adminDAVSession, parts []string) {
	files, err := s.adminDAVFiles(r.Context(), session)
	if err != nil {
		s.writeDAVError(w, err)
		return
	}
	collections, err := s.adminDAVCollections(r.Context(), session)
	if err != nil {
		s.writeDAVError(w, err)
		return
	}
	rootHref := davRootHref(r, "/admin-dav/", session.DavUsername)
	displayPaths := davDisplayPaths(files)
	relativePath := strings.Join(parts, "/")
	if relativePath != "" {
		file, displayPath, found := davFindFile(files, displayPaths, relativePath)
		if found {
			writeDAVMultiStatus(w, []davXMLResponse{davFileXMLResponse(davResourceHref(rootHref, displayPath, false), path.Base(displayPath), file)})
			return
		}
		if !davCollectionExistsWith(collections, displayPaths, relativePath) {
			writeDAVError(w, http.StatusNotFound, "not_found")
			return
		}
	}

	responses := []davXMLResponse{davCollectionXMLResponse(davResourceHref(rootHref, relativePath, true), davCollectionDisplayName(relativePath))}
	if strings.TrimSpace(r.Header.Get("Depth")) != "0" {
		childCollections, childFiles := davImmediateChildrenWith(files, displayPaths, collections, relativePath)
		for _, child := range childCollections {
			responses = append(responses, davCollectionXMLResponse(davResourceHref(rootHref, child, true), path.Base(child)))
		}
		for _, file := range childFiles {
			displayPath := displayPaths[file.ID]
			responses = append(responses, davFileXMLResponse(davResourceHref(rootHref, displayPath, false), path.Base(displayPath), file))
		}
	}
	writeDAVMultiStatus(w, responses)
}

func (s *Service) handleAdminDAVRead(w http.ResponseWriter, r *http.Request, session adminDAVSession, parts []string) {
	if len(parts) == 0 {
		writeDAVError(w, http.StatusNotFound, "not_found")
		return
	}
	files, err := s.adminDAVFiles(r.Context(), session)
	if err != nil {
		s.writeDAVError(w, err)
		return
	}
	displayPaths := davDisplayPaths(files)
	requestedPath := strings.Join(parts, "/")
	file, displayPath, found := davFindFile(files, displayPaths, requestedPath)
	if !found {
		writeDAVError(w, http.StatusNotFound, "not_found")
		return
	}
	record, err := s.fileRecordByID(r.Context(), session.TenantID, file.ID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeDAVError(w, http.StatusNotFound, "not_found")
			return
		}
		writeDAVError(w, http.StatusInternalServerError, "file_lookup_failed")
		return
	}
	etag := `"` + record.PlaintextSHA256 + `"`
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("ETag", etag)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.Method == http.MethodHead {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", record.SizeBytes))
		w.WriteHeader(http.StatusOK)
		return
	}
	temp, err := os.CreateTemp("", "archivon-admin-webdav-*")
	if err != nil {
		writeDAVError(w, http.StatusInternalServerError, "webdav_temp_create_failed")
		return
	}
	tempPath := temp.Name()
	defer func() {
		_ = temp.Close()
		_ = os.Remove(tempPath)
	}()
	if err := s.copyStoredFileToWriter(r.Context(), record, temp); err != nil {
		if s.logger != nil {
			s.logger.Warn("admin webdav file read failed", "file_id", record.ID, "error", err)
		}
		writeDAVError(w, http.StatusInternalServerError, "file_read_failed")
		return
	}
	if _, err := temp.Seek(0, io.SeekStart); err != nil {
		writeDAVError(w, http.StatusInternalServerError, "webdav_temp_seek_failed")
		return
	}
	if err := insertAuditEvent(r.Context(), s.db, session.TenantID, session.UserID, "archive.file.downloaded", "file", record.ID, "critical", clientIP(r), map[string]any{
		"folder_id":        record.FolderID,
		"admin_dav_id":     session.ID,
		"size_bytes":       record.SizeBytes,
		"plaintext_sha256": record.PlaintextSHA256,
		"via":              "admin_webdav",
	}); err != nil {
		writeDAVError(w, http.StatusInternalServerError, "audit_failed")
		return
	}
	http.ServeContent(w, r, path.Base(displayPath), time.Time{}, temp)
}

func (s *Service) handleAdminDAVPut(w http.ResponseWriter, r *http.Request, session adminDAVSession, parts []string) {
	if len(parts) == 0 || strings.HasSuffix(r.URL.EscapedPath(), "/") {
		writeDAVError(w, http.StatusConflict, "file_path_required")
		return
	}
	entryPath := strings.Join(parts, "/")
	originalName := parts[len(parts)-1]
	parentSegments := parts[:len(parts)-1]

	fileID, err := newUUID()
	if err != nil {
		writeDAVError(w, http.StatusInternalServerError, "file_id_failed")
		return
	}
	entryID, err := newUUID()
	if err != nil {
		writeDAVError(w, http.StatusInternalServerError, "entry_id_failed")
		return
	}
	storageObjectID, err := newStorageObjectID()
	if err != nil {
		writeDAVError(w, http.StatusInternalServerError, "storage_object_id_failed")
		return
	}
	objectDir := s.objectDir(storageObjectID)
	if err := os.MkdirAll(objectDir, 0700); err != nil {
		if s.logger != nil {
			s.logger.Warn("admin webdav storage object directory create failed", "relative_path", entryPath, "error", err)
		}
		writeDAVError(w, http.StatusInternalServerError, "storage_object_create_failed")
		return
	}
	cleanupObject := true
	defer func() {
		if cleanupObject {
			_ = os.RemoveAll(objectDir)
		}
	}()

	plaintextSHA, sizeBytes, err := s.writeUploadToStorage(r.Context(), r.Body, objectDir)
	if err != nil {
		if s.logger != nil {
			s.logger.Warn("admin webdav file storage write failed", "relative_path", entryPath, "error", err)
		}
		writeDAVError(w, http.StatusInternalServerError, "file_store_failed")
		return
	}

	var replacedFileID string
	replacedStorageObjectIDs := []string{}
	if files, err := s.adminDAVFiles(r.Context(), session); err == nil {
		displayPaths := davDisplayPaths(files)
		if existing, _, found := davFindFile(files, displayPaths, entryPath); found {
			replacedFileID = existing.ID
		}
	} else if s.logger != nil {
		s.logger.Warn("admin webdav existing file lookup failed", "relative_path", entryPath, "error", err)
	}

	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		writeDAVError(w, http.StatusInternalServerError, "transaction_failed")
		return
	}
	defer func() {
		_ = tx.Rollback()
	}()
	parentEntryID, err := ensureFolderEntryPathTx(r.Context(), tx, session.TenantID, session.FolderID, parentSegments)
	if err != nil {
		if s.logger != nil {
			s.logger.Warn("admin webdav folder path create failed", "relative_path", entryPath, "error", err)
		}
		writeDAVError(w, http.StatusInternalServerError, "folder_path_create_failed")
		return
	}
	if replacedFileID != "" {
		storageObjectID, err := deleteFileTx(r.Context(), tx, session.TenantID, replacedFileID)
		if err != nil {
			writeDAVError(w, http.StatusInternalServerError, "file_replace_failed")
			return
		}
		replacedStorageObjectIDs = append(replacedStorageObjectIDs, storageObjectID)
	}
	if _, err := tx.ExecContext(r.Context(), `
INSERT INTO files (
  id, tenant_id, protected_folder_id, storage_object_id, original_name,
  plaintext_sha256, size_bytes, created_by
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		fileID, session.TenantID, session.FolderID, storageObjectID, originalName, plaintextSHA, sizeBytes, session.UserID,
	); err != nil {
		if s.logger != nil {
			s.logger.Warn("admin webdav file record create failed", "relative_path", entryPath, "size_bytes", sizeBytes, "error", err)
		}
		writeDAVError(w, http.StatusInternalServerError, "file_record_create_failed")
		return
	}
	if _, err := tx.ExecContext(r.Context(), `
INSERT INTO folder_entries (
  id, tenant_id, protected_folder_id, parent_entry_id, entry_type, name, file_id
)
VALUES ($1, $2, $3, $4, 'file', $5, $6)`,
		entryID, session.TenantID, session.FolderID, nullableStringPtr(parentEntryID), originalName, fileID,
	); err != nil {
		if s.logger != nil {
			s.logger.Warn("admin webdav folder entry create failed", "relative_path", entryPath, "error", err)
		}
		writeDAVError(w, http.StatusInternalServerError, "folder_entry_create_failed")
		return
	}
	if err := insertAuditEventTx(r.Context(), tx, session.TenantID, session.UserID, "archive.file.uploaded", "file", fileID, "info", clientIP(r), map[string]any{
		"folder_id":         session.FolderID,
		"file_name":         originalName,
		"relative_path":     entryPath,
		"size_bytes":        sizeBytes,
		"plaintext_sha256":  plaintextSHA,
		"storage_object_id": storageObjectID,
		"admin_dav_id":      session.ID,
		"via":               "admin_webdav",
		"replaced_file_id":  replacedFileID,
	}); err != nil {
		writeDAVError(w, http.StatusInternalServerError, "audit_failed")
		return
	}
	if err := tx.Commit(); err != nil {
		writeDAVError(w, http.StatusInternalServerError, "transaction_commit_failed")
		return
	}
	cleanupObject = false
	s.removeStorageObjects(replacedStorageObjectIDs)

	w.Header().Set("ETag", `"`+plaintextSHA+`"`)
	if replacedFileID != "" {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (s *Service) handleAdminDAVMkcol(w http.ResponseWriter, r *http.Request, session adminDAVSession, parts []string) {
	if len(parts) == 0 {
		writeDAVError(w, http.StatusMethodNotAllowed, "root_collection_exists")
		return
	}
	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		writeDAVError(w, http.StatusInternalServerError, "transaction_failed")
		return
	}
	defer func() {
		_ = tx.Rollback()
	}()
	if _, err := ensureFolderEntryPathTx(r.Context(), tx, session.TenantID, session.FolderID, parts); err != nil {
		writeDAVError(w, http.StatusInternalServerError, "folder_path_create_failed")
		return
	}
	if err := insertAuditEventTx(r.Context(), tx, session.TenantID, session.UserID, "archive.folder_entry.created", "protected_folder", session.FolderID, "info", clientIP(r), map[string]any{
		"relative_path": strings.Join(parts, "/"),
		"admin_dav_id":  session.ID,
		"via":           "admin_webdav",
	}); err != nil {
		writeDAVError(w, http.StatusInternalServerError, "audit_failed")
		return
	}
	if err := tx.Commit(); err != nil {
		writeDAVError(w, http.StatusInternalServerError, "transaction_commit_failed")
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (s *Service) importFolderBackup(ctx context.Context, actor auth.User, source multipart.File, header *multipart.FileHeader, requestIP string) (importFolderBackupResponse, error) {
	if header == nil || strings.TrimSpace(header.Filename) == "" {
		return importFolderBackupResponse{}, davHTTPError{status: http.StatusBadRequest, code: "backup_file_required"}
	}
	temp, err := os.CreateTemp("", "archivon-folder-backup-*.zip")
	if err != nil {
		return importFolderBackupResponse{}, err
	}
	tempPath := temp.Name()
	defer func() {
		_ = os.Remove(tempPath)
	}()
	if _, err := io.Copy(temp, source); err != nil {
		_ = temp.Close()
		return importFolderBackupResponse{}, err
	}
	if err := temp.Close(); err != nil {
		return importFolderBackupResponse{}, err
	}

	archive, err := zip.OpenReader(tempPath)
	if err != nil {
		return importFolderBackupResponse{}, davHTTPError{status: http.StatusBadRequest, code: "backup_zip_invalid"}
	}
	defer archive.Close()

	filesByName := map[string]*zip.File{}
	for _, file := range archive.File {
		filesByName[file.Name] = file
	}
	manifestFile := filesByName[folderBackupManifestName]
	if manifestFile == nil {
		return importFolderBackupResponse{}, davHTTPError{status: http.StatusBadRequest, code: "backup_manifest_missing"}
	}
	manifestSource, err := manifestFile.Open()
	if err != nil {
		return importFolderBackupResponse{}, err
	}
	var manifest folderBackupManifest
	if err := json.NewDecoder(io.LimitReader(manifestSource, 8*1024*1024)).Decode(&manifest); err != nil {
		_ = manifestSource.Close()
		return importFolderBackupResponse{}, davHTTPError{status: http.StatusBadRequest, code: "backup_manifest_invalid"}
	}
	_ = manifestSource.Close()
	if manifest.Format != folderBackupFormat || manifest.Version != folderBackupVersion {
		return importFolderBackupResponse{}, davHTTPError{status: http.StatusBadRequest, code: "backup_format_unsupported"}
	}
	folderName := restoredFolderName(manifest.Folder.Name)
	if folderName == "" {
		return importFolderBackupResponse{}, davHTTPError{status: http.StatusBadRequest, code: "backup_folder_name_invalid"}
	}
	powPolicy := normalizeFolderPoWPolicy(manifest.Folder.PoWPolicy, FolderPoWPolicy{})
	if err := validateFolderPoWPolicy(powPolicy); err != nil {
		return importFolderBackupResponse{}, davHTTPError{status: http.StatusBadRequest, code: "backup_pow_policy_invalid"}
	}

	folderID, err := newUUID()
	if err != nil {
		return importFolderBackupResponse{}, err
	}
	policySeal, err := s.folderPoWPolicySeal(ctx, actor.TenantID, folderID, powPolicy)
	if err != nil {
		return importFolderBackupResponse{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return importFolderBackupResponse{}, err
	}
	createdStorageObjectIDs := []string{}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
			s.removeStorageObjects(createdStorageObjectIDs)
		}
	}()

	if _, err := tx.ExecContext(ctx, `
INSERT INTO protected_folders (
  id, tenant_id, name, description,
  pow_required_hashrate_ths, pow_hashrate_tolerance_percent, pow_proof_window_seconds,
  pow_max_proof_attempts, pow_policy_seal, created_by
)
VALUES ($1, $2, $3, nullif($4, ''), $5, $6, $7, $8, $9, $10)`,
		folderID,
		actor.TenantID,
		folderName,
		manifest.Folder.Description,
		powPolicy.RequiredHashrateTHs,
		powPolicy.HashrateTolerancePercent,
		powPolicy.ProofWindowSeconds,
		powPolicy.MaxProofAttempts,
		policySeal,
		actor.ID,
	); err != nil {
		return importFolderBackupResponse{}, err
	}

	importedCollections := 0
	for _, collection := range manifest.Collections {
		segments, err := cleanFolderCollectionPath(collection)
		if err != nil {
			return importFolderBackupResponse{}, davHTTPError{status: http.StatusBadRequest, code: "backup_collection_path_invalid"}
		}
		if len(segments) == 0 {
			continue
		}
		if _, err := ensureFolderEntryPathTx(ctx, tx, actor.TenantID, folderID, segments); err != nil {
			return importFolderBackupResponse{}, err
		}
		importedCollections++
	}

	for _, item := range manifest.Files {
		if strings.TrimSpace(item.ArchivePath) == "" || !strings.HasPrefix(item.ArchivePath, "content/") {
			return importFolderBackupResponse{}, davHTTPError{status: http.StatusBadRequest, code: "backup_file_archive_path_invalid"}
		}
		zipFile := filesByName[item.ArchivePath]
		if zipFile == nil || zipFile.FileInfo().IsDir() {
			return importFolderBackupResponse{}, davHTTPError{status: http.StatusBadRequest, code: "backup_file_missing"}
		}
		uploadPath, err := cleanUploadPath(item.Path, item.Name)
		if err != nil {
			return importFolderBackupResponse{}, davHTTPError{status: http.StatusBadRequest, code: "backup_file_path_invalid"}
		}
		originalName := uploadPath[len(uploadPath)-1]
		parentSegments := uploadPath[:len(uploadPath)-1]

		fileID, err := newUUID()
		if err != nil {
			return importFolderBackupResponse{}, err
		}
		entryID, err := newUUID()
		if err != nil {
			return importFolderBackupResponse{}, err
		}
		storageObjectID, err := newStorageObjectID()
		if err != nil {
			return importFolderBackupResponse{}, err
		}
		objectDir := s.objectDir(storageObjectID)
		if err := os.MkdirAll(objectDir, 0700); err != nil {
			return importFolderBackupResponse{}, err
		}
		createdStorageObjectIDs = append(createdStorageObjectIDs, storageObjectID)
		fileSource, err := zipFile.Open()
		if err != nil {
			return importFolderBackupResponse{}, err
		}
		plaintextSHA, sizeBytes, err := s.writeUploadToStorage(ctx, fileSource, objectDir)
		_ = fileSource.Close()
		if err != nil {
			return importFolderBackupResponse{}, err
		}
		if sizeBytes != item.SizeBytes || !strings.EqualFold(plaintextSHA, item.PlaintextSHA256) {
			return importFolderBackupResponse{}, davHTTPError{status: http.StatusBadRequest, code: "backup_file_checksum_mismatch"}
		}
		parentEntryID, err := ensureFolderEntryPathTx(ctx, tx, actor.TenantID, folderID, parentSegments)
		if err != nil {
			return importFolderBackupResponse{}, err
		}
		if _, err := tx.ExecContext(ctx, `
INSERT INTO files (
  id, tenant_id, protected_folder_id, storage_object_id, original_name,
  plaintext_sha256, size_bytes, created_by
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
			fileID, actor.TenantID, folderID, storageObjectID, originalName, plaintextSHA, sizeBytes, actor.ID,
		); err != nil {
			return importFolderBackupResponse{}, err
		}
		if _, err := tx.ExecContext(ctx, `
INSERT INTO folder_entries (
  id, tenant_id, protected_folder_id, parent_entry_id, entry_type, name, file_id
)
VALUES ($1, $2, $3, $4, 'file', $5, $6)`,
			entryID, actor.TenantID, folderID, nullableStringPtr(parentEntryID), originalName, fileID,
		); err != nil {
			return importFolderBackupResponse{}, err
		}
	}

	if err := insertAuditEventTx(ctx, tx, actor.TenantID, actor.ID, "archive.folder.backup_imported", "protected_folder", folderID, "warning", requestIP, map[string]any{
		"source_folder_name": manifest.Folder.Name,
		"folder_name":        folderName,
		"file_count":         len(manifest.Files),
		"collection_count":   importedCollections,
	}); err != nil {
		return importFolderBackupResponse{}, err
	}
	if err := tx.Commit(); err != nil {
		return importFolderBackupResponse{}, err
	}
	committed = true

	folder, err := s.folderByID(ctx, actor.TenantID, folderID)
	if err != nil {
		return importFolderBackupResponse{}, err
	}
	return importFolderBackupResponse{
		Folder:              folder,
		ImportedFiles:       len(manifest.Files),
		ImportedCollections: importedCollections,
	}, nil
}

func (s *Service) writeUploadToStorage(ctx context.Context, source io.Reader, objectDir string) (string, int64, error) {
	_ = ctx
	dataPath := filepath.Join(objectDir, "data")
	destination, err := os.OpenFile(dataPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return "", 0, err
	}
	defer destination.Close()

	hasher := sha256.New()
	size, err := io.Copy(io.MultiWriter(destination, hasher), source)
	if err != nil {
		return "", 0, err
	}
	if err := destination.Sync(); err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(hasher.Sum(nil)), size, nil
}

func (s *Service) copyStoredFileToWriter(ctx context.Context, record fileRecord, destination io.Writer) error {
	_ = ctx
	dataPath := filepath.Join(s.objectDir(record.StorageObjectID), "data")
	source, err := os.Open(dataPath)
	if err != nil {
		return err
	}
	defer source.Close()

	hasher := sha256.New()
	written, err := io.Copy(io.MultiWriter(destination, hasher), source)
	if err != nil {
		return err
	}
	if written != record.SizeBytes {
		return errors.New("plaintext_size_mismatch")
	}
	if hex.EncodeToString(hasher.Sum(nil)) != record.PlaintextSHA256 {
		return errors.New("plaintext_sha256_mismatch")
	}
	return nil
}

func (s *Service) authenticateDAV(ctx context.Context, w http.ResponseWriter, r *http.Request) (davSession, bool) {
	username, password, ok := r.BasicAuth()
	if !ok || strings.TrimSpace(username) == "" || strings.TrimSpace(password) == "" {
		writeDAVUnauthorized(w)
		return davSession{}, false
	}
	var session davSession
	err := s.db.QueryRowContext(ctx, `
SELECT s.id::text, s.tenant_id::text, s.user_id::text, s.protected_folder_id::text,
       s.dav_username, s.dav_password_hash, s.expires_at
FROM access_sessions s
JOIN users u ON u.id = s.user_id
WHERE s.dav_username = $1
  AND s.status = 'active'
  AND s.expires_at > now()
  AND s.dav_password_hash IS NOT NULL
  AND u.is_blocked = false
LIMIT 1`, strings.TrimSpace(username)).Scan(
		&session.ID,
		&session.TenantID,
		&session.UserID,
		&session.FolderID,
		&session.DavUsername,
		&session.PasswordHash,
		&session.ExpiresAt,
	)
	if err != nil {
		writeDAVUnauthorized(w)
		return davSession{}, false
	}
	if bcrypt.CompareHashAndPassword([]byte(session.PasswordHash), []byte(password)) != nil {
		writeDAVUnauthorized(w)
		return davSession{}, false
	}
	return session, true
}

func (s *Service) authenticateAdminDAV(ctx context.Context, w http.ResponseWriter, r *http.Request) (adminDAVSession, bool) {
	username, password, ok := r.BasicAuth()
	if !ok || strings.TrimSpace(username) == "" || strings.TrimSpace(password) == "" {
		writeDAVUnauthorized(w)
		return adminDAVSession{}, false
	}
	var session adminDAVSession
	err := s.db.QueryRowContext(ctx, `
SELECT s.id::text, s.tenant_id::text, s.user_id::text, s.protected_folder_id::text,
       s.dav_username, s.dav_password_hash, s.expires_at
FROM admin_dav_sessions s
JOIN users u ON u.id = s.user_id
JOIN protected_folders pf ON pf.id = s.protected_folder_id
WHERE s.dav_username = $1
  AND s.status = 'active'
  AND s.expires_at > now()
  AND u.is_blocked = false
  AND u.role IN ('super_admin', 'admin')
  AND pf.status = 'active'
LIMIT 1`, strings.TrimSpace(username)).Scan(
		&session.ID,
		&session.TenantID,
		&session.UserID,
		&session.FolderID,
		&session.DavUsername,
		&session.PasswordHash,
		&session.ExpiresAt,
	)
	if err != nil {
		writeDAVUnauthorized(w)
		return adminDAVSession{}, false
	}
	if bcrypt.CompareHashAndPassword([]byte(session.PasswordHash), []byte(password)) != nil {
		writeDAVUnauthorized(w)
		return adminDAVSession{}, false
	}
	return session, true
}

func (s *Service) davFiles(ctx context.Context, session davSession) ([]File, error) {
	access, err := s.effectiveAccess(ctx, session.TenantID, session.UserID, session.FolderID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, davHTTPError{status: http.StatusNotFound, code: "not_found"}
		}
		return nil, err
	}
	if !access.CanUnlockAndAccess {
		return nil, davHTTPError{status: http.StatusNotFound, code: "not_found"}
	}
	rows, err := s.db.QueryContext(ctx, `
WITH RECURSIVE entry_paths AS (
  SELECT id, file_id, parent_entry_id, entry_type, name, name::text AS path
  FROM folder_entries
  WHERE tenant_id = $1 AND protected_folder_id = $2 AND parent_entry_id IS NULL
  UNION ALL
  SELECT child.id, child.file_id, child.parent_entry_id, child.entry_type, child.name, entry_paths.path || '/' || child.name
  FROM folder_entries child
  JOIN entry_paths ON entry_paths.id = child.parent_entry_id
  WHERE child.tenant_id = $1 AND child.protected_folder_id = $2
)
SELECT f.id::text, f.protected_folder_id::text, f.storage_object_id, f.original_name,
       f.plaintext_sha256, f.size_bytes, f.status, f.created_at, f.updated_at,
       coalesce(ep.path, f.original_name) AS path
FROM files f
LEFT JOIN entry_paths ep ON ep.file_id = f.id AND ep.entry_type = 'file'
WHERE f.tenant_id = $1
  AND f.protected_folder_id = $2
  AND f.status = 'active'
ORDER BY coalesce(ep.path, f.original_name) ASC, f.id DESC`, session.TenantID, session.FolderID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	files := []File{}
	for rows.Next() {
		file, err := s.scanFile(ctx, session.TenantID, rows)
		if err != nil {
			return nil, err
		}
		files = append(files, file)
	}
	return files, rows.Err()
}

func (s *Service) adminDAVFiles(ctx context.Context, session adminDAVSession) ([]File, error) {
	if err := s.ensureFolderActive(ctx, session.TenantID, session.FolderID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, davHTTPError{status: http.StatusNotFound, code: "not_found"}
		}
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `
WITH RECURSIVE entry_paths AS (
  SELECT id, file_id, parent_entry_id, entry_type, name, name::text AS path
  FROM folder_entries
  WHERE tenant_id = $1 AND protected_folder_id = $2 AND parent_entry_id IS NULL
  UNION ALL
  SELECT child.id, child.file_id, child.parent_entry_id, child.entry_type, child.name, entry_paths.path || '/' || child.name
  FROM folder_entries child
  JOIN entry_paths ON entry_paths.id = child.parent_entry_id
  WHERE child.tenant_id = $1 AND child.protected_folder_id = $2
)
SELECT f.id::text, f.protected_folder_id::text, f.storage_object_id, f.original_name,
       f.plaintext_sha256, f.size_bytes, f.status, f.created_at, f.updated_at,
       coalesce(ep.path, f.original_name) AS path
FROM files f
LEFT JOIN entry_paths ep ON ep.file_id = f.id AND ep.entry_type = 'file'
WHERE f.tenant_id = $1
  AND f.protected_folder_id = $2
  AND f.status = 'active'
ORDER BY coalesce(ep.path, f.original_name) ASC, f.id DESC`, session.TenantID, session.FolderID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	files := []File{}
	for rows.Next() {
		file, err := s.scanFile(ctx, session.TenantID, rows)
		if err != nil {
			return nil, err
		}
		files = append(files, file)
	}
	return files, rows.Err()
}

func (s *Service) adminDAVCollections(ctx context.Context, session adminDAVSession) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `
WITH RECURSIVE entry_paths AS (
  SELECT id, parent_entry_id, entry_type, name, name::text AS path
  FROM folder_entries
  WHERE tenant_id = $1 AND protected_folder_id = $2 AND parent_entry_id IS NULL
  UNION ALL
  SELECT child.id, child.parent_entry_id, child.entry_type, child.name, entry_paths.path || '/' || child.name
  FROM folder_entries child
  JOIN entry_paths ON entry_paths.id = child.parent_entry_id
  WHERE child.tenant_id = $1 AND child.protected_folder_id = $2
)
SELECT path
FROM entry_paths
WHERE entry_type = 'folder'
ORDER BY path ASC`, session.TenantID, session.FolderID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	collections := []string{}
	for rows.Next() {
		var collection string
		if err := rows.Scan(&collection); err != nil {
			return nil, err
		}
		collection = strings.Trim(collection, "/")
		if collection != "" {
			collections = append(collections, collection)
		}
	}
	return collections, rows.Err()
}

type davXMLResponse struct {
	Href          string
	DisplayName   string
	Collection    bool
	ContentLength int64
	ContentType   string
	LastModified  *time.Time
	ETag          string
}

func davCollectionXMLResponse(href string, displayName string) davXMLResponse {
	return davXMLResponse{
		Href:        href,
		DisplayName: displayName,
		Collection:  true,
	}
}

func davFileXMLResponse(href string, displayName string, file File) davXMLResponse {
	return davXMLResponse{
		Href:          href,
		DisplayName:   displayName,
		Collection:    false,
		ContentLength: file.SizeBytes,
		ContentType:   "application/octet-stream",
		LastModified:  &file.UpdatedAt,
		ETag:          `"` + file.PlaintextSHA256 + `"`,
	}
}

func writeDAVMultiStatus(w http.ResponseWriter, responses []davXMLResponse) {
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.WriteHeader(207)
	var buffer bytes.Buffer
	buffer.WriteString(`<?xml version="1.0" encoding="utf-8"?>`)
	buffer.WriteString(`<D:multistatus xmlns:D="DAV:">`)
	for _, response := range responses {
		buffer.WriteString(`<D:response><D:href>`)
		writeXMLEscaped(&buffer, response.Href)
		buffer.WriteString(`</D:href><D:propstat><D:prop>`)
		buffer.WriteString(`<D:displayname>`)
		writeXMLEscaped(&buffer, response.DisplayName)
		buffer.WriteString(`</D:displayname>`)
		buffer.WriteString(`<D:resourcetype>`)
		if response.Collection {
			buffer.WriteString(`<D:collection/>`)
		}
		buffer.WriteString(`</D:resourcetype>`)
		if !response.Collection {
			buffer.WriteString(`<D:getcontentlength>`)
			buffer.WriteString(fmt.Sprintf("%d", response.ContentLength))
			buffer.WriteString(`</D:getcontentlength>`)
			buffer.WriteString(`<D:getcontenttype>`)
			writeXMLEscaped(&buffer, response.ContentType)
			buffer.WriteString(`</D:getcontenttype>`)
			buffer.WriteString(`<D:getetag>`)
			writeXMLEscaped(&buffer, response.ETag)
			buffer.WriteString(`</D:getetag>`)
		}
		if response.LastModified != nil {
			buffer.WriteString(`<D:getlastmodified>`)
			writeXMLEscaped(&buffer, response.LastModified.UTC().Format(http.TimeFormat))
			buffer.WriteString(`</D:getlastmodified>`)
		}
		buffer.WriteString(`</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>`)
	}
	buffer.WriteString(`</D:multistatus>`)
	_, _ = w.Write(buffer.Bytes())
}

func writeXMLEscaped(buffer *bytes.Buffer, value string) {
	_ = xml.EscapeText(buffer, []byte(value))
}

func davDisplayPaths(files []File) map[string]string {
	usedByDir := map[string]map[string]int{}
	result := map[string]string{}
	for _, file := range files {
		cleanPath := strings.Trim(strings.ReplaceAll(file.Path, "\\", "/"), "/")
		if cleanPath == "" {
			cleanPath = file.Name
		}
		dir := path.Dir(cleanPath)
		if dir == "." {
			dir = ""
		}
		base := path.Base(cleanPath)
		if base == "." || base == "/" || strings.TrimSpace(base) == "" {
			base = file.Name
		}
		extension := path.Ext(base)
		stem := strings.TrimSuffix(base, extension)
		if stem == "" {
			stem = base
			extension = ""
		}
		used := usedByDir[dir]
		if used == nil {
			used = map[string]int{}
			usedByDir[dir] = used
		}
		index := used[base]
		displayName := base
		for {
			if index == 1 {
				displayName = stem + " (copy)" + extension
			} else if index > 1 {
				displayName = fmt.Sprintf("%s (copy %d)%s", stem, index, extension)
			}
			displayPath := displayName
			if dir != "" {
				displayPath = dir + "/" + displayName
			}
			if !davPathUsed(result, displayPath) {
				result[file.ID] = displayPath
				break
			}
			index++
		}
		used[base] = index + 1
	}
	return result
}

func davPathUsed(paths map[string]string, value string) bool {
	for _, existing := range paths {
		if existing == value {
			return true
		}
	}
	return false
}

func davFindFile(files []File, displayPaths map[string]string, requestedPath string) (File, string, bool) {
	requestedPath = strings.Trim(requestedPath, "/")
	for _, file := range files {
		displayPath := displayPaths[file.ID]
		if displayPath == requestedPath {
			return file, displayPath, true
		}
	}
	return File{}, "", false
}

func davCollectionExists(displayPaths map[string]string, requestedPath string) bool {
	requestedPath = strings.Trim(requestedPath, "/")
	if requestedPath == "" {
		return true
	}
	prefix := requestedPath + "/"
	for _, displayPath := range displayPaths {
		if strings.HasPrefix(displayPath, prefix) {
			return true
		}
	}
	return false
}

func davCollectionExistsWith(collections []string, displayPaths map[string]string, requestedPath string) bool {
	requestedPath = strings.Trim(requestedPath, "/")
	if requestedPath == "" {
		return true
	}
	for _, collection := range davAllCollections(collections, displayPaths) {
		if collection == requestedPath {
			return true
		}
	}
	return false
}

func davImmediateChildren(files []File, displayPaths map[string]string, parentPath string) ([]string, []File) {
	parentPath = strings.Trim(parentPath, "/")
	collectionSet := map[string]struct{}{}
	childFiles := []File{}
	for _, file := range files {
		displayPath := displayPaths[file.ID]
		remainder := davChildRemainder(parentPath, displayPath)
		if remainder == "" {
			continue
		}
		if strings.Contains(remainder, "/") {
			childName := strings.SplitN(remainder, "/", 2)[0]
			childPath := childName
			if parentPath != "" {
				childPath = parentPath + "/" + childName
			}
			collectionSet[childPath] = struct{}{}
			continue
		}
		childFiles = append(childFiles, file)
	}
	collections := make([]string, 0, len(collectionSet))
	for collection := range collectionSet {
		collections = append(collections, collection)
	}
	sort.Strings(collections)
	sort.Slice(childFiles, func(i, j int) bool {
		return displayPaths[childFiles[i].ID] < displayPaths[childFiles[j].ID]
	})
	return collections, childFiles
}

func davImmediateChildrenWith(files []File, displayPaths map[string]string, explicitCollections []string, parentPath string) ([]string, []File) {
	parentPath = strings.Trim(parentPath, "/")
	collectionSet := map[string]struct{}{}
	childFiles := []File{}
	for _, collection := range davAllCollections(explicitCollections, displayPaths) {
		remainder := davChildRemainder(parentPath, collection)
		if remainder == "" || strings.Contains(remainder, "/") {
			continue
		}
		childPath := remainder
		if parentPath != "" {
			childPath = parentPath + "/" + remainder
		}
		collectionSet[childPath] = struct{}{}
	}
	for _, file := range files {
		displayPath := displayPaths[file.ID]
		remainder := davChildRemainder(parentPath, displayPath)
		if remainder == "" {
			continue
		}
		if strings.Contains(remainder, "/") {
			childName := strings.SplitN(remainder, "/", 2)[0]
			childPath := childName
			if parentPath != "" {
				childPath = parentPath + "/" + childName
			}
			collectionSet[childPath] = struct{}{}
			continue
		}
		childFiles = append(childFiles, file)
	}
	collections := make([]string, 0, len(collectionSet))
	for collection := range collectionSet {
		collections = append(collections, collection)
	}
	sort.Strings(collections)
	sort.Slice(childFiles, func(i, j int) bool {
		return displayPaths[childFiles[i].ID] < displayPaths[childFiles[j].ID]
	})
	return collections, childFiles
}

func davAllCollections(explicitCollections []string, displayPaths map[string]string) []string {
	collectionSet := map[string]struct{}{}
	for _, collection := range explicitCollections {
		collection = strings.Trim(collection, "/")
		if collection != "" {
			collectionSet[collection] = struct{}{}
		}
	}
	for _, displayPath := range displayPaths {
		dir := path.Dir(strings.Trim(displayPath, "/"))
		for dir != "." && dir != "/" && strings.TrimSpace(dir) != "" {
			collectionSet[dir] = struct{}{}
			next := path.Dir(dir)
			if next == dir {
				break
			}
			dir = next
		}
	}
	collections := make([]string, 0, len(collectionSet))
	for collection := range collectionSet {
		collections = append(collections, collection)
	}
	sort.Strings(collections)
	return collections
}

func davChildRemainder(parentPath string, displayPath string) string {
	displayPath = strings.Trim(displayPath, "/")
	if parentPath == "" {
		return displayPath
	}
	prefix := parentPath + "/"
	if !strings.HasPrefix(displayPath, prefix) {
		return ""
	}
	return strings.TrimPrefix(displayPath, prefix)
}

func davResourceHref(rootHref string, relativePath string, collection bool) string {
	relativePath = strings.Trim(relativePath, "/")
	if relativePath == "" {
		return rootHref
	}
	segments := strings.Split(relativePath, "/")
	escaped := make([]string, 0, len(segments))
	for _, segment := range segments {
		escaped = append(escaped, url.PathEscape(segment))
	}
	href := rootHref + strings.Join(escaped, "/")
	if collection {
		href += "/"
	}
	return href
}

func davCollectionDisplayName(relativePath string) string {
	relativePath = strings.Trim(relativePath, "/")
	if relativePath == "" {
		return "Archivon"
	}
	return path.Base(relativePath)
}

func davPathParts(r *http.Request, basePath string, username string) ([]string, bool) {
	value := strings.TrimPrefix(r.URL.EscapedPath(), basePath)
	value = strings.Trim(value, "/")
	if value == "" {
		return nil, true
	}
	segments := strings.Split(value, "/")
	first, err := url.PathUnescape(segments[0])
	if err != nil || first != username {
		return nil, false
	}
	segments = segments[1:]
	if len(segments) == 0 {
		return nil, true
	}
	parts := make([]string, 0, len(segments))
	for _, segment := range segments {
		name, err := url.PathUnescape(segment)
		if err != nil {
			return nil, false
		}
		name = cleanUploadPathSegment(name)
		if name == "" || name == "." || name == ".." {
			return nil, false
		}
		parts = append(parts, name)
	}
	return parts, true
}

func davRootHref(r *http.Request, basePath string, username string) string {
	return forwardedPrefix(r) + strings.TrimRight(basePath, "/") + "/" + url.PathEscape(username) + "/"
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

func setDAVHeaders(w http.ResponseWriter) {
	w.Header().Set("DAV", "1")
	w.Header().Set("Allow", "OPTIONS, PROPFIND, GET, HEAD")
}

func setAdminDAVHeaders(w http.ResponseWriter) {
	w.Header().Set("DAV", "1, 2")
	w.Header().Set("Allow", "OPTIONS, PROPFIND, GET, HEAD, PUT, MKCOL, LOCK, UNLOCK")
}

func davMethodAllowed(method string) bool {
	return method == "PROPFIND" || method == http.MethodGet || method == http.MethodHead
}

func adminDAVMethodAllowed(method string) bool {
	return method == "PROPFIND" ||
		method == http.MethodGet ||
		method == http.MethodHead ||
		method == http.MethodPut ||
		method == "MKCOL" ||
		method == "LOCK" ||
		method == "UNLOCK"
}

func writeAdminDAVLock(w http.ResponseWriter, r *http.Request) {
	token := "opaquelocktoken:" + strings.ReplaceAll(r.URL.EscapedPath(), "/", "-")
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.Header().Set("Lock-Token", "<"+token+">")
	w.WriteHeader(http.StatusOK)
	var buffer bytes.Buffer
	buffer.WriteString(`<?xml version="1.0" encoding="utf-8"?>`)
	buffer.WriteString(`<D:prop xmlns:D="DAV:"><D:lockdiscovery><D:activelock>`)
	buffer.WriteString(`<D:locktype><D:write/></D:locktype><D:lockscope><D:exclusive/></D:lockscope>`)
	buffer.WriteString(`<D:depth>Infinity</D:depth><D:timeout>Second-3600</D:timeout><D:locktoken><D:href>`)
	writeXMLEscaped(&buffer, token)
	buffer.WriteString(`</D:href></D:locktoken></D:activelock></D:lockdiscovery></D:prop>`)
	_, _ = w.Write(buffer.Bytes())
}

func writeDAVUnauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Basic realm="Archivon WebDAV"`)
	writeDAVError(w, http.StatusUnauthorized, "unauthorized")
}

func writeDAVError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	_, _ = fmt.Fprintln(w, code)
}

func (s *Service) writeDAVError(w http.ResponseWriter, err error) {
	var typed davHTTPError
	if errors.As(err, &typed) {
		writeDAVError(w, typed.status, typed.code)
		return
	}
	if s.logger != nil {
		s.logger.Warn("webdav request failed", "error", err)
	}
	writeDAVError(w, http.StatusInternalServerError, "webdav_failed")
}

func (s *Service) folderByID(ctx context.Context, tenantID string, folderID string) (Folder, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT
  pf.id::text,
  pf.name,
  coalesce(pf.description, ''),
  pf.status,
  pf.created_at,
  pf.updated_at,
	  pf.pow_required_hashrate_ths::float8,
	  pf.pow_hashrate_tolerance_percent::float8,
	  pf.pow_proof_window_seconds,
	  pf.pow_max_proof_attempts,
  pf.pow_policy_seal,
  (
    SELECT count(f.id)::int
    FROM files f
    WHERE f.protected_folder_id = pf.id AND f.status = 'active'
  ) AS file_count,
  (
    SELECT coalesce(sum(f.size_bytes), 0)::bigint
    FROM files f
    WHERE f.protected_folder_id = pf.id AND f.status = 'active'
  ) AS total_bytes,
  (
    SELECT coalesce(jsonb_agg(unlock_users.username ORDER BY unlock_users.username), '[]'::jsonb)::text
    FROM (
      SELECT DISTINCT u.username
      FROM folder_permissions fp
      JOIN users u ON u.id = fp.user_id
      WHERE fp.tenant_id = pf.tenant_id
        AND fp.protected_folder_id = pf.id
        AND fp.can_unlock_and_access = true
        AND (fp.expires_at IS NULL OR fp.expires_at > now())
        AND u.role = 'client'
        AND u.is_blocked = false
    ) unlock_users
  ) AS unlock_usernames
FROM protected_folders pf
WHERE pf.tenant_id = $1 AND pf.id = $2 AND pf.status = 'active'
`, tenantID, folderID)
	return s.scanFolder(ctx, tenantID, row)
}

func (s *Service) fileByID(ctx context.Context, tenantID string, fileID string) (File, error) {
	row := s.db.QueryRowContext(ctx, `
WITH RECURSIVE entry_paths AS (
  SELECT fe.id, fe.file_id, fe.parent_entry_id, fe.entry_type, fe.name, fe.name::text AS path
  FROM folder_entries fe
  JOIN files f ON f.protected_folder_id = fe.protected_folder_id
  WHERE fe.tenant_id = $1 AND f.id = $2 AND fe.parent_entry_id IS NULL
  UNION ALL
  SELECT child.id, child.file_id, child.parent_entry_id, child.entry_type, child.name, entry_paths.path || '/' || child.name
  FROM folder_entries child
  JOIN entry_paths ON entry_paths.id = child.parent_entry_id
  WHERE child.tenant_id = $1
)
SELECT f.id::text, f.protected_folder_id::text, f.storage_object_id, f.original_name,
       f.plaintext_sha256, f.size_bytes, f.status, f.created_at, f.updated_at,
       coalesce(ep.path, f.original_name) AS path
FROM files f
LEFT JOIN entry_paths ep ON ep.file_id = f.id AND ep.entry_type = 'file'
WHERE f.tenant_id = $1 AND f.id = $2 AND f.status = 'active'`, tenantID, fileID)
	return s.scanFile(ctx, tenantID, row)
}

func (s *Service) fileRecordByID(ctx context.Context, tenantID string, fileID string) (fileRecord, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT id::text, protected_folder_id::text, storage_object_id, original_name,
       plaintext_sha256, size_bytes, status
FROM files
WHERE tenant_id = $1 AND id = $2 AND status = 'active'`, tenantID, fileID)
	var record fileRecord
	if err := row.Scan(
		&record.ID,
		&record.FolderID,
		&record.StorageObjectID,
		&record.Name,
		&record.PlaintextSHA256,
		&record.SizeBytes,
		&record.Status,
	); err != nil {
		return fileRecord{}, err
	}
	record.TenantID = tenantID
	record.ChunkCount = 1
	return record, nil
}

func (s *Service) scanFolder(ctx context.Context, tenantID string, scanner interface{ Scan(dest ...any) error }) (Folder, error) {
	var folder Folder
	var policySeal sql.NullString
	var unlockUsernamesJSON string
	if err := scanner.Scan(
		&folder.ID,
		&folder.Name,
		&folder.Description,
		&folder.Status,
		&folder.CreatedAt,
		&folder.UpdatedAt,
		&folder.PoWPolicy.RequiredHashrateTHs,
		&folder.PoWPolicy.HashrateTolerancePercent,
		&folder.PoWPolicy.ProofWindowSeconds,
		&folder.PoWPolicy.MaxProofAttempts,
		&policySeal,
		&folder.FileCount,
		&folder.TotalBytes,
		&unlockUsernamesJSON,
	); err != nil {
		return Folder{}, err
	}
	if strings.TrimSpace(unlockUsernamesJSON) != "" {
		if err := json.Unmarshal([]byte(unlockUsernamesJSON), &folder.UnlockUsernames); err != nil {
			return Folder{}, err
		}
	}
	if folder.UnlockUsernames == nil {
		folder.UnlockUsernames = []string{}
	}
	if _, err := s.ensureFolderPoWPolicySeal(ctx, tenantID, folder.ID, folder.PoWPolicy, policySeal); err != nil {
		return Folder{}, err
	}
	return folder, nil
}

func (s *Service) scanFile(ctx context.Context, tenantID string, scanner interface{ Scan(dest ...any) error }) (File, error) {
	_ = ctx
	_ = tenantID
	var file File
	if err := scanner.Scan(&file.ID, &file.FolderID, &file.StorageObjectID, &file.Name, &file.PlaintextSHA256, &file.SizeBytes, &file.Status, &file.CreatedAt, &file.UpdatedAt, &file.Path); err != nil {
		return File{}, err
	}
	if strings.TrimSpace(file.Path) == "" {
		file.Path = file.Name
	}
	file.ChunkCount = 1
	return file, nil
}

func (s *Service) scanClientFolder(ctx context.Context, tenantID string, scanner interface{ Scan(dest ...any) error }) (ClientFolder, error) {
	var folder ClientFolder
	var policy FolderPoWPolicy
	var expiresAt sql.NullTime
	var policySeal sql.NullString
	access := Access{}
	if err := scanner.Scan(
		&folder.ID,
		&folder.Name,
		&folder.Description,
		&folder.Status,
		&policy.RequiredHashrateTHs,
		&policy.HashrateTolerancePercent,
		&policy.ProofWindowSeconds,
		&policy.MaxProofAttempts,
		&policySeal,
		&folder.FileCount,
		&folder.TotalBytes,
		&access.CanUnlockAndAccess,
		&expiresAt,
	); err != nil {
		return ClientFolder{}, err
	}
	if _, err := s.ensureFolderPoWPolicySeal(ctx, tenantID, folder.ID, policy, policySeal); err != nil {
		return ClientFolder{}, err
	}
	if expiresAt.Valid {
		access.ExpiresAt = &expiresAt.Time
	}
	access = normalizeStoredAccess(access)
	folder.Access = &access
	return folder, nil
}

func (s *Service) folderPermissions(ctx context.Context, tenantID string, folderID string) ([]FolderPermission, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT
  u.id::text,
  u.username,
  u.role,
  coalesce(fp.can_unlock_and_access, false),
  fp.expires_at,
  fp.updated_at
FROM users u
LEFT JOIN folder_permissions fp ON fp.user_id = u.id AND fp.protected_folder_id = $2
WHERE u.tenant_id = $1
  AND u.role = 'client'
  AND u.is_blocked = false
ORDER BY u.username`, tenantID, folderID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	permissions := []FolderPermission{}
	for rows.Next() {
		permission, err := scanFolderPermission(rows)
		if err != nil {
			return nil, err
		}
		permissions = append(permissions, permission)
	}
	return permissions, rows.Err()
}

func (s *Service) folderPermissionForUser(ctx context.Context, tenantID string, folderID string, userID string) (FolderPermission, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT
  u.id::text,
  u.username,
  u.role,
  coalesce(fp.can_unlock_and_access, false),
  fp.expires_at,
  fp.updated_at
FROM users u
LEFT JOIN folder_permissions fp ON fp.user_id = u.id AND fp.protected_folder_id = $2
WHERE u.tenant_id = $1
  AND u.id = $3
  AND u.role = 'client'
  AND u.is_blocked = false`, tenantID, folderID, userID)
	return scanFolderPermission(row)
}

func scanFolderPermission(scanner interface{ Scan(dest ...any) error }) (FolderPermission, error) {
	var permission FolderPermission
	var expiresAt sql.NullTime
	var updatedAt sql.NullTime
	if err := scanner.Scan(
		&permission.UserID,
		&permission.Username,
		&permission.Role,
		&permission.CanUnlockAndAccess,
		&expiresAt,
		&updatedAt,
	); err != nil {
		return FolderPermission{}, err
	}
	if expiresAt.Valid {
		permission.ExpiresAt = &expiresAt.Time
	}
	if updatedAt.Valid {
		permission.UpdatedAt = &updatedAt.Time
	}
	access := normalizeStoredAccess(Access{
		CanUnlockAndAccess: permission.CanUnlockAndAccess,
		ExpiresAt:          permission.ExpiresAt,
	})
	permission.CanUnlockAndAccess = access.CanUnlockAndAccess
	return permission, nil
}

func (s *Service) effectiveAccess(ctx context.Context, tenantID string, userID string, folderID string) (Access, error) {
	var access Access
	var expiresAt sql.NullTime
	if err := s.db.QueryRowContext(ctx, `
SELECT fp.can_unlock_and_access, fp.expires_at
FROM folder_permissions fp
JOIN protected_folders pf ON pf.id = fp.protected_folder_id
WHERE fp.tenant_id = $1
  AND fp.user_id = $2
  AND fp.protected_folder_id = $3
  AND pf.status = 'active'
  AND (fp.expires_at IS NULL OR fp.expires_at > now())`, tenantID, userID, folderID,
	).Scan(&access.CanUnlockAndAccess, &expiresAt); err != nil {
		return Access{}, err
	}
	if expiresAt.Valid {
		access.ExpiresAt = &expiresAt.Time
	}
	return normalizeStoredAccess(access), nil
}

func (s *Service) activeAccessSessionID(ctx context.Context, tenantID string, userID string, folderID string) (string, error) {
	var sessionID string
	err := s.db.QueryRowContext(ctx, `
SELECT id::text
FROM access_sessions
WHERE tenant_id = $1
  AND user_id = $2
  AND protected_folder_id = $3
  AND status = 'active'
  AND expires_at > now()
ORDER BY expires_at DESC
LIMIT 1`, tenantID, userID, folderID).Scan(&sessionID)
	return sessionID, err
}

func normalizeAccess(canUnlock bool, expiresAtRaw string) (Access, error) {
	access := Access{
		CanUnlockAndAccess: canUnlock,
	}
	expiresAtRaw = strings.TrimSpace(expiresAtRaw)
	if expiresAtRaw == "" {
		return access, nil
	}
	expiresAt, err := time.Parse(time.RFC3339, expiresAtRaw)
	if err != nil {
		return Access{}, err
	}
	access.ExpiresAt = &expiresAt
	return access, nil
}

func normalizeStoredAccess(access Access) Access {
	return access
}

func (s *Service) defaultFolderPoWPolicy(ctx context.Context) (FolderPoWPolicy, error) {
	policy := FolderPoWPolicy{
		RequiredHashrateTHs:      1,
		HashrateTolerancePercent: 10,
		ProofWindowSeconds:       60,
		MaxProofAttempts:         3,
	}
	var raw []byte
	err := s.db.QueryRowContext(ctx, `SELECT value FROM system_settings WHERE key = $1`, powAccessPolicyKey).Scan(&raw)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return policy, nil
		}
		return FolderPoWPolicy{}, err
	}
	var stored struct {
		RequiredHashrateTHs      float64 `json:"required_hashrate_ths"`
		HashrateTolerancePercent float64 `json:"hashrate_tolerance_percent"`
		ProofWindowSeconds       int     `json:"proof_window_seconds"`
		MaxProofAttempts         int     `json:"max_proof_attempts"`
	}
	if err := json.Unmarshal(raw, &stored); err != nil {
		return FolderPoWPolicy{}, err
	}
	return normalizeFolderPoWPolicy(FolderPoWPolicy{
		RequiredHashrateTHs:      stored.RequiredHashrateTHs,
		HashrateTolerancePercent: stored.HashrateTolerancePercent,
		ProofWindowSeconds:       stored.ProofWindowSeconds,
		MaxProofAttempts:         stored.MaxProofAttempts,
	}, policy), nil
}

func normalizeFolderPoWPolicy(policy FolderPoWPolicy, fallback FolderPoWPolicy) FolderPoWPolicy {
	if policy.RequiredHashrateTHs == 0 &&
		policy.HashrateTolerancePercent == 0 &&
		policy.ProofWindowSeconds == 0 &&
		policy.MaxProofAttempts == 0 {
		policy = fallback
	}
	if fallback.RequiredHashrateTHs <= 0 {
		fallback.RequiredHashrateTHs = 1
	}
	if fallback.HashrateTolerancePercent < 0 {
		fallback.HashrateTolerancePercent = 10
	}
	if fallback.ProofWindowSeconds <= 0 {
		fallback.ProofWindowSeconds = 60
	}
	if fallback.MaxProofAttempts <= 0 {
		fallback.MaxProofAttempts = 3
	}
	if policy.RequiredHashrateTHs <= 0 {
		policy.RequiredHashrateTHs = fallback.RequiredHashrateTHs
	}
	if policy.ProofWindowSeconds <= 0 {
		policy.ProofWindowSeconds = fallback.ProofWindowSeconds
	}
	if policy.MaxProofAttempts <= 0 {
		policy.MaxProofAttempts = fallback.MaxProofAttempts
	}
	return policy
}

func validateFolderPoWPolicy(policy FolderPoWPolicy) error {
	switch {
	case policy.RequiredHashrateTHs <= 0:
		return errors.New("pow_required_hashrate_invalid")
	case policy.HashrateTolerancePercent < 0 || policy.HashrateTolerancePercent > 50:
		return errors.New("pow_hashrate_tolerance_invalid")
	case policy.ProofWindowSeconds < 5 || policy.ProofWindowSeconds > 600:
		return errors.New("pow_proof_window_invalid")
	case policy.MaxProofAttempts < 1 || policy.MaxProofAttempts > 10:
		return errors.New("pow_max_proof_attempts_invalid")
	default:
		return nil
	}
}

func (s *Service) folderPoWPolicySeal(ctx context.Context, tenantID string, folderID string, policy FolderPoWPolicy) (string, error) {
	if s.kms == nil {
		return "", errors.New("kms_not_configured")
	}
	return s.kms.Seal(ctx, policyseal.FolderPoWPurpose, policyseal.FolderPoWPolicyPayload(tenantID, folderID, policyseal.FolderPoWPolicy{
		RequiredHashrateTHs:      policy.RequiredHashrateTHs,
		HashrateTolerancePercent: policy.HashrateTolerancePercent,
		ProofWindowSeconds:       policy.ProofWindowSeconds,
		MaxProofAttempts:         policy.MaxProofAttempts,
	}))
}

func (s *Service) ensureFolderPoWPolicySeal(ctx context.Context, tenantID string, folderID string, policy FolderPoWPolicy, storedSeal sql.NullString) (string, error) {
	expectedSeal, err := s.folderPoWPolicySeal(ctx, tenantID, folderID, policy)
	if err != nil {
		return "", err
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
		if err != nil {
			return "", err
		}
		return expectedSeal, nil
	}
	if seal != expectedSeal {
		return "", errors.New("folder_pow_policy_seal_mismatch")
	}
	return seal, nil
}

func validateFolderPoWPolicyStrengthening(current FolderPoWPolicy, next FolderPoWPolicy) error {
	const epsilon = 0.000001
	switch {
	case next.RequiredHashrateTHs+epsilon < current.RequiredHashrateTHs:
		return errors.New("pow_policy_cannot_reduce_hashrate")
	case next.HashrateTolerancePercent-epsilon > current.HashrateTolerancePercent:
		return errors.New("pow_policy_cannot_increase_tolerance")
	case next.ProofWindowSeconds < current.ProofWindowSeconds:
		return errors.New("pow_policy_cannot_reduce_window")
	case next.MaxProofAttempts > current.MaxProofAttempts:
		return errors.New("pow_policy_cannot_increase_attempts")
	default:
		return nil
	}
}

func revokeAccessOnPermissionLossTx(ctx context.Context, tx *sql.Tx, tenantID string, userID string, folderID string, access Access) (int64, int64, error) {
	permissionAlreadyExpired := access.ExpiresAt != nil && !access.ExpiresAt.After(time.Now().UTC())
	if access.CanUnlockAndAccess && !permissionAlreadyExpired {
		return 0, 0, nil
	}
	sessionResult, err := tx.ExecContext(ctx, `
UPDATE access_sessions
SET status = 'revoked',
    closed_at = now(),
    close_reason = 'permission_revoked'
WHERE tenant_id = $1
  AND user_id = $2
  AND protected_folder_id = $3
  AND status = 'active'`, tenantID, userID, folderID)
	if err != nil {
		return 0, 0, err
	}
	revokedSessions, err := sessionResult.RowsAffected()
	if err != nil {
		return 0, 0, err
	}
	jobResult, err := tx.ExecContext(ctx, `
UPDATE pow_jobs
SET status = 'canceled',
    finished_at = now(),
    failure_reason = 'permission_revoked'
WHERE tenant_id = $1
  AND user_id = $2
  AND protected_folder_id = $3
  AND status IN ('queued', 'running')`, tenantID, userID, folderID)
	if err != nil {
		return 0, 0, err
	}
	canceledJobs, err := jobResult.RowsAffected()
	if err != nil {
		return 0, 0, err
	}
	return revokedSessions, canceledJobs, nil
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

func (s *Service) ensureFolderActive(ctx context.Context, tenantID string, folderID string) error {
	var policy FolderPoWPolicy
	var policySeal sql.NullString
	if err := s.db.QueryRowContext(ctx, `
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
	); err != nil {
		return err
	}
	_, err := s.ensureFolderPoWPolicySeal(ctx, tenantID, folderID, policy, policySeal)
	return err
}

func (s *Service) ensureClientUser(ctx context.Context, tenantID string, userID string) (string, error) {
	var username string
	var role string
	if err := s.db.QueryRowContext(ctx, `
SELECT username, role
FROM users
WHERE tenant_id = $1 AND id = $2 AND is_blocked = false`, tenantID, userID).Scan(&username, &role); err != nil {
		return "", err
	}
	if role != "client" {
		return "", sql.ErrNoRows
	}
	return username, nil
}

func insertAuditEvent(ctx context.Context, db *sql.DB, tenantID string, actorUserID string, eventType string, targetType string, targetID string, severity string, ipAddress string, details map[string]any) error {
	tx, err := db.BeginTx(ctx, nil)
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

func insertAuditEventTx(ctx context.Context, tx *sql.Tx, tenantID string, actorUserID string, eventType string, targetType string, targetID string, severity string, ipAddress string, details map[string]any) error {
	rawDetails, err := json.Marshal(details)
	if err != nil {
		rawDetails = []byte(`{}`)
	}
	_, err = tx.ExecContext(ctx, `
INSERT INTO audit_events (tenant_id, actor_user_id, event_type, target_type, target_id, severity, ip_address, details)
VALUES ($1, $2, $3, nullif($4, ''), $5, $6, nullif($7, ''), $8::jsonb)`,
		tenantID, actorUserID, eventType, targetType, targetID, severity, ipAddress, string(rawDetails),
	)
	return err
}

func (s *Service) kmsReady(ctx context.Context, w http.ResponseWriter) bool {
	status := s.kms.Status(ctx)
	if status.Available {
		return true
	}
	writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "kms_not_ready", "state": status.State, "reason": status.Reason})
	return false
}

func (s *Service) objectDir(storageObjectID string) string {
	return filepath.Join(s.storagePath, "objects", objectShard(storageObjectID), storageObjectID)
}

func (s *Service) removeStorageObjects(storageObjectIDs []string) {
	for _, storageObjectID := range storageObjectIDs {
		storageObjectID = strings.TrimSpace(storageObjectID)
		if storageObjectID == "" {
			continue
		}
		if err := os.RemoveAll(s.objectDir(storageObjectID)); err != nil && s.logger != nil {
			s.logger.Warn("storage object removal failed", "storage_object_id", storageObjectID, "error", err)
		}
	}
}

func objectShard(storageObjectID string) string {
	if strings.HasPrefix(storageObjectID, "obj_") && len(storageObjectID) >= 6 {
		return storageObjectID[4:6]
	}
	if len(storageObjectID) >= 2 {
		return storageObjectID[:2]
	}
	return "00"
}

func newAdminDAVPassword() (string, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return "AdmDav1-" + hex.EncodeToString(raw), nil
}

func adminDAVURLFromRequest(r *http.Request, username string) string {
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
	return scheme + "://" + host + forwardedPrefix(r) + "/admin-dav/" + url.PathEscape(username) + "/"
}

func cleanUploadName(value string) string {
	value = strings.ReplaceAll(strings.TrimSpace(value), "\\", "/")
	name := path.Base(value)
	if name == "." || name == "/" {
		return ""
	}
	return strings.TrimSpace(name)
}

func cleanUploadPath(relativePath string, fallbackName string) ([]string, error) {
	value := strings.TrimSpace(strings.ReplaceAll(relativePath, "\\", "/"))
	if value == "" {
		value = cleanUploadName(fallbackName)
	}
	value = strings.Trim(value, "/")
	if value == "" || len(value) > maxUploadPathLength {
		return nil, errors.New("invalid_upload_path")
	}
	rawSegments := strings.Split(value, "/")
	if len(rawSegments) == 0 || len(rawSegments) > maxUploadPathSegments {
		return nil, errors.New("invalid_upload_path")
	}
	segments := make([]string, 0, len(rawSegments))
	for _, rawSegment := range rawSegments {
		segment := cleanUploadPathSegment(rawSegment)
		if segment == "" || segment == "." || segment == ".." {
			return nil, errors.New("invalid_upload_path")
		}
		segments = append(segments, segment)
	}
	if len(segments) == 0 {
		return nil, errors.New("invalid_upload_path")
	}
	return segments, nil
}

func cleanFolderCollectionPath(relativePath string) ([]string, error) {
	value := strings.Trim(strings.TrimSpace(strings.ReplaceAll(relativePath, "\\", "/")), "/")
	if value == "" {
		return nil, nil
	}
	segments, err := cleanUploadPath(value+"/.keep", ".keep")
	if err != nil {
		return nil, err
	}
	if len(segments) == 0 {
		return nil, nil
	}
	return segments[:len(segments)-1], nil
}

func cleanUploadPathSegment(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	for _, char := range value {
		if char < 32 || char == 127 || char == '/' || char == '\\' {
			return ""
		}
	}
	return value
}

func backupArchivePath(displayPath string, file File) string {
	cleanPath := strings.Trim(strings.ReplaceAll(displayPath, "\\", "/"), "/")
	if cleanPath != "" {
		return "content/" + cleanPath
	}
	name := cleanUploadName(file.Path)
	if name == "" {
		name = cleanUploadName(file.Name)
	}
	if name == "" {
		name = "file.bin"
	}
	return "content/" + name
}

func backupDownloadName(folderName string) string {
	name := cleanUploadName(folderName)
	if name == "" {
		name = "archivon-folder"
	}
	return name + ".archivon-backup.zip"
}

func restoredFolderName(folderName string) string {
	name := strings.TrimSpace(folderName)
	if name == "" {
		return ""
	}
	return name + " (backup)"
}

func ensureFolderEntryPathTx(ctx context.Context, tx *sql.Tx, tenantID string, folderID string, segments []string) (*string, error) {
	var parentID *string
	for _, segment := range segments {
		var entryID string
		err := tx.QueryRowContext(ctx, `
SELECT id::text
FROM folder_entries
WHERE tenant_id = $1
  AND protected_folder_id = $2
  AND entry_type = 'folder'
  AND name = $3
  AND (
    ($4::uuid IS NULL AND parent_entry_id IS NULL)
    OR parent_entry_id = $4::uuid
  )
ORDER BY created_at ASC, id ASC
LIMIT 1`, tenantID, folderID, segment, nullableStringPtr(parentID)).Scan(&entryID)
		if err == nil {
			parentID = &entryID
			continue
		}
		if err != sql.ErrNoRows {
			return nil, err
		}
		newID, err := newUUID()
		if err != nil {
			return nil, err
		}
		if _, err := tx.ExecContext(ctx, `
INSERT INTO folder_entries (
  id, tenant_id, protected_folder_id, parent_entry_id, entry_type, name
)
VALUES ($1, $2, $3, $4, 'folder', $5)`,
			newID, tenantID, folderID, nullableStringPtr(parentID), segment,
		); err != nil {
			return nil, err
		}
		parentID = &newID
	}
	return parentID, nil
}

func nullableStringPtr(value *string) any {
	if value == nil || strings.TrimSpace(*value) == "" {
		return nil
	}
	return *value
}

func newStorageObjectID() (string, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return "obj_" + hex.EncodeToString(raw), nil
}

func newUUID() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	raw[6] = (raw[6] & 0x0f) | 0x40
	raw[8] = (raw[8] & 0x3f) | 0x80
	encoded := hex.EncodeToString(raw)
	return fmt.Sprintf("%s-%s-%s-%s-%s", encoded[0:8], encoded[8:12], encoded[12:16], encoded[16:20], encoded[20:32]), nil
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
