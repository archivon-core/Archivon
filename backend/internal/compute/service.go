package compute

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"archivon/backend/internal/auth"

	"golang.org/x/crypto/bcrypt"
)

const (
	computePolicyKey          = "compute_gateway_policy"
	diff1TargetHex            = "00000000ffff0000000000000000000000000000000000000000000000000000"
	maxTargetHex              = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	diff1WorkTH               = 0.004294967296
	versionRollingMaskDefault = "00c00000"
)

var errCloseStratumConnection = errors.New("close stratum connection")

type Reconciler interface {
	Reconcile(ctx context.Context, tenantID string) error
}

type Options struct {
	ListenAddress string
}

type Service struct {
	db            *sql.DB
	logger        *slog.Logger
	auth          *auth.Service
	reconciler    Reconciler
	listenAddress string
	startedAt     time.Time

	mu          sync.Mutex
	connections map[string]map[string]struct{}
	listener    net.Listener
}

type Policy struct {
	Enabled            bool       `json:"enabled"`
	BindAddress        string     `json:"bind_address"`
	StratumPort        int        `json:"stratum_port"`
	ShareDifficulty    float64    `json:"share_difficulty"`
	Extranonce2Size    int        `json:"extranonce2_size"`
	PasswordConfigured bool       `json:"password_configured"`
	PasswordHash       string     `json:"password_hash,omitempty"`
	PasswordUpdatedAt  *time.Time `json:"password_updated_at,omitempty"`
}

type updateSettingsRequest struct {
	Enabled         *bool   `json:"enabled"`
	ShareDifficulty float64 `json:"share_difficulty"`
	StratumPassword string  `json:"stratum_password"`
}

type statusResponse struct {
	Policy       Policy        `json:"policy"`
	Runtime      RuntimeStatus `json:"runtime"`
	ActiveJob    *ActiveJob    `json:"active_job,omitempty"`
	Workers      []Worker      `json:"workers"`
	RecentShares []Share       `json:"recent_shares"`
}

type RuntimeStatus struct {
	Running           bool      `json:"running"`
	ListenAddress     string    `json:"listen_address"`
	StartedAt         time.Time `json:"started_at"`
	ActiveConnections int       `json:"active_connections"`
}

type ActiveJob struct {
	ID                       string    `json:"id"`
	UserID                   string    `json:"user_id"`
	Username                 string    `json:"username"`
	RequiredHashrateTHs      float64   `json:"required_hashrate_ths"`
	RequiredWorkTH           float64   `json:"required_work_th"`
	HashrateTolerancePercent float64   `json:"hashrate_tolerance_percent"`
	ProofWindowSeconds       int       `json:"proof_window_seconds"`
	MaxProofAttempts         int       `json:"max_proof_attempts"`
	ValidWorkTH              float64   `json:"valid_work_th"`
	ValidWorkerCount         int       `json:"valid_worker_count"`
	StartedAt                time.Time `json:"started_at"`
}

type Worker struct {
	ID                  string     `json:"id"`
	WorkerName          string     `json:"worker_name"`
	Status              string     `json:"status"`
	RuntimeConnections  int        `json:"runtime_connections"`
	Conflict            bool       `json:"conflict"`
	ReportedHashrateTHs *float64   `json:"reported_hashrate_ths,omitempty"`
	ConnectionCount     int        `json:"connection_count"`
	ValidShares         int        `json:"valid_shares"`
	InvalidShares       int        `json:"invalid_shares"`
	ValidWorkTH         float64    `json:"valid_work_th"`
	LastSeenAt          *time.Time `json:"last_seen_at,omitempty"`
	LastConnectedAt     *time.Time `json:"last_connected_at,omitempty"`
	LastDisconnectedAt  *time.Time `json:"last_disconnected_at,omitempty"`
	StatsResetAt        *time.Time `json:"stats_reset_at,omitempty"`
	LastIP              string     `json:"last_ip,omitempty"`
	LastError           string     `json:"last_error,omitempty"`
}

type Share struct {
	ID              string    `json:"id"`
	PoWJobID        string    `json:"pow_job_id"`
	WorkerName      string    `json:"worker_name"`
	ShareHash       string    `json:"share_hash"`
	ShareTarget     string    `json:"share_target"`
	WorkTH          float64   `json:"work_th"`
	IsValid         bool      `json:"is_valid"`
	RejectionReason string    `json:"rejection_reason,omitempty"`
	SubmittedAt     time.Time `json:"submitted_at"`
}

type runningJob struct {
	id                       string
	tenantID                 string
	userID                   string
	username                 string
	requiredWorkTH           float64
	requiredHashrateTHs      float64
	minWorkers               int
	hashrateTolerancePercent float64
	proofWindowSeconds       int
	maxProofAttempts         int
	startedAt                time.Time
}

type stratumState struct {
	mu              sync.Mutex
	writeMu         sync.Mutex
	dispatchOnce    sync.Once
	id              string
	peer            string
	tenantID        string
	workerID        string
	workerName      string
	subscribed      bool
	authorized      bool
	extranonce1     string
	extranonce2Size int
	currentWork     *work
	versionRolling  bool
	versionMask     string
	invalidLogCount int
	done            chan struct{}
}

type work struct {
	powJobID    string
	stratumID   string
	extranonce1 string
	coinb1      string
	coinb2      string
	prevhash    string
	version     string
	nbits       string
	ntime       string
	targetHex   string
	difficulty  float64
	workTH      float64
}

type stratumRequest struct {
	ID     any    `json:"id"`
	Method string `json:"method"`
	Params []any  `json:"params"`
}

type lockedWriter struct {
	mu     *sync.Mutex
	writer io.Writer
}

func (w lockedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.writer.Write(p)
}

func NewService(db *sql.DB, logger *slog.Logger, authService *auth.Service, reconciler Reconciler, opts Options) *Service {
	address := strings.TrimSpace(opts.ListenAddress)
	if address == "" {
		address = ":3333"
	}
	return &Service{
		db:            db,
		logger:        logger,
		auth:          authService,
		reconciler:    reconciler,
		listenAddress: address,
		connections:   map[string]map[string]struct{}{},
	}
}

func (s *Service) Register(mux *http.ServeMux) {
	mux.Handle("/api/admin/compute/status", s.auth.RequireRole(http.HandlerFunc(s.handleStatus), "super_admin", "admin"))
	mux.Handle("/api/admin/compute/settings", s.auth.RequireRole(http.HandlerFunc(s.handleSettings), "super_admin", "admin"))
	mux.Handle("/api/admin/compute/workers/", s.auth.RequireRole(http.HandlerFunc(s.handleWorkerAction), "super_admin"))
}

func (s *Service) Start(ctx context.Context) error {
	if err := s.markRuntimeWorkersDisconnected(context.Background()); err != nil && s.logger != nil {
		s.logger.Warn("compute runtime worker status cleanup failed", "error", err)
	}
	listener, err := net.Listen("tcp", s.listenAddress)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.listener = listener
	s.startedAt = time.Now().UTC()
	s.mu.Unlock()
	if s.logger != nil {
		s.logger.Info("compute stratum gateway starting", "address", listener.Addr().String())
	}
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	go s.acceptLoop(listener)
	return nil
}

func (s *Service) acceptLoop(listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			if s.logger != nil {
				s.logger.Warn("compute stratum accept failed", "error", err)
			}
			continue
		}
		go s.handleConn(conn)
	}
}

func (s *Service) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, "GET")
		return
	}
	response, err := s.status(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "compute_status_failed")
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Service) handleSettings(w http.ResponseWriter, r *http.Request) {
	user, err := s.auth.CurrentUser(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "not_authenticated")
		return
	}
	switch r.Method {
	case http.MethodGet:
		response, err := s.status(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, "compute_status_failed")
			return
		}
		writeJSON(w, http.StatusOK, response)
	case http.MethodPost:
		if user.Role != "super_admin" {
			writeError(w, http.StatusForbidden, "super_admin_required")
			return
		}
		var req updateSettingsRequest
		if !decodeJSON(w, r, &req) {
			return
		}
		policy, err := s.loadPolicy(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, "policy_load_failed")
			return
		}
		if req.Enabled != nil {
			policy.Enabled = *req.Enabled
		}
		if req.ShareDifficulty > 0 {
			policy.ShareDifficulty = req.ShareDifficulty
		}
		password := strings.TrimSpace(req.StratumPassword)
		if password != "" {
			if len(password) < 8 {
				writeError(w, http.StatusBadRequest, "stratum_password_too_short")
				return
			}
			hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "password_hash_failed")
				return
			}
			now := time.Now().UTC()
			policy.PasswordHash = string(hash)
			policy.PasswordConfigured = true
			policy.PasswordUpdatedAt = &now
		}
		policy = normalizePolicy(policy, s.listenAddress)
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
    updated_at = now()`, computePolicyKey, string(raw), user.ID); err != nil {
			writeError(w, http.StatusInternalServerError, "policy_update_failed")
			return
		}
		_ = s.insertAuditEvent(r.Context(), user.TenantID, user.ID, "compute.policy.updated", "system_setting", nil, "warning", clientIP(r), map[string]any{
			"enabled":             policy.Enabled,
			"share_difficulty":    policy.ShareDifficulty,
			"password_configured": policy.PasswordConfigured,
		})
		response, err := s.status(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, "compute_status_failed")
			return
		}
		writeJSON(w, http.StatusOK, response)
	default:
		writeMethodNotAllowed(w, "GET, POST")
	}
}

func (s *Service) handleWorkerAction(w http.ResponseWriter, r *http.Request) {
	user, err := s.auth.CurrentUser(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "not_authenticated")
		return
	}
	workerID, action, ok := computeWorkerActionPath(r.URL.Path)
	if !ok || action != "reset-stats" {
		writeError(w, http.StatusNotFound, "worker_action_not_found")
		return
	}
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, "POST")
		return
	}
	workerName, err := s.resetWorkerStats(r.Context(), user.TenantID, workerID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "worker_not_found")
			return
		}
		writeError(w, http.StatusInternalServerError, "worker_stats_reset_failed")
		return
	}
	_ = s.insertAuditEvent(r.Context(), user.TenantID, user.ID, "compute.worker.stats_reset", "compute_worker", &workerID, "warning", clientIP(r), map[string]any{
		"worker_name": workerName,
	})
	response, err := s.status(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "compute_status_failed")
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Service) status(ctx context.Context) (statusResponse, error) {
	policy, err := s.loadPolicy(ctx)
	if err != nil {
		return statusResponse{}, err
	}
	runtime := s.runtimeStatus()
	active, err := s.activeJob(ctx)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return statusResponse{}, err
	}
	var activeJob *ActiveJob
	if err == nil {
		activeJob = &active
	}
	workers, err := s.workers(ctx)
	if err != nil {
		return statusResponse{}, err
	}
	shares, err := s.recentShares(ctx)
	if err != nil {
		return statusResponse{}, err
	}
	return statusResponse{
		Policy:       sanitizePolicy(policy),
		Runtime:      runtime,
		ActiveJob:    activeJob,
		Workers:      workers,
		RecentShares: shares,
	}, nil
}

func (s *Service) runtimeStatus() RuntimeStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	total := 0
	for _, sessions := range s.connections {
		total += len(sessions)
	}
	running := s.listener != nil
	return RuntimeStatus{
		Running:           running,
		ListenAddress:     s.listenAddress,
		StartedAt:         s.startedAt,
		ActiveConnections: total,
	}
}

func (s *Service) HasActiveConnection() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, sessions := range s.connections {
		if len(sessions) > 0 {
			return true
		}
	}
	return false
}

func (s *Service) handleConn(conn net.Conn) {
	defer conn.Close()
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		_ = tcpConn.SetKeepAlive(true)
		_ = tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}
	peer := conn.RemoteAddr().String()
	state := &stratumState{
		id:              randomHex(8),
		peer:            peer,
		extranonce1:     randomHex(4),
		extranonce2Size: 4,
		done:            make(chan struct{}),
	}
	writer := lockedWriter{mu: &state.writeMu, writer: conn}
	defer func() {
		close(state.done)
		s.unregisterConnection(context.Background(), state)
		if s.logger != nil {
			s.logger.Info("compute worker disconnected", "peer", peer, "worker", state.workerName)
		}
	}()
	if s.logger != nil {
		s.logger.Info("compute worker connected", "peer", peer)
	}
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 0, 4096), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "GET ") || strings.HasPrefix(line, "POST ") {
			return
		}
		var req stratumRequest
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			_ = sendStratumError(writer, nil, 20, "invalid JSON")
			continue
		}
		if err := s.handleMessage(writer, state, req); err != nil {
			if errors.Is(err, errCloseStratumConnection) {
				return
			}
			if s.logger != nil {
				s.logger.Warn("compute stratum request failed", "peer", peer, "worker", state.workerName, "error", err)
			}
		}
	}
	if err := scanner.Err(); err != nil && !errors.Is(err, io.EOF) && s.logger != nil {
		s.logger.Warn("compute worker read failed", "peer", peer, "error", err)
	}
}

func (s *Service) handleMessage(conn io.Writer, state *stratumState, req stratumRequest) error {
	switch req.Method {
	case "mining.configure":
		return s.handleConfigure(conn, state, req)
	case "mining.subscribe":
		state.subscribed = true
		policy, err := s.loadPolicy(context.Background())
		if err == nil {
			state.extranonce2Size = policy.Extranonce2Size
		}
		return sendStratumResult(conn, req.ID, []any{
			[]any{
				[]any{"mining.set_difficulty", "archivon-diff"},
				[]any{"mining.notify", "archivon-job"},
			},
			state.extranonce1,
			state.extranonce2Size,
		})
	case "mining.extranonce.subscribe", "mining.suggest_difficulty":
		return sendStratumResult(conn, req.ID, true)
	case "mining.authorize":
		return s.authorize(conn, state, req)
	case "mining.submit":
		return s.submitShare(conn, state, req)
	default:
		return sendStratumError(conn, req.ID, 21, "unknown method")
	}
}

func (s *Service) handleConfigure(conn io.Writer, state *stratumState, req stratumRequest) error {
	result := map[string]any{}
	requested := stratumExtensionNames(req.Params)
	for _, extension := range requested {
		result[extension] = false
	}
	if stratumExtensionRequested(requested, "version-rolling") {
		mask := requestedVersionRollingMask(req.Params)
		state.versionRolling = true
		state.versionMask = mask
		result["version-rolling"] = true
		result["version-rolling.mask"] = mask
	}
	return sendStratumResult(conn, req.ID, result)
}

func (s *Service) authorize(conn io.Writer, state *stratumState, req stratumRequest) error {
	workerName := paramString(req.Params, 0)
	password := paramString(req.Params, 1)
	if strings.TrimSpace(workerName) == "" {
		_ = sendStratumResult(conn, req.ID, false)
		return nil
	}
	policy, err := s.loadPolicy(context.Background())
	if err != nil || !policy.Enabled || !policy.PasswordConfigured || policy.PasswordHash == "" {
		_ = sendStratumResult(conn, req.ID, false)
		return nil
	}
	if bcrypt.CompareHashAndPassword([]byte(policy.PasswordHash), []byte(password)) != nil {
		_ = sendStratumResult(conn, req.ID, false)
		tenantID, _ := s.defaultTenantID(context.Background())
		if tenantID != "" {
			_ = s.updateWorkerError(context.Background(), tenantID, workerName, "invalid_password")
		}
		return nil
	}
	job, jobErr := s.runningJob(context.Background())
	if jobErr != nil && !errors.Is(jobErr, sql.ErrNoRows) {
		_ = sendStratumResult(conn, req.ID, false)
		return jobErr
	}
	tenantID := ""
	if jobErr == nil {
		tenantID = job.tenantID
	} else {
		tenantID, _ = s.defaultTenantID(context.Background())
	}
	workerID, err := s.upsertWorker(context.Background(), tenantID, workerName, state.peer)
	if err != nil {
		_ = sendStratumResult(conn, req.ID, false)
		return err
	}
	state.mu.Lock()
	state.tenantID = tenantID
	state.workerID = workerID
	state.workerName = workerName
	state.authorized = true
	state.mu.Unlock()
	s.registerConnection(state)
	if err := sendStratumResult(conn, req.ID, true); err != nil {
		return err
	}
	if err := sendStratumNotification(conn, "mining.set_difficulty", []any{policy.ShareDifficulty}); err != nil {
		return err
	}
	if state.versionRolling && state.versionMask != "" {
		if err := sendStratumNotification(conn, "mining.set_version_mask", []any{state.versionMask}); err != nil {
			return err
		}
	}
	if jobErr == nil {
		if err := s.sendWork(conn, state, job, policy, false); err != nil {
			return err
		}
	}
	s.startWorkDispatch(conn, state)
	return nil
}

func (s *Service) startWorkDispatch(conn io.Writer, state *stratumState) {
	state.dispatchOnce.Do(func() {
		go s.workDispatchLoop(conn, state)
	})
}

func (s *Service) workDispatchLoop(conn io.Writer, state *stratumState) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-state.done:
			return
		case <-ticker.C:
			state.mu.Lock()
			authorized := state.authorized
			tenantID := state.tenantID
			currentWorkID := ""
			if state.currentWork != nil {
				currentWorkID = state.currentWork.powJobID
			}
			state.mu.Unlock()
			if !authorized || tenantID == "" {
				continue
			}
			job, err := s.runningJob(context.Background())
			if errors.Is(err, sql.ErrNoRows) {
				continue
			}
			if err != nil {
				if s.logger != nil {
					s.logger.Warn("compute work dispatch lookup failed", "worker", state.workerName, "error", err)
				}
				continue
			}
			if job.tenantID != tenantID || job.id == currentWorkID {
				continue
			}
			policy, err := s.loadPolicy(context.Background())
			if err != nil || !policy.Enabled {
				if err != nil && s.logger != nil {
					s.logger.Warn("compute work dispatch policy failed", "worker", state.workerName, "error", err)
				}
				continue
			}
			if err := s.sendWork(conn, state, job, policy, true); err != nil {
				if s.logger != nil {
					s.logger.Warn("compute work dispatch failed", "worker", state.workerName, "pow_job_id", job.id, "error", err)
				}
				return
			}
		}
	}
}

func (s *Service) sendWork(conn io.Writer, state *stratumState, job runningJob, policy Policy, refreshDifficulty bool) error {
	work, err := buildWork(job, state.extranonce1, policy)
	if err != nil {
		return err
	}
	state.mu.Lock()
	if state.currentWork != nil && state.currentWork.powJobID == work.powJobID {
		state.mu.Unlock()
		return nil
	}
	state.currentWork = &work
	state.invalidLogCount = 0
	versionRolling := state.versionRolling
	versionMask := state.versionMask
	workerName := state.workerName
	state.mu.Unlock()
	if refreshDifficulty {
		if err := sendStratumNotification(conn, "mining.set_difficulty", []any{policy.ShareDifficulty}); err != nil {
			return err
		}
		if versionRolling && versionMask != "" {
			if err := sendStratumNotification(conn, "mining.set_version_mask", []any{versionMask}); err != nil {
				return err
			}
		}
	}
	s.logWorkSent(workerName, work, versionRolling, versionMask)
	return sendStratumNotification(conn, "mining.notify", work.notifyParams())
}

func (s *Service) logWorkSent(workerName string, work work, versionRolling bool, versionMask string) {
	if s.logger == nil {
		return
	}
	s.logger.Info("compute work sent",
		"worker", workerName,
		"pow_job_id", work.powJobID,
		"stratum_job_id", work.stratumID,
		"extranonce1", work.extranonce1,
		"coinb1", work.coinb1,
		"coinb2", work.coinb2,
		"prevhash", work.prevhash,
		"version", work.version,
		"nbits", work.nbits,
		"ntime", work.ntime,
		"difficulty", work.difficulty,
		"version_rolling", versionRolling,
		"version_mask", versionMask,
	)
}

func (s *Service) submitShare(conn io.Writer, state *stratumState, req stratumRequest) error {
	state.mu.Lock()
	authorized := state.authorized
	workerName := state.workerName
	versionMask := state.versionMask
	versionRolling := state.versionRolling
	if state.currentWork == nil {
		state.mu.Unlock()
		return sendStratumError(conn, req.ID, 24, "worker is not authorized for active work")
	}
	work := *state.currentWork
	state.mu.Unlock()
	if !authorized {
		return sendStratumError(conn, req.ID, 24, "worker is not authorized for active work")
	}
	worker := paramString(req.Params, 0)
	stratumJobID := paramString(req.Params, 1)
	extranonce2 := paramString(req.Params, 2)
	ntime := paramString(req.Params, 3)
	nonce := paramString(req.Params, 4)
	versionHex := work.version
	if submittedVersion := paramString(req.Params, 5); submittedVersion != "" {
		effective, err := effectiveVersionHex(work.version, submittedVersion, versionMask, versionRolling)
		if err != nil {
			_ = s.insertShare(context.Background(), state, work, "", false, err.Error())
			_ = s.touchWorkerShare(context.Background(), state, false, err.Error())
			return sendStratumResult(conn, req.ID, false)
		}
		versionHex = effective
	}
	if worker == "" {
		worker = workerName
	}
	current, err := s.runningJob(context.Background())
	if err != nil || current.id != work.powJobID {
		_ = sendStratumResult(conn, req.ID, false)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		return errCloseStratumConnection
	}
	valid, hashHex, reason := verifyShare(work, stratumJobID, extranonce2, ntime, nonce, versionHex)
	if worker != workerName {
		valid = false
		reason = "worker_mismatch"
	}
	shouldLogInvalid := false
	if !valid && s.logger != nil {
		state.mu.Lock()
		if state.invalidLogCount < 5 {
			state.invalidLogCount++
			shouldLogInvalid = true
		}
		state.mu.Unlock()
	}
	if shouldLogInvalid {
		s.logger.Info("compute share rejected",
			"worker", workerName,
			"pow_job_id", work.powJobID,
			"stratum_job_id", stratumJobID,
			"extranonce2", extranonce2,
			"ntime", ntime,
			"nonce", nonce,
			"version", versionHex,
			"hash", hashHex,
			"reason", reason,
		)
	}
	if err := s.insertShare(context.Background(), state, work, hashHex, valid, reason); err != nil {
		return err
	}
	if valid && s.reconciler != nil {
		_ = s.reconciler.Reconcile(context.Background(), state.tenantID)
	}
	if err := s.touchWorkerShare(context.Background(), state, valid, reason); err != nil {
		return err
	}
	if err := sendStratumResult(conn, req.ID, valid); err != nil {
		return err
	}
	if valid {
		stillRunning, err := s.workStillRunning(context.Background(), work.powJobID)
		if err != nil {
			return err
		}
		if !stillRunning {
			return errCloseStratumConnection
		}
	}
	return nil
}

func (s *Service) registerConnection(state *stratumState) {
	key := workerKey(state.tenantID, state.workerName)
	s.mu.Lock()
	if s.connections[key] == nil {
		s.connections[key] = map[string]struct{}{}
	}
	s.connections[key][state.id] = struct{}{}
	count := len(s.connections[key])
	s.mu.Unlock()
	status := "connected"
	if count > 1 {
		status = "conflict"
	}
	_, _ = s.db.ExecContext(context.Background(), `
UPDATE compute_workers
SET status = $1,
    last_connected_at = now(),
    last_seen_at = now(),
    updated_at = now()
WHERE id = $2`, status, state.workerID)
}

func (s *Service) unregisterConnection(ctx context.Context, state *stratumState) {
	if state.workerID == "" || state.workerName == "" || state.tenantID == "" {
		return
	}
	key := workerKey(state.tenantID, state.workerName)
	s.mu.Lock()
	if s.connections[key] != nil {
		delete(s.connections[key], state.id)
	}
	count := len(s.connections[key])
	if count == 0 {
		delete(s.connections, key)
	}
	s.mu.Unlock()
	status := "disconnected"
	if count == 1 {
		status = "connected"
	} else if count > 1 {
		status = "conflict"
	}
	_, _ = s.db.ExecContext(ctx, `
UPDATE compute_workers
SET status = $1,
    last_disconnected_at = now(),
    updated_at = now()
WHERE id = $2`, status, state.workerID)
}

func (s *Service) runningJob(ctx context.Context) (runningJob, error) {
	var job runningJob
	err := s.db.QueryRowContext(ctx, `
SELECT pj.id::text, pj.tenant_id::text, pj.user_id::text, u.username,
       pj.required_work_th::float8, pj.required_hashrate_ths::float8, pj.min_workers,
       pj.hashrate_tolerance_percent::float8, pj.proof_window_seconds, pj.max_proof_attempts,
       pj.started_at
FROM pow_jobs pj
JOIN users u ON u.id = pj.user_id
WHERE pj.status = 'running' AND pj.started_at IS NOT NULL
ORDER BY pj.started_at
LIMIT 1`).Scan(
		&job.id,
		&job.tenantID,
		&job.userID,
		&job.username,
		&job.requiredWorkTH,
		&job.requiredHashrateTHs,
		&job.minWorkers,
		&job.hashrateTolerancePercent,
		&job.proofWindowSeconds,
		&job.maxProofAttempts,
		&job.startedAt,
	)
	return job, err
}

func (s *Service) workStillRunning(ctx context.Context, powJobID string) (bool, error) {
	var running bool
	err := s.db.QueryRowContext(ctx, `
SELECT EXISTS (
  SELECT 1
  FROM pow_jobs
  WHERE id = $1 AND status = 'running'
)`, powJobID).Scan(&running)
	return running, err
}

func (s *Service) activeJob(ctx context.Context) (ActiveJob, error) {
	job, err := s.runningJob(ctx)
	if err != nil {
		return ActiveJob{}, err
	}
	validWork, workerCount, err := s.bestAttemptProgress(ctx, job.tenantID, job.id, job.startedAt, job.proofWindowSeconds, job.maxProofAttempts)
	if err != nil {
		return ActiveJob{}, err
	}
	return ActiveJob{
		ID:                       job.id,
		UserID:                   job.userID,
		Username:                 job.username,
		RequiredHashrateTHs:      job.requiredHashrateTHs,
		RequiredWorkTH:           job.requiredWorkTH,
		HashrateTolerancePercent: job.hashrateTolerancePercent,
		ProofWindowSeconds:       normalizePositiveInt(job.proofWindowSeconds, 60),
		MaxProofAttempts:         normalizePositiveInt(job.maxProofAttempts, 3),
		ValidWorkTH:              validWork,
		ValidWorkerCount:         workerCount,
		StartedAt:                job.startedAt,
	}, nil
}

func (s *Service) bestAttemptProgress(ctx context.Context, tenantID string, jobID string, startedAt time.Time, proofWindowSeconds int, maxAttempts int) (float64, int, error) {
	proofWindowSeconds = normalizePositiveInt(proofWindowSeconds, 60)
	maxAttempts = normalizePositiveInt(maxAttempts, 3)
	now := time.Now().UTC()
	bestWork := 0.0
	bestWorkers := 0
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		attemptStart := startedAt.Add(time.Duration((attempt-1)*proofWindowSeconds) * time.Second)
		if attemptStart.After(now) {
			break
		}
		var validWork float64
		var workerCount int
		if err := s.db.QueryRowContext(ctx, `
SELECT coalesce(sum(work_th), 0)::float8, count(DISTINCT compute_worker_id)::int
FROM pow_shares
WHERE tenant_id = $1
  AND pow_job_id = $2
  AND is_valid = true
  AND submitted_at >= $3
  AND submitted_at <= $3 + ($4::int * interval '1 second')`, tenantID, jobID, attemptStart, proofWindowSeconds).Scan(&validWork, &workerCount); err != nil {
			return 0, 0, err
		}
		if validWork > bestWork {
			bestWork = validWork
			bestWorkers = workerCount
		}
	}
	return bestWork, bestWorkers, nil
}

func normalizePositiveInt(value int, fallback int) int {
	if value > 0 {
		return value
	}
	return fallback
}

func (s *Service) workers(ctx context.Context) ([]Worker, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT cw.id::text, cw.tenant_id::text, cw.worker_name, cw.status, cw.reported_hashrate_ths::float8,
       cw.connection_count, cw.last_seen_at, cw.last_connected_at, cw.last_disconnected_at, cw.stats_reset_at, cw.last_ip, cw.last_error,
       count(ps.id) FILTER (WHERE ps.is_valid = true AND (cw.stats_reset_at IS NULL OR ps.submitted_at >= cw.stats_reset_at))::int AS valid_shares,
       count(ps.id) FILTER (WHERE ps.is_valid = false AND (cw.stats_reset_at IS NULL OR ps.submitted_at >= cw.stats_reset_at))::int AS invalid_shares,
       coalesce(sum(ps.work_th) FILTER (WHERE ps.is_valid = true AND (cw.stats_reset_at IS NULL OR ps.submitted_at >= cw.stats_reset_at)), 0)::float8 AS valid_work_th
FROM compute_workers cw
LEFT JOIN pow_shares ps ON ps.compute_worker_id = cw.id
GROUP BY cw.id
ORDER BY cw.updated_at DESC
LIMIT 50`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []Worker{}
	runtimeCounts := s.runtimeWorkerCounts()
	for rows.Next() {
		var item Worker
		var tenantID string
		var hashrate sql.NullFloat64
		var lastSeen sql.NullTime
		var lastConnected sql.NullTime
		var lastDisconnected sql.NullTime
		var statsReset sql.NullTime
		var lastIP sql.NullString
		var lastError sql.NullString
		if err := rows.Scan(
			&item.ID,
			&tenantID,
			&item.WorkerName,
			&item.Status,
			&hashrate,
			&item.ConnectionCount,
			&lastSeen,
			&lastConnected,
			&lastDisconnected,
			&statsReset,
			&lastIP,
			&lastError,
			&item.ValidShares,
			&item.InvalidShares,
			&item.ValidWorkTH,
		); err != nil {
			return nil, err
		}
		if hashrate.Valid {
			item.ReportedHashrateTHs = &hashrate.Float64
		}
		if lastSeen.Valid {
			item.LastSeenAt = &lastSeen.Time
		}
		if lastConnected.Valid {
			item.LastConnectedAt = &lastConnected.Time
		}
		if lastDisconnected.Valid {
			item.LastDisconnectedAt = &lastDisconnected.Time
		}
		if statsReset.Valid {
			item.StatsResetAt = &statsReset.Time
		}
		if lastIP.Valid {
			item.LastIP = lastIP.String
		}
		if lastError.Valid {
			item.LastError = lastError.String
		}
		item.RuntimeConnections = runtimeCounts[workerKey(tenantID, item.WorkerName)]
		if item.Status != "blocked" {
			switch {
			case item.RuntimeConnections > 1:
				item.Status = "conflict"
			case item.RuntimeConnections == 1:
				item.Status = "connected"
			default:
				item.Status = "disconnected"
			}
		}
		item.Conflict = item.RuntimeConnections > 1
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Service) recentShares(ctx context.Context) ([]Share, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT ps.id::text, ps.pow_job_id::text, coalesce(cw.worker_name, ''), ps.share_hash, ps.share_target,
       ps.work_th::float8, ps.is_valid, ps.rejection_reason, ps.submitted_at
FROM pow_shares ps
LEFT JOIN compute_workers cw ON cw.id = ps.compute_worker_id
ORDER BY ps.submitted_at DESC
LIMIT 20`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []Share{}
	for rows.Next() {
		var item Share
		var rejection sql.NullString
		if err := rows.Scan(&item.ID, &item.PoWJobID, &item.WorkerName, &item.ShareHash, &item.ShareTarget, &item.WorkTH, &item.IsValid, &rejection, &item.SubmittedAt); err != nil {
			return nil, err
		}
		if rejection.Valid {
			item.RejectionReason = rejection.String
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Service) runtimeWorkerCounts() map[string]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := map[string]int{}
	for key, sessions := range s.connections {
		result[key] = len(sessions)
	}
	return result
}

func (s *Service) markRuntimeWorkersDisconnected(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
UPDATE compute_workers
SET status = 'disconnected',
    last_disconnected_at = now(),
    updated_at = now()
WHERE status IN ('connected', 'conflict')`)
	return err
}

func (s *Service) resetWorkerStats(ctx context.Context, tenantID string, workerID string) (string, error) {
	var workerName string
	err := s.db.QueryRowContext(ctx, `
UPDATE compute_workers
SET stats_reset_at = now(),
    last_error = NULL,
    updated_at = now()
WHERE tenant_id = $1 AND id = $2
RETURNING worker_name`, tenantID, workerID).Scan(&workerName)
	return workerName, err
}

func (s *Service) upsertWorker(ctx context.Context, tenantID string, workerName string, peer string) (string, error) {
	var workerID string
	err := s.db.QueryRowContext(ctx, `
INSERT INTO compute_workers (tenant_id, worker_name, status, connection_count, last_seen_at, last_connected_at, last_ip)
VALUES ($1, $2, 'connected', 1, now(), now(), $3)
ON CONFLICT (tenant_id, worker_name) DO UPDATE
SET status = 'connected',
    connection_count = compute_workers.connection_count + 1,
    last_seen_at = now(),
    last_connected_at = now(),
    last_ip = EXCLUDED.last_ip,
    last_error = NULL,
    updated_at = now()
RETURNING id::text`, tenantID, workerName, peer).Scan(&workerID)
	return workerID, err
}

func (s *Service) updateWorkerError(ctx context.Context, tenantID string, workerName string, reason string) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO compute_workers (tenant_id, worker_name, status, last_error, last_seen_at)
VALUES ($1, $2, 'blocked', $3, now())
ON CONFLICT (tenant_id, worker_name) DO UPDATE
SET last_error = EXCLUDED.last_error,
    last_seen_at = now(),
    updated_at = now()`, tenantID, workerName, reason)
	return err
}

func (s *Service) touchWorkerShare(ctx context.Context, state *stratumState, valid bool, reason string) error {
	status := "connected"
	if !valid {
		status = "connected"
	}
	_, err := s.db.ExecContext(ctx, `
UPDATE compute_workers
SET status = $1,
    last_seen_at = now(),
    last_error = $2,
    updated_at = now()
WHERE id = $3`, status, nullableString(reason), state.workerID)
	return err
}

func (s *Service) insertShare(ctx context.Context, state *stratumState, work work, hashHex string, valid bool, reason string) error {
	if hashHex == "" {
		hashHex = strings.Repeat("0", 64)
	}
	workTH := 0.0
	if valid {
		workTH = work.workTH
		reason = ""
	}
	_, err := s.db.ExecContext(ctx, `
INSERT INTO pow_shares (tenant_id, pow_job_id, compute_worker_id, share_hash, share_target, work_th, is_valid, rejection_reason)
VALUES ($1, $2, $3, $4, $5, $6, $7, nullif($8, ''))`,
		state.tenantID, work.powJobID, state.workerID, hashHex, work.targetHex, workTH, valid, reason,
	)
	return err
}

func buildWork(job runningJob, extranonce1 string, policy Policy) (work, error) {
	target, err := targetForDifficulty(policy.ShareDifficulty)
	if err != nil {
		return work{}, err
	}
	stratumID := strings.ReplaceAll(job.id, "-", "")
	if len(stratumID) > 24 {
		stratumID = stratumID[:24]
	}
	seed := sha256.Sum256([]byte("archivon-phase1h:" + job.id + ":" + job.startedAt.Format(time.RFC3339Nano)))
	coinb1, coinb2, err := buildValidCoinbaseParts(extranonce1, policy.Extranonce2Size)
	if err != nil {
		return work{}, err
	}
	return work{
		powJobID:    job.id,
		stratumID:   stratumID,
		extranonce1: extranonce1,
		coinb1:      coinb1,
		coinb2:      coinb2,
		prevhash:    hex.EncodeToString(seed[:]),
		version:     "20000000",
		nbits:       "1d00ffff",
		ntime:       fmt.Sprintf("%08x", time.Now().UTC().Unix()),
		targetHex:   fmt.Sprintf("%064x", target),
		difficulty:  policy.ShareDifficulty,
		workTH:      policy.ShareDifficulty * diff1WorkTH,
	}, nil
}

func buildValidCoinbaseParts(extranonce1 string, extranonce2Size int) (string, string, error) {
	n1, err := hex.DecodeString(strings.TrimSpace(extranonce1))
	if err != nil {
		return "", "", errors.New("invalid_extranonce1")
	}
	if extranonce2Size < 0 {
		return "", "", errors.New("invalid_extranonce2_size")
	}
	prefix := append([]byte{0x03, 0x01, 0x00, 0x00}, []byte("Archivon")...)
	scriptLen := len(prefix) + len(n1) + extranonce2Size

	coinb1 := make([]byte, 0, 4+1+32+4+9+len(prefix))
	coinb1 = append(coinb1, 0x01, 0x00, 0x00, 0x00)
	coinb1 = append(coinb1, 0x01)
	coinb1 = append(coinb1, make([]byte, 32)...)
	coinb1 = append(coinb1, 0xff, 0xff, 0xff, 0xff)
	coinb1 = append(coinb1, compactSize(scriptLen)...)
	coinb1 = append(coinb1, prefix...)

	coinb2 := []byte{
		0xff, 0xff, 0xff, 0xff,
		0x01,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x01,
		0x51,
		0x00, 0x00, 0x00, 0x00,
	}
	return hex.EncodeToString(coinb1), hex.EncodeToString(coinb2), nil
}

func compactSize(value int) []byte {
	switch {
	case value < 0:
		return []byte{0x00}
	case value < 253:
		return []byte{byte(value)}
	case value <= 0xffff:
		return []byte{0xfd, byte(value), byte(value >> 8)}
	case value <= 0xffffffff:
		return []byte{0xfe, byte(value), byte(value >> 8), byte(value >> 16), byte(value >> 24)}
	default:
		return []byte{0xff, byte(value), byte(value >> 8), byte(value >> 16), byte(value >> 24), byte(value >> 32), byte(value >> 40), byte(value >> 48), byte(value >> 56)}
	}
}

func (w work) notifyParams() []any {
	return []any{
		w.stratumID,
		w.prevhash,
		w.coinb1,
		w.coinb2,
		[]string{},
		w.version,
		w.nbits,
		w.ntime,
		true,
	}
}

func verifyShare(work work, stratumJobID string, extranonce2 string, ntime string, nonce string, versionHex string) (bool, string, string) {
	if stratumJobID != work.stratumID {
		return false, "", "job_id_mismatch"
	}
	if !hexLen(versionHex, 8) {
		return false, "", "invalid_version"
	}
	if !hexLen(extranonce2, 8) {
		return false, "", "invalid_extranonce2"
	}
	if !hexLen(ntime, 8) || strings.ToLower(ntime) != work.ntime {
		return false, "", "invalid_ntime"
	}
	if !hexLen(nonce, 8) {
		return false, "", "invalid_nonce"
	}
	coinbase, err := hex.DecodeString(work.coinb1 + work.extranonce1 + strings.ToLower(extranonce2) + work.coinb2)
	if err != nil {
		return false, "", "invalid_coinbase"
	}
	merkle := sha256d(coinbase)
	header, err := stratumHeaderBytes(versionHex, work.prevhash, merkle, ntime, work.nbits, nonce)
	if err != nil {
		return false, "", "invalid_header"
	}
	hash := sha256d(header)
	blockHash := reverseBytes(hash)
	hashHex := hex.EncodeToString(blockHash)
	target, ok := new(big.Int).SetString(work.targetHex, 16)
	if !ok {
		return false, hashHex, "invalid_target"
	}
	hashInt := new(big.Int).SetBytes(blockHash)
	if hashInt.Cmp(target) <= 0 {
		return true, hashHex, ""
	}
	return false, hashHex, "hash_above_target"
}

func stratumHeaderBytes(versionHex string, prevhash string, merkle []byte, ntime string, nbits string, nonce string) ([]byte, error) {
	version, err := reverseHexBytes(versionHex)
	if err != nil {
		return nil, err
	}
	previous, err := reverseHexWords(prevhash)
	if err != nil {
		return nil, err
	}
	timeBytes, err := reverseHexBytes(ntime)
	if err != nil {
		return nil, err
	}
	bits, err := reverseHexBytes(nbits)
	if err != nil {
		return nil, err
	}
	nonceBytes, err := reverseHexBytes(nonce)
	if err != nil {
		return nil, err
	}
	header := make([]byte, 0, 80)
	header = append(header, version...)
	header = append(header, previous...)
	header = append(header, merkle...)
	header = append(header, timeBytes...)
	header = append(header, bits...)
	header = append(header, nonceBytes...)
	if len(header) != 80 {
		return nil, errors.New("invalid_header_length")
	}
	return header, nil
}

func reverseHexBytes(value string) ([]byte, error) {
	raw, err := hex.DecodeString(strings.ToLower(strings.TrimSpace(value)))
	if err != nil {
		return nil, err
	}
	return reverseBytes(raw), nil
}

func reverseHexWords(value string) ([]byte, error) {
	raw, err := hex.DecodeString(strings.ToLower(strings.TrimSpace(value)))
	if err != nil {
		return nil, err
	}
	if len(raw)%4 != 0 {
		return nil, errors.New("invalid_word_length")
	}
	result := make([]byte, len(raw))
	for i := 0; i < len(raw); i += 4 {
		result[i] = raw[i+3]
		result[i+1] = raw[i+2]
		result[i+2] = raw[i+1]
		result[i+3] = raw[i]
	}
	return result, nil
}

func reverseBytes(raw []byte) []byte {
	result := make([]byte, len(raw))
	for i := range raw {
		result[len(raw)-1-i] = raw[i]
	}
	return result
}

func (s *Service) loadPolicy(ctx context.Context) (Policy, error) {
	var raw []byte
	if err := s.db.QueryRowContext(ctx, `SELECT value FROM system_settings WHERE key = $1`, computePolicyKey).Scan(&raw); err != nil {
		return Policy{}, err
	}
	var policy Policy
	if err := json.Unmarshal(raw, &policy); err != nil {
		return Policy{}, err
	}
	return normalizePolicy(policy, s.listenAddress), nil
}

func normalizePolicy(policy Policy, listenAddress string) Policy {
	if strings.TrimSpace(policy.BindAddress) == "" {
		policy.BindAddress = listenAddress
	}
	if strings.TrimSpace(listenAddress) != "" {
		policy.BindAddress = listenAddress
	}
	if policy.StratumPort <= 0 {
		policy.StratumPort = portFromAddress(policy.BindAddress, 3333)
	}
	if policy.ShareDifficulty <= 0 {
		policy.ShareDifficulty = 0.0025
	}
	if policy.Extranonce2Size <= 0 {
		policy.Extranonce2Size = 4
	}
	if policy.PasswordHash != "" {
		policy.PasswordConfigured = true
	}
	return policy
}

func sanitizePolicy(policy Policy) Policy {
	policy.PasswordHash = ""
	return policy
}

func validatePolicy(policy Policy) error {
	if policy.ShareDifficulty <= 0 || math.IsNaN(policy.ShareDifficulty) || math.IsInf(policy.ShareDifficulty, 0) {
		return errors.New("share_difficulty_invalid")
	}
	if policy.ShareDifficulty > 1_000_000 {
		return errors.New("share_difficulty_too_high")
	}
	if policy.Extranonce2Size != 4 {
		return errors.New("extranonce2_size_unsupported")
	}
	return nil
}

func targetForDifficulty(difficulty float64) (*big.Int, error) {
	if difficulty <= 0 || math.IsNaN(difficulty) || math.IsInf(difficulty, 0) {
		return nil, errors.New("invalid difficulty")
	}
	diff1, _ := new(big.Int).SetString(diff1TargetHex, 16)
	maxTarget, _ := new(big.Int).SetString(maxTargetHex, 16)
	value := new(big.Float).SetPrec(256).SetInt(diff1)
	value.Quo(value, new(big.Float).SetPrec(256).SetFloat64(difficulty))
	target, _ := value.Int(nil)
	if target.Sign() <= 0 {
		return nil, errors.New("target is zero")
	}
	if target.Cmp(maxTarget) > 0 {
		target = maxTarget
	}
	return target, nil
}

func sha256d(data []byte) []byte {
	first := sha256.Sum256(data)
	second := sha256.Sum256(first[:])
	return second[:]
}

func (s *Service) defaultTenantID(ctx context.Context) (string, error) {
	var tenantID string
	err := s.db.QueryRowContext(ctx, `SELECT id::text FROM tenants WHERE slug = 'default' LIMIT 1`).Scan(&tenantID)
	return tenantID, err
}

func (s *Service) insertAuditEvent(ctx context.Context, tenantID string, actorUserID string, eventType string, targetType string, targetID *string, severity string, ipAddress string, details map[string]any) error {
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
	_, err = s.db.ExecContext(ctx, `
INSERT INTO audit_events (tenant_id, actor_user_id, event_type, target_type, target_id, severity, ip_address, details)
VALUES ($1, $2, $3, nullif($4, ''), $5, $6, nullif($7, ''), $8::jsonb)`,
		tenantID, actor, eventType, targetType, target, severity, ipAddress, string(rawDetails),
	)
	return err
}

func sendStratumResult(writer io.Writer, id any, result any) error {
	return sendStratum(writer, map[string]any{"id": id, "result": result, "error": nil})
}

func sendStratumError(writer io.Writer, id any, code int, message string) error {
	return sendStratum(writer, map[string]any{"id": id, "result": nil, "error": []any{code, message, nil}})
}

func sendStratumNotification(writer io.Writer, method string, params []any) error {
	return sendStratum(writer, map[string]any{"id": nil, "method": method, "params": params})
}

func sendStratum(writer io.Writer, payload any) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	_, err = writer.Write(raw)
	return err
}

func paramString(params []any, index int) string {
	if index >= len(params) || params[index] == nil {
		return ""
	}
	switch value := params[index].(type) {
	case string:
		return strings.TrimSpace(value)
	case float64:
		return strconv.FormatFloat(value, 'f', -1, 64)
	default:
		return strings.TrimSpace(fmt.Sprint(value))
	}
}

func stratumExtensionNames(params []any) []string {
	if len(params) == 0 || params[0] == nil {
		return nil
	}
	values, ok := params[0].([]any)
	if !ok {
		return nil
	}
	names := make([]string, 0, len(values))
	for _, value := range values {
		name, ok := value.(string)
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		if name != "" {
			names = append(names, name)
		}
	}
	return names
}

func computeWorkerActionPath(path string) (string, string, bool) {
	rest := strings.TrimPrefix(path, "/api/admin/compute/workers/")
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}

func stratumExtensionRequested(names []string, target string) bool {
	for _, name := range names {
		if name == target {
			return true
		}
	}
	return false
}

func requestedVersionRollingMask(params []any) string {
	if len(params) < 2 || params[1] == nil {
		return versionRollingMaskDefault
	}
	options, ok := params[1].(map[string]any)
	if !ok {
		return versionRollingMaskDefault
	}
	mask, ok := options["version-rolling.mask"].(string)
	if !ok {
		return versionRollingMaskDefault
	}
	mask = strings.ToLower(strings.TrimSpace(mask))
	if !hexLen(mask, 8) || mask == "00000000" {
		return versionRollingMaskDefault
	}
	return mask
}

func effectiveVersionHex(baseVersion string, submittedVersion string, mask string, enabled bool) (string, error) {
	if !enabled {
		return "", errors.New("version_rolling_not_configured")
	}
	baseVersion = strings.ToLower(strings.TrimSpace(baseVersion))
	submittedVersion = strings.ToLower(strings.TrimSpace(submittedVersion))
	mask = strings.ToLower(strings.TrimSpace(mask))
	if !hexLen(baseVersion, 8) {
		return "", errors.New("invalid_base_version")
	}
	if !hexLen(submittedVersion, 8) {
		return "", errors.New("invalid_version_bits")
	}
	if !hexLen(mask, 8) || mask == "00000000" {
		mask = versionRollingMaskDefault
	}
	baseValue, err := strconv.ParseUint(baseVersion, 16, 32)
	if err != nil {
		return "", errors.New("invalid_base_version")
	}
	submittedValue, err := strconv.ParseUint(submittedVersion, 16, 32)
	if err != nil {
		return "", errors.New("invalid_version_bits")
	}
	maskValue, err := strconv.ParseUint(mask, 16, 32)
	if err != nil {
		return "", errors.New("invalid_version_mask")
	}
	effective := (uint32(baseValue) &^ uint32(maskValue)) | (uint32(submittedValue) & uint32(maskValue))
	return fmt.Sprintf("%08x", effective), nil
}

func randomHex(bytesLen int) string {
	raw := make([]byte, bytesLen)
	if _, err := rand.Read(raw); err != nil {
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(raw)
}

func hexLen(value string, length int) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	if len(value) != length {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func workerKey(tenantID string, workerName string) string {
	return tenantID + "\x00" + workerName
}

func portFromAddress(address string, fallback int) int {
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		if strings.HasPrefix(address, ":") {
			port = strings.TrimPrefix(address, ":")
		} else {
			return fallback
		}
	}
	parsed, err := strconv.Atoi(port)
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}

func nullableString(value string) any {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	return value
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
