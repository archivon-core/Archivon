package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"time"

	"archivon/backend/internal/access"
	"archivon/backend/internal/archive"
	"archivon/backend/internal/audit"
	"archivon/backend/internal/auth"
	"archivon/backend/internal/compute"
	"archivon/backend/internal/config"
	"archivon/backend/internal/database"
	"archivon/backend/internal/health"
	"archivon/backend/internal/kms"
)

type statusResponse struct {
	Status      string                    `json:"status"`
	Service     string                    `json:"service"`
	Phase       string                    `json:"phase"`
	Environment string                    `json:"environment"`
	Time        string                    `json:"time"`
	Checks      map[string]string         `json:"checks,omitempty"`
	Migrations  *database.MigrationStatus `json:"migrations,omitempty"`
	Runtime     map[string]string         `json:"runtime,omitempty"`
	KMS         *kms.Status               `json:"kms,omitempty"`
}

const productPhase = "phase1r"

func main() {
	cfg := config.Load()
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	if err := cfg.Validate(); err != nil {
		logger.Error("invalid configuration", "error", err)
		os.Exit(1)
	}

	ctx := context.Background()
	db, err := database.OpenWithRetry(ctx, cfg.DatabaseDSN, logger)
	if err != nil {
		logger.Error("database connection failed", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	migrationStatus, err := database.ApplyMigrations(ctx, db, cfg.MigrationsPath, logger)
	if err != nil {
		logger.Error("database migrations failed", "error", err)
		os.Exit(1)
	}
	authService := auth.NewService(db, logger, auth.Options{
		SessionTTL:   cfg.AuthSessionTTL,
		CookieSecure: cfg.CookieSecure,
	})
	kmsService := kms.NewService(db, logger, kms.Options{
		Provider:      cfg.KMSProvider,
		MasterKeyPath: cfg.MasterKeyPath,
		KeyID:         cfg.KMSKeyID,
	})
	archiveService := archive.NewService(db, logger, kmsService, authService, archive.Options{
		StoragePath: cfg.StoragePath,
	})
	if kmsService.Ready(ctx) {
		if err := archiveService.BackfillFolderPoWPolicySeals(ctx); err != nil {
			logger.Error("folder pow policy seal verification failed", "error", err)
			os.Exit(1)
		}
	} else {
		logger.Warn("folder pow policy seal backfill postponed until kms is ready")
	}
	auditService := audit.NewService(db, logger, authService)
	accessService := access.NewService(db, logger, authService, kmsService)
	computeService := compute.NewService(db, logger, authService, accessService, compute.Options{
		ListenAddress: cfg.ComputeGatewayAddress,
	})
	accessService.SetNodeLinkProvider(computeService)

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", handleHealth(cfg))
	mux.HandleFunc("/readyz", handleReady(cfg, db, migrationStatus, authService, kmsService))
	mux.HandleFunc("/system/status", handleSystemStatus(cfg, db, migrationStatus, authService, kmsService))
	authService.Register(mux)
	mux.Handle("/api/kms/status", authService.RequireRole(http.HandlerFunc(kmsService.HandleStatus), "super_admin", "admin"))
	archiveService.Register(mux)
	auditService.Register(mux)
	accessService.Register(mux)
	computeService.Register(mux)

	server := &http.Server{
		Addr:              cfg.APIAddress,
		Handler:           requestLogger(logger, mux),
		ReadHeaderTimeout: 5 * time.Second,
	}

	if err := computeService.Start(ctx); err != nil {
		logger.Error("compute stratum gateway failed to start", "error", err, "address", cfg.ComputeGatewayAddress)
		os.Exit(1)
	}

	logger.Info(
		"archivon api starting",
		"address", cfg.APIAddress,
		"compute_stratum_address", cfg.ComputeGatewayAddress,
		"environment", cfg.Environment,
		"database", cfg.RedactedDatabaseDSN(),
		"latest_migration", migrationStatus.LatestVersion,
	)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("archivon api stopped", "error", err)
		os.Exit(1)
	}
}

func handleHealth(cfg config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, statusResponse{
			Status:      "ok",
			Service:     "archivon-api",
			Phase:       productPhase,
			Environment: cfg.Environment,
			Time:        time.Now().UTC().Format(time.RFC3339),
		})
	}
}

func handleReady(cfg config.Config, db *sql.DB, migrations database.MigrationStatus, authService *auth.Service, kmsService *kms.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		kmsStatus := kmsService.Status(r.Context())
		checks := readinessChecks(r.Context(), cfg, db, authService, kmsStatus)
		status := "ready"
		code := http.StatusOK
		for key, value := range checks {
			if !readyValue(key, value) {
				status = "not_ready"
				code = http.StatusServiceUnavailable
				break
			}
		}
		writeJSON(w, code, statusResponse{
			Status:      status,
			Service:     "archivon-api",
			Phase:       productPhase,
			Environment: cfg.Environment,
			Time:        time.Now().UTC().Format(time.RFC3339),
			Checks:      checks,
			Migrations:  &migrations,
			KMS:         &kmsStatus,
		})
	}
}

func handleSystemStatus(cfg config.Config, db *sql.DB, migrations database.MigrationStatus, authService *auth.Service, kmsService *kms.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		kmsStatus := kmsService.Status(r.Context())
		writeJSON(w, http.StatusOK, statusResponse{
			Status:      productPhase,
			Service:     "archivon-api",
			Phase:       productPhase,
			Environment: cfg.Environment,
			Time:        time.Now().UTC().Format(time.RFC3339),
			Checks:      readinessChecks(r.Context(), cfg, db, authService, kmsStatus),
			Migrations:  &migrations,
			Runtime: map[string]string{
				"storage_path":         cfg.StoragePath,
				"master_key_path":      cfg.MasterKeyPath,
				"migrations_path":      cfg.MigrationsPath,
				"auth_session_ttl":     cfg.AuthSessionTTL.String(),
				"kms_provider":         cfg.KMSProvider,
				"kms_key_id":           cfg.KMSKeyID,
				"compute_stratum_addr": cfg.ComputeGatewayAddress,
			},
			KMS: &kmsStatus,
		})
	}
}

func readinessChecks(ctx context.Context, cfg config.Config, db *sql.DB, authService *auth.Service, kmsStatus kms.Status) map[string]string {
	return map[string]string{
		"config":     "ok",
		"storage":    health.PathState(cfg.StoragePath, true),
		"kms":        kmsStatus.State,
		"master_key": kmsStatus.State,
		"database":   database.Ping(ctx, db),
		"schema":     database.SchemaStatus(ctx, db),
		"migrations": "ok",
		"bootstrap":  authService.BootstrapState(ctx),
	}
}

func readyValue(key string, value string) bool {
	if key == "bootstrap" {
		return value == "required" || value == "complete"
	}
	if key == "kms" || key == "master_key" {
		return value == "ready"
	}
	return value == "ok"
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		slog.Error("failed to write response", "error", err)
	}
}

func requestLogger(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(recorder, r)
		logger.Info(
			"request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", recorder.status,
			"bytes", recorder.bytes,
			"duration_ms", time.Since(started).Milliseconds(),
		)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func (r *statusRecorder) Write(payload []byte) (int, error) {
	written, err := r.ResponseWriter.Write(payload)
	r.bytes += written
	return written, err
}
