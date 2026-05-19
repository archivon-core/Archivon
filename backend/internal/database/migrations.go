package database

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type MigrationStatus struct {
	LatestVersion     string `json:"latest_version"`
	AppliedMigrations int    `json:"applied_migrations"`
}

type migrationFile struct {
	Version  string
	Name     string
	Path     string
	SQL      string
	Checksum string
}

var acceptedLegacyMigrationChecksums = map[string]map[string]struct{}{
	// These checksums belong to pre-production deployments created before the file
	// upload timestamp cleanup. Clean installs use the current SQL files, while
	// existing deployments keep their recorded historical checksums.
	"0001_phase1_foundation": {
		"e723c06265733c54543a956f265616d594c66cd06eaff288b3b5f835859646b5": {},
	},
	"0004_phase1d_kms_key_management": {
		"8d7b24da4fc93cd21e676deac5313da7bbce1b7a084af6c6a753059495e774ab": {},
	},
	"0005_phase1e_encrypted_storage": {
		"7c77f745ae37c029ba3482f913c66c334c979e997340795fddd78615c97cf1a7": {},
	},
}

func ApplyMigrations(ctx context.Context, db *sql.DB, migrationsPath string, logger *slog.Logger) (MigrationStatus, error) {
	files, err := loadMigrationFiles(migrationsPath)
	if err != nil {
		return MigrationStatus{}, err
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return MigrationStatus{}, err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	if _, err := tx.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS schema_migrations (
  version text PRIMARY KEY,
  name text NOT NULL,
  checksum text NOT NULL,
  applied_at timestamptz NOT NULL DEFAULT now()
)`); err != nil {
		return MigrationStatus{}, err
	}

	status := MigrationStatus{}
	for _, file := range files {
		appliedChecksum, found, err := appliedMigration(ctx, tx, file.Version)
		if err != nil {
			return MigrationStatus{}, err
		}
		if found {
			if appliedChecksum != file.Checksum && !isAcceptedLegacyMigrationChecksum(file.Version, appliedChecksum) {
				return MigrationStatus{}, fmt.Errorf("migration %s checksum mismatch", file.Version)
			}
			if appliedChecksum != file.Checksum {
				logger.Warn("accepted legacy migration checksum", "version", file.Version)
			}
			status.LatestVersion = file.Version
			status.AppliedMigrations++
			continue
		}

		logger.Info("applying database migration", "version", file.Version, "name", file.Name)
		if _, err := tx.ExecContext(ctx, file.SQL); err != nil {
			return MigrationStatus{}, fmt.Errorf("apply migration %s: %w", file.Name, err)
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO schema_migrations (version, name, checksum, applied_at) VALUES ($1, $2, $3, $4)`,
			file.Version, file.Name, file.Checksum, time.Now().UTC(),
		); err != nil {
			return MigrationStatus{}, err
		}
		status.LatestVersion = file.Version
		status.AppliedMigrations++
	}

	if err := tx.Commit(); err != nil {
		return MigrationStatus{}, err
	}
	return status, nil
}

func isAcceptedLegacyMigrationChecksum(version string, checksum string) bool {
	checksums, ok := acceptedLegacyMigrationChecksums[version]
	if !ok {
		return false
	}
	_, ok = checksums[checksum]
	return ok
}

func SchemaStatus(ctx context.Context, db *sql.DB) string {
	if db == nil {
		return "not_configured"
	}
	queryCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	var count int
	if err := db.QueryRowContext(queryCtx, `SELECT count(*) FROM schema_migrations`).Scan(&count); err != nil {
		return "missing_or_error"
	}
	if count == 0 {
		return "empty"
	}
	return "ok"
}

func loadMigrationFiles(migrationsPath string) ([]migrationFile, error) {
	entries, err := os.ReadDir(filepath.Clean(migrationsPath))
	if err != nil {
		return nil, fmt.Errorf("read migrations path: %w", err)
	}

	var files []migrationFile
	for _, entry := range entries {
		if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") || !strings.HasSuffix(entry.Name(), ".up.sql") {
			continue
		}
		version, ok := strings.CutSuffix(entry.Name(), ".up.sql")
		if !ok || strings.TrimSpace(version) == "" {
			continue
		}
		path := filepath.Join(migrationsPath, entry.Name())
		raw, err := os.ReadFile(filepath.Clean(path))
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(raw)
		files = append(files, migrationFile{
			Version:  version,
			Name:     entry.Name(),
			Path:     path,
			SQL:      string(raw),
			Checksum: hex.EncodeToString(sum[:]),
		})
	}
	sort.Slice(files, func(i, j int) bool {
		return files[i].Name < files[j].Name
	})
	if len(files) == 0 {
		return nil, fmt.Errorf("no .up.sql migrations found in %s", migrationsPath)
	}
	return files, nil
}

func appliedMigration(ctx context.Context, tx *sql.Tx, version string) (string, bool, error) {
	var checksum string
	err := tx.QueryRowContext(ctx, `SELECT checksum FROM schema_migrations WHERE version = $1`, version).Scan(&checksum)
	if err == nil {
		return checksum, true, nil
	}
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	return "", false, err
}
