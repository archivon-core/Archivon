package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	APIAddress            string
	ComputeGatewayAddress string
	Environment           string
	StoragePath           string
	MasterKeyPath         string
	KMSProvider           string
	KMSKeyID              string
	DatabaseDSN           string
	MigrationsPath        string
	AuthSessionTTL        time.Duration
	CookieSecure          bool
}

func Load() Config {
	return Config{
		APIAddress:            env("ARCHIVON_API_ADDR", ":8080"),
		ComputeGatewayAddress: env("ARCHIVON_COMPUTE_STRATUM_ADDR", ":3333"),
		Environment:           env("ARCHIVON_ENV", "dev"),
		StoragePath:           env("ARCHIVON_STORAGE_PATH", "/var/lib/archivon/storage"),
		MasterKeyPath:         env("ARCHIVON_MASTER_KEY_PATH", "/run/archivon/master.key"),
		KMSProvider:           env("ARCHIVON_KMS_PROVIDER", "local-file"),
		KMSKeyID:              env("ARCHIVON_KMS_KEY_ID", "local-master-v1"),
		DatabaseDSN:           env("ARCHIVON_DATABASE_DSN", ""),
		MigrationsPath:        env("ARCHIVON_MIGRATIONS_PATH", "/opt/archivon/migrations"),
		AuthSessionTTL:        time.Duration(envInt("ARCHIVON_AUTH_SESSION_TTL_HOURS", 12)) * time.Hour,
		CookieSecure:          envBool("ARCHIVON_COOKIE_SECURE", false),
	}
}

func (cfg Config) Validate() error {
	var errs []error
	if strings.TrimSpace(cfg.APIAddress) == "" {
		errs = append(errs, errors.New("ARCHIVON_API_ADDR is required"))
	}
	if strings.TrimSpace(cfg.ComputeGatewayAddress) == "" {
		errs = append(errs, errors.New("ARCHIVON_COMPUTE_STRATUM_ADDR is required"))
	}
	switch cfg.Environment {
	case "dev", "test", "preprod":
	default:
		errs = append(errs, fmt.Errorf("ARCHIVON_ENV must be dev, test, or preprod; got %q", cfg.Environment))
	}
	if strings.TrimSpace(cfg.StoragePath) == "" {
		errs = append(errs, errors.New("ARCHIVON_STORAGE_PATH is required"))
	}
	if strings.TrimSpace(cfg.MasterKeyPath) == "" {
		errs = append(errs, errors.New("ARCHIVON_MASTER_KEY_PATH is required"))
	}
	if strings.TrimSpace(cfg.KMSProvider) == "" {
		errs = append(errs, errors.New("ARCHIVON_KMS_PROVIDER is required"))
	} else if cfg.KMSProvider != "local-file" {
		errs = append(errs, fmt.Errorf("ARCHIVON_KMS_PROVIDER must be local-file for the current pre-production phase; got %q", cfg.KMSProvider))
	}
	if strings.TrimSpace(cfg.KMSKeyID) == "" {
		errs = append(errs, errors.New("ARCHIVON_KMS_KEY_ID is required"))
	}
	if strings.TrimSpace(cfg.DatabaseDSN) == "" {
		errs = append(errs, errors.New("ARCHIVON_DATABASE_DSN is required"))
	} else if _, err := url.Parse(cfg.DatabaseDSN); err != nil {
		errs = append(errs, fmt.Errorf("ARCHIVON_DATABASE_DSN is invalid: %w", err))
	}
	if strings.TrimSpace(cfg.MigrationsPath) == "" {
		errs = append(errs, errors.New("ARCHIVON_MIGRATIONS_PATH is required"))
	}
	if cfg.AuthSessionTTL <= 0 {
		errs = append(errs, errors.New("ARCHIVON_AUTH_SESSION_TTL_HOURS must be positive"))
	}
	return errors.Join(errs...)
}

func (cfg Config) RedactedDatabaseDSN() string {
	parsed, err := url.Parse(cfg.DatabaseDSN)
	if err != nil {
		return "invalid"
	}
	if parsed.User != nil {
		username := parsed.User.Username()
		parsed.User = url.UserPassword(username, "redacted")
	}
	return parsed.String()
}

func env(key string, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}

func envInt(key string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func envBool(key string, fallback bool) bool {
	value := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	if value == "" {
		return fallback
	}
	switch value {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return fallback
	}
}
