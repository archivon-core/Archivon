package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func OpenWithRetry(ctx context.Context, dsn string, logger *slog.Logger) (*sql.DB, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(16)
	db.SetMaxIdleConns(4)
	db.SetConnMaxLifetime(30 * time.Minute)

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	deadline := time.After(60 * time.Second)
	for {
		pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		err = db.PingContext(pingCtx)
		cancel()
		if err == nil {
			return db, nil
		}

		logger.Warn("database not ready", "error", err)
		select {
		case <-ctx.Done():
			_ = db.Close()
			return nil, ctx.Err()
		case <-deadline:
			_ = db.Close()
			return nil, fmt.Errorf("database ping timeout: %w", err)
		case <-ticker.C:
		}
	}
}

func Ping(ctx context.Context, db *sql.DB) string {
	if db == nil {
		return "not_configured"
	}
	pingCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := db.PingContext(pingCtx); err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return "timeout"
		}
		return "error"
	}
	return "ok"
}
