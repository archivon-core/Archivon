package kms

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	DefaultProvider = "local-file"
	DefaultKeyID    = "local-master-v1"
	minKeyBytes     = 32
)

type Service struct {
	db            *sql.DB
	logger        *slog.Logger
	provider      string
	masterKeyPath string
	keyID         string
}

type Options struct {
	Provider      string
	MasterKeyPath string
	KeyID         string
}

type Status struct {
	Provider    string    `json:"provider"`
	State       string    `json:"state"`
	Available   bool      `json:"available"`
	KeyID       string    `json:"key_id"`
	Algorithm   string    `json:"algorithm"`
	Source      string    `json:"source,omitempty"`
	Format      string    `json:"format,omitempty"`
	Fingerprint string    `json:"fingerprint,omitempty"`
	Reason      string    `json:"reason,omitempty"`
	CheckedAt   time.Time `json:"checked_at"`
	MinKeyBytes int       `json:"min_key_bytes"`
}

type WrappedDataKey struct {
	KeyID       string `json:"key_id"`
	Provider    string `json:"provider"`
	Algorithm   string `json:"algorithm"`
	Nonce       string `json:"nonce"`
	Ciphertext  string `json:"ciphertext"`
	Fingerprint string `json:"fingerprint"`
}

type loadedKey struct {
	status      Status
	kek         []byte
	metadataKey []byte
	sealKey     []byte
}

func NewService(db *sql.DB, logger *slog.Logger, opts Options) *Service {
	provider := strings.TrimSpace(opts.Provider)
	if provider == "" {
		provider = DefaultProvider
	}
	keyID := strings.TrimSpace(opts.KeyID)
	if keyID == "" {
		keyID = DefaultKeyID
	}
	return &Service{
		db:            db,
		logger:        logger,
		provider:      provider,
		masterKeyPath: opts.MasterKeyPath,
		keyID:         keyID,
	}
}

func (s *Service) HandleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		return
	}
	writeJSON(w, http.StatusOK, s.Status(r.Context()))
}

func (s *Service) Status(ctx context.Context) Status {
	loaded := s.loadKey(ctx)
	if loaded.status.Available {
		if err := s.upsertKeySlot(ctx, loaded.status); err != nil && s.logger != nil {
			s.logger.Warn("kms key slot sync failed", "error", err)
		}
	}
	zeroBytes(loaded.kek)
	zeroBytes(loaded.metadataKey)
	zeroBytes(loaded.sealKey)
	return loaded.status
}

func (s *Service) State(ctx context.Context) string {
	return s.Status(ctx).State
}

func (s *Service) Ready(ctx context.Context) bool {
	return s.Status(ctx).Available
}

func (s *Service) WrapDataKey(ctx context.Context, plaintext []byte, aad []byte) (WrappedDataKey, error) {
	if len(plaintext) == 0 {
		return WrappedDataKey{}, errors.New("plaintext data key is empty")
	}
	loaded := s.loadKey(ctx)
	defer zeroBytes(loaded.kek)
	if !loaded.status.Available {
		return WrappedDataKey{}, errors.New(loaded.status.State)
	}

	block, err := aes.NewCipher(loaded.kek)
	if err != nil {
		return WrappedDataKey{}, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return WrappedDataKey{}, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return WrappedDataKey{}, err
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, aad)
	return WrappedDataKey{
		KeyID:       loaded.status.KeyID,
		Provider:    loaded.status.Provider,
		Algorithm:   "AES-256-GCM",
		Nonce:       base64.RawURLEncoding.EncodeToString(nonce),
		Ciphertext:  base64.RawURLEncoding.EncodeToString(ciphertext),
		Fingerprint: loaded.status.Fingerprint,
	}, nil
}

func (s *Service) UnwrapDataKey(ctx context.Context, wrapped WrappedDataKey, aad []byte) ([]byte, error) {
	loaded := s.loadKey(ctx)
	defer zeroBytes(loaded.kek)
	if !loaded.status.Available {
		return nil, errors.New(loaded.status.State)
	}
	if wrapped.Provider != loaded.status.Provider {
		return nil, errors.New("kms_provider_mismatch")
	}
	if wrapped.KeyID != loaded.status.KeyID {
		return nil, errors.New("kms_key_id_mismatch")
	}
	if wrapped.Algorithm != "AES-256-GCM" {
		return nil, errors.New("kms_wrapped_key_algorithm_unsupported")
	}

	nonce, err := base64.RawURLEncoding.DecodeString(wrapped.Nonce)
	if err != nil {
		return nil, errors.New("kms_wrapped_key_nonce_invalid")
	}
	ciphertext, err := base64.RawURLEncoding.DecodeString(wrapped.Ciphertext)
	if err != nil {
		return nil, errors.New("kms_wrapped_key_ciphertext_invalid")
	}
	block, err := aes.NewCipher(loaded.kek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, errors.New("kms_wrapped_key_auth_failed")
	}
	return plaintext, nil
}

func (s *Service) EncryptMetadata(ctx context.Context, plaintext []byte, aad []byte) ([]byte, []byte, error) {
	loaded := s.loadKey(ctx)
	defer zeroBytes(loaded.metadataKey)
	if !loaded.status.Available {
		return nil, nil, errors.New(loaded.status.State)
	}
	block, err := aes.NewCipher(loaded.metadataKey)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	return nonce, gcm.Seal(nil, nonce, plaintext, aad), nil
}

func (s *Service) DecryptMetadata(ctx context.Context, nonce []byte, ciphertext []byte, aad []byte) ([]byte, error) {
	loaded := s.loadKey(ctx)
	defer zeroBytes(loaded.metadataKey)
	if !loaded.status.Available {
		return nil, errors.New(loaded.status.State)
	}
	block, err := aes.NewCipher(loaded.metadataKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, errors.New("metadata_auth_failed")
	}
	return plaintext, nil
}

func (s *Service) Seal(ctx context.Context, purpose string, payload []byte) (string, error) {
	purpose = strings.TrimSpace(purpose)
	if purpose == "" {
		return "", errors.New("kms_seal_purpose_required")
	}
	loaded := s.loadKey(ctx)
	defer zeroBytes(loaded.sealKey)
	if !loaded.status.Available {
		return "", errors.New(loaded.status.State)
	}
	mac := hmac.New(sha256.New, loaded.sealKey)
	_, _ = mac.Write([]byte("archivon:kms-seal:v1\n"))
	_, _ = mac.Write([]byte(purpose))
	_, _ = mac.Write([]byte("\n"))
	_, _ = mac.Write(payload)
	return "kms-hmac-sha256:v1:" + hex.EncodeToString(mac.Sum(nil)), nil
}

func (s *Service) VerifySeal(ctx context.Context, purpose string, payload []byte, seal string) error {
	expected, err := s.Seal(ctx, purpose, payload)
	if err != nil {
		return err
	}
	if !hmac.Equal([]byte(expected), []byte(strings.TrimSpace(seal))) {
		return errors.New("kms_seal_mismatch")
	}
	return nil
}

func (s *Service) loadKey(ctx context.Context) loadedKey {
	_ = ctx
	status := Status{
		Provider:    s.provider,
		State:       "waiting_for_key",
		Available:   false,
		KeyID:       s.keyID,
		Algorithm:   "AES-256-GCM",
		Source:      filepath.Clean(s.masterKeyPath),
		CheckedAt:   time.Now().UTC(),
		MinKeyBytes: minKeyBytes,
	}
	if s.provider != DefaultProvider {
		status.State = "unsupported_provider"
		status.Reason = "kms_provider_unsupported"
		return loadedKey{status: status}
	}
	if strings.TrimSpace(s.masterKeyPath) == "" {
		status.Reason = "master_key_path_empty"
		return loadedKey{status: status}
	}

	raw, err := os.ReadFile(filepath.Clean(s.masterKeyPath))
	if err != nil {
		if os.IsNotExist(err) {
			status.Reason = "master_key_missing"
			return loadedKey{status: status}
		}
		if errors.Is(err, os.ErrPermission) {
			status.State = "permission_denied"
			status.Reason = "master_key_permission_denied"
			return loadedKey{status: status}
		}
		status.State = "error"
		status.Reason = "master_key_read_failed"
		return loadedKey{status: status}
	}

	keyMaterial, format, err := normalizeMasterKey(raw)
	defer zeroBytes(keyMaterial)
	if err != nil {
		status.State = "invalid_key"
		status.Reason = err.Error()
		return loadedKey{status: status}
	}

	fingerprintSum := sha256.Sum256(keyMaterial)
	status.State = "ready"
	status.Available = true
	status.Format = format
	status.Fingerprint = hex.EncodeToString(fingerprintSum[:])[:16]
	return loadedKey{
		status:      status,
		kek:         deriveLocalKey("archivon-local-kms-v1", keyMaterial),
		metadataKey: deriveLocalKey("archivon-local-metadata-v1", keyMaterial),
		sealKey:     deriveLocalKey("archivon-local-seal-v1", keyMaterial),
	}
}

func deriveLocalKey(purpose string, keyMaterial []byte) []byte {
	sum := sha256.Sum256(append([]byte(purpose+":"), keyMaterial...))
	return append([]byte(nil), sum[:]...)
}

func normalizeMasterKey(raw []byte) ([]byte, string, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return nil, "", errors.New("master_key_empty")
	}
	if strings.HasPrefix(trimmed, "archivon-local-master-key-v1:") {
		encoded := strings.TrimSpace(strings.TrimPrefix(trimmed, "archivon-local-master-key-v1:"))
		decoded, err := decodeBase64(encoded)
		if err != nil {
			return nil, "", errors.New("master_key_base64_invalid")
		}
		if len(decoded) < minKeyBytes {
			return nil, "", errors.New("master_key_too_short")
		}
		return decoded, "archivon-local-master-key-v1", nil
	}
	if decoded, err := hex.DecodeString(trimmed); err == nil && len(decoded) >= minKeyBytes {
		return decoded, "hex", nil
	}
	if decoded, err := decodeBase64(trimmed); err == nil && len(decoded) >= minKeyBytes {
		return decoded, "base64", nil
	}
	rawBytes := []byte(trimmed)
	if len(rawBytes) < minKeyBytes {
		return nil, "", errors.New("master_key_too_short")
	}
	return rawBytes, "raw", nil
}

func decodeBase64(value string) ([]byte, error) {
	decoders := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}
	var lastErr error
	for _, decoder := range decoders {
		decoded, err := decoder.DecodeString(value)
		if err == nil {
			return decoded, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func (s *Service) upsertKeySlot(ctx context.Context, status Status) error {
	if s.db == nil {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `
INSERT INTO kms_key_slots (tenant_id, key_id, provider, purpose, status, fingerprint_sha256, last_seen_at)
SELECT id, $1, $2, 'master', 'active', $3, now()
FROM tenants
WHERE slug = 'default'
ON CONFLICT (tenant_id, key_id) DO UPDATE
SET provider = EXCLUDED.provider,
    status = EXCLUDED.status,
    fingerprint_sha256 = EXCLUDED.fingerprint_sha256,
    updated_at = now(),
    last_seen_at = now()`,
		status.KeyID, status.Provider, status.Fingerprint,
	)
	return err
}

func zeroBytes(value []byte) {
	for i := range value {
		value[i] = 0
	}
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
