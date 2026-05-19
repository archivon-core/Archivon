package compute

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestHandleConfigureAcceptsVersionRolling(t *testing.T) {
	var buf bytes.Buffer
	service := &Service{}
	state := &stratumState{}
	req := stratumRequest{
		ID:     float64(7),
		Method: "mining.configure",
		Params: []any{
			[]any{"version-rolling", "minimum-difficulty"},
			map[string]any{
				"version-rolling.mask":          "00c00000",
				"version-rolling.min-bit-count": float64(2),
			},
		},
	}

	if err := service.handleConfigure(&buf, state, req); err != nil {
		t.Fatalf("handleConfigure returned error: %v", err)
	}

	var response struct {
		Result map[string]any `json:"result"`
		Error  any            `json:"error"`
	}
	if err := json.Unmarshal(buf.Bytes(), &response); err != nil {
		t.Fatalf("response is not JSON: %v", err)
	}
	if response.Error != nil {
		t.Fatalf("unexpected error response: %#v", response.Error)
	}
	if response.Result["version-rolling"] != true {
		t.Fatalf("version-rolling was not accepted: %#v", response.Result)
	}
	if response.Result["version-rolling.mask"] != "00c00000" {
		t.Fatalf("unexpected version-rolling mask: %#v", response.Result["version-rolling.mask"])
	}
	if response.Result["minimum-difficulty"] != false {
		t.Fatalf("unsupported extension should be explicitly rejected: %#v", response.Result)
	}
	if !state.versionRolling || state.versionMask != "00c00000" {
		t.Fatalf("state was not configured for version rolling: %#v", state)
	}
}

func TestEffectiveVersionHexAppliesOnlyConfiguredMask(t *testing.T) {
	version, err := effectiveVersionHex("20000000", "ffffffff", "00c00000", true)
	if err != nil {
		t.Fatalf("effectiveVersionHex returned error: %v", err)
	}
	if version != "20c00000" {
		t.Fatalf("unexpected effective version: %s", version)
	}
}

func TestEffectiveVersionHexRequiresConfiguredVersionRolling(t *testing.T) {
	if _, err := effectiveVersionHex("20000000", "00c00000", "00c00000", false); err == nil {
		t.Fatal("expected error when version rolling was not configured")
	}
}

func TestBuildValidCoinbaseParts(t *testing.T) {
	coinb1, coinb2, err := buildValidCoinbaseParts("11d9bcb5", 4)
	if err != nil {
		t.Fatalf("buildValidCoinbaseParts returned error: %v", err)
	}
	const wantCoinb1 = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff14030100004172636869766f6e"
	const wantCoinb2 = "ffffffff010000000000000000015100000000"
	if coinb1 != wantCoinb1 {
		t.Fatalf("unexpected coinb1:\nwant %s\n got %s", wantCoinb1, coinb1)
	}
	if coinb2 != wantCoinb2 {
		t.Fatalf("unexpected coinb2:\nwant %s\n got %s", wantCoinb2, coinb2)
	}
}

func TestVerifyShareAcceptsSyntheticSubmit(t *testing.T) {
	coinb1, coinb2, err := buildValidCoinbaseParts("00000001", 4)
	if err != nil {
		t.Fatalf("buildValidCoinbaseParts returned error: %v", err)
	}

	work := work{
		powJobID:    "00000000-0000-4000-8000-000000000001",
		stratumID:   "000000000000000000000001",
		extranonce1: "00000001",
		coinb1:      coinb1,
		coinb2:      coinb2,
		prevhash:    "0000000000000000000000000000000000000000000000000000000000000000",
		version:     "20000000",
		nbits:       "1d00ffff",
		ntime:       "00000001",
		targetHex:   maxTargetHex,
		difficulty:  1,
	}

	valid, hashHex, reason := verifyShare(work, "000000000000000000000001", "00000000", "00000001", "00000000", "20000000")
	if !valid {
		t.Fatalf("expected synthetic share to be valid, reason=%s hash=%s", reason, hashHex)
	}
	if hashHex == "" {
		t.Fatal("expected reconstructed block hash")
	}
}
