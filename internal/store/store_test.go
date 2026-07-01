// Copyright 2026 Bitwise Media Group Ltd.
// SPDX-License-Identifier: MIT

package store

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// fileStore returns a Store backed by the encrypted file backend in a temp dir,
// exercising the same code path used on Linux/WSL2 without touching a keychain.
func fileStore(t *testing.T, dir string) *Store {
	t.Helper()
	fb, err := newFileBackend(dir, func(string) (string, error) { return "unit-test-key", nil })
	if err != nil {
		t.Fatalf("open file backend: %v", err)
	}
	return &Store{impl: fb, backend: BackendFile}
}

func TestStoreRoundTrip(t *testing.T) {
	s := fileStore(t, t.TempDir())

	if _, ok, err := s.Get("github.com"); err != nil || ok {
		t.Fatalf("Get on empty store: ok=%v err=%v, want false/nil", ok, err)
	}

	want := []byte(`{"token":"github_pat_x","login":"octocat"}`)
	if err := s.Set("github.com", want); err != nil {
		t.Fatal(err)
	}
	got, ok, err := s.Get("github.com")
	if err != nil || !ok {
		t.Fatalf("Get after Set: ok=%v err=%v", ok, err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("round-trip data = %q, want %q", got, want)
	}

	if err := s.Delete("github.com"); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.Get("github.com"); ok {
		t.Error("key still present after Delete")
	}
	if err := s.Delete("github.com"); err != nil {
		t.Errorf("Delete of missing key returned %v, want nil", err)
	}
}

func TestStoreEncryptsAtRest(t *testing.T) {
	dir := t.TempDir()
	s := fileStore(t, dir)
	secret := []byte("github_pat_super_secret_value")
	if err := s.Set("github.com", secret); err != nil {
		t.Fatal(err)
	}

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(content, secret) {
			t.Errorf("plaintext secret found on disk in %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestFileBackendCorruptBlobReadsAsAbsent covers the clean-break migration path:
// a blob the current format can't decrypt (e.g. one written by the old
// keyring/JWE backend) must read back as "absent" and be cleared, so the login
// flow re-authenticates instead of crashing.
func TestFileBackendCorruptBlobReadsAsAbsent(t *testing.T) {
	dir := t.TempDir()
	s := fileStore(t, dir)
	if err := s.Set("github.com", []byte("real")); err != nil {
		t.Fatal(err)
	}

	fb := s.impl.(*fileBackend)
	if err := os.WriteFile(fb.filename("github.com"), []byte("eyJ.legacy.jwe.blob"), 0o600); err != nil {
		t.Fatal(err)
	}

	got, ok, err := s.Get("github.com")
	if err != nil || ok || got != nil {
		t.Fatalf("corrupt blob: got=%q ok=%v err=%v, want nil/false/nil", got, ok, err)
	}
	if _, statErr := os.Stat(fb.filename("github.com")); !os.IsNotExist(statErr) {
		t.Errorf("stale file not removed after failed decrypt: %v", statErr)
	}
}

func TestFilePasswordUsesMachineID(t *testing.T) {
	if machineID() == "" {
		t.Skip("no machine-id on this host (expected on macOS)")
	}
	pw, err := filePassword("")
	if err != nil {
		t.Fatal(err)
	}
	if len(pw) != 64 { // sha256 hex
		t.Errorf("derived key length = %d, want 64", len(pw))
	}
}
