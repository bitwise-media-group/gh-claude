// Copyright 2026 Bitwise Media Group Ltd.
// SPDX-License-Identifier: MIT

// Package store persists a small secret blob in the most secure place available
// on the host: the macOS Keychain (via the `security` CLI) or the Windows
// Credential Manager (via advapi32), and an encrypted, machine-bound file as the
// fallback everywhere else — including Linux and WSL2, which use the file backend
// directly. Backends are implemented against the standard library only; there is
// no third-party keyring dependency and no cgo.
//
// The store is deliberately "dumb": it reads and writes opaque bytes by key.
// Callers own the schema of what they store.
package store

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ServiceName is the service/collection identifier used across backends.
const ServiceName = "gh-claude"

// Backend names surfaced to the caller for diagnostics.
const (
	BackendKeychain          = "keychain"
	BackendCredentialManager = "credential-manager"
	BackendFile              = "encrypted-file"
	Backend1Password         = "1password"
)

// backend is the pluggable persistence implementation behind a Store. Each OS
// keychain, the encrypted file fallback, and the optional 1Password backend
// implement it. It mirrors the "opaque bytes by key" contract of Store itself.
type backend interface {
	get(key string) ([]byte, bool, error)
	set(key string, data []byte) error
	delete(key string) error
}

// Store wraps a single resolved persistence backend.
type Store struct {
	impl    backend
	backend string
	detail  string
}

// Backend reports which backend was selected (see the Backend* constants).
func (s *Store) Backend() string { return s.backend }

// Detail reports an optional human-readable qualifier for the backend (e.g. the
// 1Password vault), or "" when there is none.
func (s *Store) Detail() string { return s.detail }

// IsFileFallback reports whether the store fell back to the on-disk encrypted
// file because no OS keychain was usable. Callers may warn the user.
func (s *Store) IsFileFallback() bool { return s.backend == BackendFile }

// Options configures backend selection. The zero value preserves the default,
// env-driven behavior; CLI flags populate it to override the environment.
type Options struct {
	// UseOnePassword forces the 1Password backend on (e.g. the --op flag), in
	// addition to the GH_CLAUDE_STORE environment variable.
	UseOnePassword bool
	// Vault overrides the 1Password vault (e.g. the --vault flag). When empty it
	// falls back to GH_CLAUDE_OP_VAULT and then the default vault.
	Vault string
}

// New resolves and opens the best available backend for this host. When the user
// opts into 1Password (--op or GH_CLAUDE_STORE), that backend is used exclusively
// and an unreachable op is a hard error. Otherwise it prefers the native OS
// keychain (macOS Keychain, Windows Credential Manager) and falls back to the
// encrypted file backend on hosts with no native keychain (Linux, WSL2) or when
// the native store is unreachable.
func New(opts Options) (*Store, error) {
	if opts.UseOnePassword || onePasswordRequested() {
		b, err := newOPBackend(opts)
		if err != nil {
			return nil, fmt.Errorf("1Password store requested but unavailable: %w", err)
		}
		return &Store{impl: b, backend: Backend1Password, detail: "vault: " + b.vault}, nil
	}

	// Prefer the platform-native credential store (macOS Keychain, Windows
	// Credential Manager). newNativeBackend returns a nil backend on platforms
	// with no native store (e.g. Linux), so we fall back to the encrypted file.
	// A non-nil error means a native store exists but is unreachable; we fall
	// back to the file backend in that case too rather than failing outright.
	if b, name, err := newNativeBackend(); err == nil && b != nil {
		return &Store{impl: b, backend: name}, nil
	}

	fb, err := newFileBackend(fileDir(), filePassword)
	if err != nil {
		return nil, fmt.Errorf("opening secret store: %w", err)
	}
	return &Store{impl: fb, backend: BackendFile}, nil
}

// Get returns the bytes stored under key. The boolean is false (with a nil
// error) when no item exists for the key.
func (s *Store) Get(key string) ([]byte, bool, error) { return s.impl.get(key) }

// Set stores data under key, replacing any existing value.
func (s *Store) Set(key string, data []byte) error { return s.impl.set(key, data) }

// Delete removes the item under key. Removing a missing key is not an error.
func (s *Store) Delete(key string) error { return s.impl.delete(key) }

// fileDir is where the encrypted file backend keeps its items.
func fileDir() string {
	if dir, err := os.UserConfigDir(); err == nil {
		return filepath.Join(dir, ServiceName)
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".config", ServiceName)
	}
	return filepath.Join(".", "."+ServiceName)
}

// filePassword derives the symmetric key for the encrypted file backend. It is
// bound to a stable machine identifier so the blob is not portable to other
// machines, with a generated per-install key file as a last resort. This is
// defense-in-depth (the machine id is not itself a secret); the file's 0600
// permissions are the primary protection. See README "Security model".
func filePassword(string) (string, error) {
	if id := machineID(); id != "" {
		sum := sha256.Sum256([]byte(ServiceName + ":" + id))
		return hex.EncodeToString(sum[:]), nil
	}
	return installKey()
}

func machineID() string {
	for _, p := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		if b, err := os.ReadFile(p); err == nil {
			if s := strings.TrimSpace(string(b)); s != "" {
				return s
			}
		}
	}
	return ""
}

// installKey returns a random per-install key, generating and persisting it
// (0600) the first time. Used only when no machine id is available.
func installKey() (string, error) {
	path := filepath.Join(fileDir(), "install-key")
	if b, err := os.ReadFile(path); err == nil {
		if s := strings.TrimSpace(string(b)); s != "" {
			return s, nil
		}
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", err
	}
	enc := hex.EncodeToString(key)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, []byte(enc), 0o600); err != nil {
		return "", err
	}
	return enc, nil
}
