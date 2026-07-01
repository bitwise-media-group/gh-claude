// Copyright 2026 Bitwise Media Group Ltd.
// SPDX-License-Identifier: MIT

//go:build darwin

package store

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// probeKey is a sentinel looked up at open time to confirm the keychain is
// reachable. It is never written; a "not found" result means the keychain works.
const probeKey = "__gh-claude-probe__"

// secItemNotFoundExit is the exit status `security` returns for
// errSecItemNotFound (the item is not in the keychain).
const secItemNotFoundExit = 44

// secRunner runs the macOS `security` CLI with args and returns stdout. The seam
// lets tests substitute a fake without touching the real keychain.
type secRunner func(args []string) (stdout []byte, err error)

// keychainBackend persists each item as a generic-password in the macOS login
// keychain by shelling out to /usr/bin/security. The opaque blob is stored
// base64-encoded so it is always valid UTF-8 for `-w`.
//
// Note: `add-generic-password -w <value>` passes the (base64) secret as an argv
// element, briefly visible via `ps` to other local users; `security` offers no
// stdin channel for the value. This is acceptable on a single-user machine and
// is what lets the tool use a real keychain in CGO_ENABLED=0 release builds.
type keychainBackend struct {
	run     secRunner
	service string
	label   string
}

// newNativeBackend returns the macOS Keychain backend when `security` is present
// and reachable, otherwise (nil, "", nil) so New falls back to the file backend.
func newNativeBackend() (backend, string, error) {
	path, err := exec.LookPath("security")
	if err != nil {
		return nil, "", nil // no security CLI (unusual on macOS); use file fallback
	}
	k := keychainBackend{run: execSecRunner(path), service: ServiceName, label: ServiceName}
	// Probe reachability: a lookup should either succeed or report "not found".
	// Any other error (e.g. no accessible keychain on a headless host) means we
	// should fall back to the encrypted file backend.
	if _, _, err := k.get(probeKey); err != nil {
		return nil, "", err
	}
	return k, BackendKeychain, nil
}

func (k keychainBackend) get(key string) ([]byte, bool, error) {
	out, err := k.run([]string{"find-generic-password", "-s", k.service, "-a", key, "-w"})
	if err != nil {
		if isSecNotFound(err) {
			return nil, false, nil
		}
		return nil, false, err
	}
	enc := strings.TrimRight(string(out), "\n") // -w prints the value + newline
	data, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return nil, false, fmt.Errorf("decoding keychain item: %w", err)
	}
	return data, true, nil
}

func (k keychainBackend) set(key string, data []byte) error {
	enc := base64.StdEncoding.EncodeToString(data)
	_, err := k.run([]string{
		"add-generic-password",
		"-U", // update the item in place if it already exists
		"-s", k.service,
		"-a", key,
		"-l", k.label,
		"-w", enc,
	})
	return err
}

func (k keychainBackend) delete(key string) error {
	_, err := k.run([]string{"delete-generic-password", "-s", k.service, "-a", key})
	if err != nil && !isSecNotFound(err) {
		return err
	}
	return nil
}

// execSecRunner returns a secRunner backed by the real `security` binary at path.
func execSecRunner(path string) secRunner {
	return func(args []string) ([]byte, error) {
		cmd := exec.Command(path, args...)
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			code := -1
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				code = ee.ExitCode()
			}
			return stdout.Bytes(), &secError{err: err, code: code, stderr: stderr.String()}
		}
		return stdout.Bytes(), nil
	}
}

// secError carries the `security` exit code and stderr so callers can classify a
// missing item (errSecItemNotFound) as "absent" rather than a hard failure.
type secError struct {
	err    error
	code   int
	stderr string
}

func (e *secError) Error() string {
	if s := strings.TrimSpace(e.stderr); s != "" {
		return fmt.Sprintf("%v: %s", e.err, s)
	}
	return e.err.Error()
}

func (e *secError) Unwrap() error { return e.err }

// isSecNotFound reports whether a `security` error means the item is not in the
// keychain, which get and delete treat as "absent".
func isSecNotFound(err error) bool {
	var se *secError
	if !errors.As(err, &se) {
		return false
	}
	return se.code == secItemNotFoundExit ||
		strings.Contains(strings.ToLower(se.stderr), "could not be found")
}
