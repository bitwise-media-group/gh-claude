// Copyright 2026 Bitwise Media Group Ltd.
// SPDX-License-Identifier: MIT

package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Environment variables controlling the optional 1Password backend.
const (
	// EnvStore opts into the 1Password backend when set to "1password" or "op".
	EnvStore = "GH_CLAUDE_STORE"
	// EnvVault selects the vault to store the item in (name or ID).
	EnvVault = "GH_CLAUDE_OP_VAULT"
	// EnvAccount selects the 1Password account for multi-account setups.
	EnvAccount = "GH_CLAUDE_OP_ACCOUNT"
)

// defaultVault is used when EnvVault is unset. "Private" is the personal vault
// present on every individual account.
const defaultVault = "Private"

// opCategory and opField define how the opaque record blob is stored: a single
// concealed "credential" field on an API Credential item. The field is read back
// by reference (op://vault/title/credential), so it must match opField exactly.
const (
	opCategory = "API_CREDENTIAL"
	opField    = "credential"
)

// onePasswordRequested reports whether the user opted into the 1Password backend
// via EnvStore.
func onePasswordRequested() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(EnvStore))) {
	case "1password", "op":
		return true
	default:
		return false
	}
}

// opRunner runs the `op` CLI with args, optionally feeding stdin, and returns
// stdout. The seam lets tests substitute a fake without a real `op` binary.
type opRunner func(args []string, stdin []byte) (stdout []byte, err error)

// opBackend persists the record in 1Password by shelling out to the `op` CLI. It
// relies on 1Password desktop app integration for auth (including biometric
// unlock), which works on macOS, Windows, Linux, and WSL (via op.exe interop).
//
// The secret value is only ever passed to `op` over stdin (the JSON item
// template), never on the command line, so it does not appear in the process
// table.
type opBackend struct {
	run     opRunner
	vault   string
	account string
}

// newOPBackend resolves the `op` binary, builds the backend from opts (falling
// back to the environment), and probes that 1Password is reachable so we fail
// loudly here rather than on the first Get/Set (mirroring the native-store
// reachability probe in New).
func newOPBackend(opts Options) (*opBackend, error) {
	path, err := exec.LookPath("op")
	if err != nil {
		return nil, fmt.Errorf("the 1Password CLI (op) was not found on PATH "+
			"(install it and enable desktop app integration): %w", err)
	}
	b := &opBackend{
		run:     execOPRunner(path),
		vault:   resolveVault(opts.Vault),
		account: strings.TrimSpace(os.Getenv(EnvAccount)),
	}
	if _, err := b.run(b.opArgs("whoami"), nil); err != nil {
		return nil, fmt.Errorf("1Password is not reachable (is the app running, "+
			"signed in, and CLI integration enabled?): %w", err)
	}
	return b, nil
}

// resolveVault picks the vault: the flag value if set, else GH_CLAUDE_OP_VAULT,
// else the default vault.
func resolveVault(flag string) string {
	if v := strings.TrimSpace(flag); v != "" {
		return v
	}
	if v := strings.TrimSpace(os.Getenv(EnvVault)); v != "" {
		return v
	}
	return defaultVault
}

// execOPRunner returns an opRunner backed by the real `op` binary at path.
func execOPRunner(path string) opRunner {
	return func(args []string, stdin []byte) ([]byte, error) {
		cmd := exec.Command(path, args...)
		if stdin != nil {
			cmd.Stdin = bytes.NewReader(stdin)
		}
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			return stdout.Bytes(), &opCmdError{err: err, stderr: stderr.String()}
		}
		return stdout.Bytes(), nil
	}
}

// opArgs prepends the global --account flag (when configured) to a command.
func (b *opBackend) opArgs(args ...string) []string {
	if b.account != "" {
		return append([]string{"--account", b.account}, args...)
	}
	return args
}

func (b *opBackend) title(key string) string { return ServiceName + ":" + key }

// get reads the credential field by reference. A missing item yields (nil,
// false, nil); any other failure propagates.
func (b *opBackend) get(key string) ([]byte, bool, error) {
	ref := fmt.Sprintf("op://%s/%s/%s", b.vault, b.title(key), opField)
	out, err := b.run(b.opArgs("read", "--no-newline", ref), nil)
	if err != nil {
		if isOPNotFound(err) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return out, true, nil
}

// set stores data as the credential field of an API Credential item. It deletes
// any existing item first so the value is always supplied through the create
// template on stdin — never as a command-line assignment.
func (b *opBackend) set(key string, data []byte) error {
	if err := b.delete(key); err != nil {
		return err
	}
	tmpl, err := json.Marshal(opItemTemplate(b.title(key), string(data)))
	if err != nil {
		return err
	}
	if _, err := b.run(b.opArgs("item", "create", "--vault", b.vault, "-"), tmpl); err != nil {
		return err
	}
	return nil
}

// delete removes the item. A missing item is not an error.
func (b *opBackend) delete(key string) error {
	_, err := b.run(b.opArgs("item", "delete", b.title(key), "--vault", b.vault), nil)
	if err != nil && !isOPNotFound(err) {
		return err
	}
	return nil
}

// opItemTemplate builds the JSON item template piped to `op item create -`. The
// blob lives in a single concealed field so the round trip returns the exact
// bytes that were stored.
func opItemTemplate(title, value string) map[string]any {
	return map[string]any{
		"title":    title,
		"category": opCategory,
		"fields": []map[string]any{{
			"id":    opField,
			"type":  "CONCEALED",
			"label": opField,
			"value": value,
		}},
	}
}

// opCmdError carries the `op` exit error alongside its stderr so callers can
// classify failures (e.g. a missing item) by message.
type opCmdError struct {
	err    error
	stderr string
}

func (e *opCmdError) Error() string {
	if s := strings.TrimSpace(e.stderr); s != "" {
		return fmt.Sprintf("%v: %s", e.err, s)
	}
	return e.err.Error()
}

func (e *opCmdError) Unwrap() error { return e.err }

// isOPNotFound reports whether an op error means the referenced item does not
// exist, which both get and delete treat as "absent" rather than a failure.
func isOPNotFound(err error) bool {
	var ce *opCmdError
	if !errors.As(err, &ce) {
		return false
	}
	s := strings.ToLower(ce.stderr)
	for _, msg := range []string{
		"isn't an item",
		"not found",
		"no item matching",
		"could not find",
		"doesn't exist",
		"no object matching",
	} {
		if strings.Contains(s, msg) {
			return true
		}
	}
	return false
}
