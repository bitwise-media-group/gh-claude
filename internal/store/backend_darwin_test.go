// Copyright 2026 Bitwise Media Group Ltd.
// SPDX-License-Identifier: MIT

//go:build darwin

package store

import (
	"bytes"
	"os/exec"
	"testing"
)

// TestKeychainBackendRoundTrip exercises the real macOS `security` shell-out. It
// uses a test-only service name and cleans up after itself, and skips when the
// keychain is unreachable (e.g. a headless CI runner) so it never wedges CI.
func TestKeychainBackendRoundTrip(t *testing.T) {
	path, err := exec.LookPath("security")
	if err != nil {
		t.Skip("security CLI not available")
	}
	k := keychainBackend{
		run:     execSecRunner(path),
		service: "gh-claude-test-roundtrip",
		label:   "gh-claude-test",
	}
	const key = "example.test"
	// Probe read+write reachability; skip on sandboxes/CI that block keychain
	// writes (e.g. "UNIX[Operation not permitted]") rather than failing.
	if err := k.set(probeKey, []byte("x")); err != nil {
		t.Skipf("keychain not writable in this environment: %v", err)
	}
	_ = k.delete(probeKey)

	_ = k.delete(key) // clean slate
	t.Cleanup(func() { _ = k.delete(key) })

	if _, ok, err := k.get(key); err != nil || ok {
		t.Fatalf("get on empty: ok=%v err=%v, want false/nil", ok, err)
	}

	want := []byte(`{"token":"github_pat_x","login":"octocat"}`)
	if err := k.set(key, want); err != nil {
		t.Fatalf("set: %v", err)
	}
	got, ok, err := k.get(key)
	if err != nil || !ok {
		t.Fatalf("get after set: ok=%v err=%v", ok, err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("round-trip = %q, want %q", got, want)
	}

	// -U updates in place, and arbitrary bytes survive the base64 round trip.
	want2 := []byte("second\x00\x01\x02value")
	if err := k.set(key, want2); err != nil {
		t.Fatalf("update: %v", err)
	}
	if got2, _, _ := k.get(key); !bytes.Equal(got2, want2) {
		t.Errorf("after update = %q, want %q", got2, want2)
	}

	if err := k.delete(key); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, ok, _ := k.get(key); ok {
		t.Error("still present after delete")
	}
	if err := k.delete(key); err != nil {
		t.Errorf("delete of missing key returned %v, want nil", err)
	}
}
