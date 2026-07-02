// Copyright 2026 Bitwise Media Group Ltd.
// SPDX-License-Identifier: MIT

package integrity

import (
	"testing"
	"time"
)

func testPolicy() *Policy {
	return &Policy{
		Schema:         SchemaVersion,
		Sequence:       1,
		IssuedAt:       time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
		Expires:        time.Date(2026, 7, 8, 0, 0, 0, 0, time.UTC),
		MinSafeVersion: "1.4.0",
		Revoked: []Revocation{
			{Version: "1.3.0", Reason: "CVE-2026-1: token echoed to stderr", Advisory: "https://example/GHSA-x"},
			{Digest: "sha256:deadbeef", Reason: "tampered build"},
		},
	}
}

func TestPolicyEvaluate(t *testing.T) {
	p := testPolicy()
	cases := []struct {
		name    string
		version string
		digest  string
		blocked bool
	}{
		{"clear above floor", "1.5.0", "", false},
		{"clear at floor", "1.4.0", "", false},
		{"below floor blocked", "1.3.9", "", true},
		{"explicitly revoked version blocked", "1.3.0", "", true},
		{"revoked version normalizes leading v", "v1.3.0", "", true},
		{"digest revocation blocks regardless of version", "9.9.9", "sha256:DEADBEEF", true},
		{"non-matching digest is clear", "1.5.0", "sha256:feed", false},
		{"empty version skips floor", "", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := p.evaluate(normalize(c.version), c.digest)
			if (got.Verdict == VerdictBlocked) != c.blocked {
				t.Fatalf("evaluate(%q,%q) verdict=%v, wantBlocked=%v", c.version, c.digest, got.Verdict, c.blocked)
			}
			if c.blocked && got.Reason == "" {
				t.Errorf("blocked evaluation must carry a reason")
			}
		})
	}
}

func TestParsePolicyRejectsBadInput(t *testing.T) {
	const ts = `"issued_at":"2026-06-01T00:00:00Z","expires_at":"2026-07-01T00:00:00Z"`
	cases := map[string]string{
		"not json":            `{`,
		"wrong schema":        `{"schema":99,` + ts + `}`,
		"missing timestamps":  `{"schema":1}`,
		"expiry before issue": `{"schema":1,"issued_at":"2026-07-01T00:00:00Z","expires_at":"2026-06-01T00:00:00Z"}`,
		"unknown field":       `{"schema":1,` + ts + `,"surprise":true}`,
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParsePolicy([]byte(in)); err == nil {
				t.Errorf("ParsePolicy(%q) = nil error, want error", in)
			}
		})
	}
}

func TestParsePolicyAcceptsValid(t *testing.T) {
	in := `{"schema":1,"sequence":7,"issued_at":"2026-06-01T00:00:00Z",` +
		`"expires_at":"2026-07-01T00:00:00Z","min_safe_version":"1.4.0"}`
	p, err := ParsePolicy([]byte(in))
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	if p.Sequence != 7 || p.MinSafeVersion != "1.4.0" {
		t.Errorf("parsed policy = %+v", p)
	}
}
