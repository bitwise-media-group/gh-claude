// Copyright 2026 Bitwise Media Group Ltd.
// SPDX-License-Identifier: MIT

package integrity

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

func authorNow() time.Time {
	return time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
}

// existingPolicy is a 14-day sequence-3 policy with one prior revocation.
func existingPolicy() *Policy {
	issued := authorNow().Add(-10 * 24 * time.Hour)
	return &Policy{
		Schema:         SchemaVersion,
		Sequence:       3,
		IssuedAt:       issued,
		Expires:        issued.Add(14 * 24 * time.Hour),
		MinSafeVersion: "0.2.0",
		Revoked:        []Revocation{{Version: "0.1.0", Reason: "CVE"}},
	}
}

func TestNextPolicy(t *testing.T) {
	tests := []struct {
		name     string
		existing *Policy
		opts     AuthorOptions
		want     *Policy
	}{
		{
			name: "fresh policy with all fields, versions normalized",
			opts: AuthorOptions{
				ExpiresIn:      7 * 24 * time.Hour,
				Sequence:       1,
				MinSafeVersion: "v0.1.0",
				Revoke:         []string{"v0.0.9"},
			},
			want: &Policy{
				Schema:         SchemaVersion,
				Sequence:       1,
				IssuedAt:       authorNow(),
				Expires:        authorNow().Add(7 * 24 * time.Hour),
				MinSafeVersion: "0.1.0",
				Revoked:        []Revocation{{Version: "0.0.9"}},
			},
		},
		{
			name:     "renewal bumps the sequence and refreshes only the dates",
			existing: existingPolicy(),
			opts:     AuthorOptions{},
			want: &Policy{
				Schema:         SchemaVersion,
				Sequence:       4,
				IssuedAt:       authorNow(),
				Expires:        authorNow().Add(14 * 24 * time.Hour), // inherited period
				MinSafeVersion: "0.2.0",
				Revoked:        []Revocation{{Version: "0.1.0", Reason: "CVE"}},
			},
		},
		{
			name:     "revocations append and deduplicate",
			existing: existingPolicy(),
			opts:     AuthorOptions{Revoke: []string{"v0.1.0", "0.2.1", "0.2.1"}},
			want: &Policy{
				Schema:         SchemaVersion,
				Sequence:       4,
				IssuedAt:       authorNow(),
				Expires:        authorNow().Add(14 * 24 * time.Hour),
				MinSafeVersion: "0.2.0",
				// 0.1.0 is already revoked (matched despite the v prefix); 0.2.1 lands once.
				Revoked: []Revocation{{Version: "0.1.0", Reason: "CVE"}, {Version: "0.2.1"}},
			},
		},
		{
			name:     "explicit sequence and higher floor win",
			existing: existingPolicy(),
			opts:     AuthorOptions{Sequence: 7, MinSafeVersion: "v0.3.0", ExpiresIn: 24 * time.Hour},
			want: &Policy{
				Schema:         SchemaVersion,
				Sequence:       7,
				IssuedAt:       authorNow(),
				Expires:        authorNow().Add(24 * time.Hour),
				MinSafeVersion: "0.3.0",
				Revoked:        []Revocation{{Version: "0.1.0", Reason: "CVE"}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NextPolicy(tt.existing, tt.opts, authorNow())
			if err != nil {
				t.Fatalf("NextPolicy: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NextPolicy = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestNextPolicyErrors(t *testing.T) {
	tests := []struct {
		name     string
		existing *Policy
		opts     AuthorOptions
		wantErr  string
	}{
		{
			name:    "fresh policy requires an expiry period",
			opts:    AuthorOptions{Sequence: 1, MinSafeVersion: "0.1.0"},
			wantErr: "expiry period is required",
		},
		{
			name:    "fresh policy requires a sequence",
			opts:    AuthorOptions{ExpiresIn: 24 * time.Hour, MinSafeVersion: "0.1.0"},
			wantErr: "sequence number is required",
		},
		{
			name:    "fresh policy requires a minimum safe version",
			opts:    AuthorOptions{ExpiresIn: 24 * time.Hour, Sequence: 1},
			wantErr: "minimum safe version is required",
		},
		{
			name:     "sequence must not go backwards",
			existing: existingPolicy(),
			opts:     AuthorOptions{Sequence: 2},
			wantErr:  "does not exceed the existing policy's 3",
		},
		{
			name:     "sequence must not be reused",
			existing: existingPolicy(),
			opts:     AuthorOptions{Sequence: 3},
			wantErr:  "does not exceed the existing policy's 3",
		},
		{
			name:     "minimum safe version must not be lowered",
			existing: existingPolicy(),
			opts:     AuthorOptions{MinSafeVersion: "0.1.9"},
			wantErr:  "below the existing policy's 0.2.0",
		},
		{
			name:    "malformed minimum safe version is rejected",
			opts:    AuthorOptions{ExpiresIn: 24 * time.Hour, Sequence: 1, MinSafeVersion: "latest"},
			wantErr: "not a valid version",
		},
		{
			name:     "invalid revoked version is rejected",
			existing: existingPolicy(),
			opts:     AuthorOptions{Revoke: []string{"not-a-version"}},
			wantErr:  "not a valid version",
		},
		{
			name:     "negative expiry period is rejected",
			existing: existingPolicy(),
			opts:     AuthorOptions{ExpiresIn: -time.Hour},
			wantErr:  "positive expiry period",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NextPolicy(tt.existing, tt.opts, authorNow())
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

// TestNextPolicyRoundTrips confirms an authored policy passes the same
// structural validation clients apply to a fetched one.
func TestNextPolicyRoundTrips(t *testing.T) {
	p, err := NextPolicy(existingPolicy(), AuthorOptions{Revoke: []string{"0.2.2"}}, authorNow())
	if err != nil {
		t.Fatalf("NextPolicy: %v", err)
	}
	b, err := MarshalPolicy(p)
	if err != nil {
		t.Fatalf("MarshalPolicy: %v", err)
	}
	if _, err := ParsePolicy(b); err != nil {
		t.Errorf("authored policy failed client-side validation: %v", err)
	}
}
