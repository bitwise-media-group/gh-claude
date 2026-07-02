// Copyright 2026 Bitwise Media Group Ltd.
// SPDX-License-Identifier: MIT

package main

import (
	"slices"
	"testing"
)

// TestRevokeFlagParsing pins the --revoke contract: comma-separated lists and
// repeated flags both accumulate.
func TestRevokeFlagParsing(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want []string
	}{
		{"single version", []string{"--revoke", "0.1.0"}, []string{"0.1.0"}},
		{"comma-separated list", []string{"--revoke", "0.1.0,0.1.1"}, []string{"0.1.0", "0.1.1"}},
		{"repeated flag", []string{"--revoke", "0.1.0", "--revoke", "0.1.1"}, []string{"0.1.0", "0.1.1"}},
		{"mixed", []string{"--revoke", "0.1.0,0.1.1", "--revoke", "0.2.0"}, []string{"0.1.0", "0.1.1", "0.2.0"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := newPolicyCmd()
			if err := cmd.ParseFlags(tt.args); err != nil {
				t.Fatalf("ParseFlags(%v): %v", tt.args, err)
			}
			got, err := cmd.Flags().GetStringSlice("revoke")
			if err != nil {
				t.Fatalf("GetStringSlice: %v", err)
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("revoke = %v, want %v", got, tt.want)
			}
		})
	}
}
