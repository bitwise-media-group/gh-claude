// Copyright 2026 Bitwise Media Group Ltd.
// SPDX-License-Identifier: MIT

package integrity

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"
)

// AuthorOptions describes the next policy revision relative to an existing
// policy. Every field is optional when an existing policy is supplied — the
// zero value then renews it (sequence bumped by one, same floor and
// revocations, fresh issue/expiry dates over the same period). Without an
// existing policy, ExpiresIn, Sequence, and MinSafeVersion are all required.
type AuthorOptions struct {
	ExpiresIn      time.Duration // validity period; 0 inherits the existing policy's period
	Sequence       uint64        // 0 means one above the existing policy's sequence (sequences start at 1)
	MinSafeVersion string        // "" inherits the existing floor; never below it
	Revoke         []string      // versions to append to the revocation list (duplicates are dropped)
}

// NextPolicy builds the next policy revision from an optional existing policy
// and the requested changes, issued at now. It enforces the channel's
// monotonicity rules at authoring time — every revision's sequence strictly
// exceeds its predecessor's and the minimum safe version never drops — so a
// revision that clients would reject (or that would silently un-revoke a
// version) cannot be produced. The returned policy is unsigned; the caller
// signs its exact marshaled bytes.
func NextPolicy(existing *Policy, opts AuthorOptions, now time.Time) (*Policy, error) {
	period, err := nextPeriod(existing, opts.ExpiresIn)
	if err != nil {
		return nil, err
	}
	seq, err := nextSequence(existing, opts.Sequence)
	if err != nil {
		return nil, err
	}
	floor, err := nextFloor(existing, opts.MinSafeVersion)
	if err != nil {
		return nil, err
	}
	revoked, err := appendRevocations(existing, opts.Revoke)
	if err != nil {
		return nil, err
	}

	now = now.UTC().Truncate(time.Second)
	return &Policy{
		Schema:         SchemaVersion,
		Sequence:       seq,
		IssuedAt:       now,
		Expires:        now.Add(period),
		MinSafeVersion: floor,
		Revoked:        revoked,
	}, nil
}

// nextPeriod resolves the validity period: the requested one, or the existing
// policy's issued→expires span when none is requested.
func nextPeriod(existing *Policy, requested time.Duration) (time.Duration, error) {
	period := requested
	if period == 0 && existing != nil {
		period = existing.Expires.Sub(existing.IssuedAt)
	}
	if period <= 0 {
		return 0, errors.New("a positive expiry period is required when no existing policy supplies one")
	}
	return period, nil
}

// nextSequence resolves the revision sequence: one above the existing policy's
// when none is requested. A requested sequence must strictly exceed the
// existing one — every revision, a plain renewal included, supersedes its
// predecessor, and a repeated sequence would put two different documents in
// circulation under the same revision.
func nextSequence(existing *Policy, requested uint64) (uint64, error) {
	if requested == 0 {
		if existing == nil {
			return 0, errors.New("a sequence number is required when no existing policy supplies one")
		}
		return existing.Sequence + 1, nil
	}
	if existing != nil && requested <= existing.Sequence {
		return 0, fmt.Errorf("sequence %d does not exceed the existing policy's %d", requested, existing.Sequence)
	}
	return requested, nil
}

// nextFloor resolves the normalized minimum safe version, refusing to lower an
// existing floor (that would silently un-block known-bad versions).
func nextFloor(existing *Policy, requested string) (string, error) {
	floor := normalize(requested)
	if floor == "" && existing != nil {
		floor = normalize(existing.MinSafeVersion)
	}
	if floor == "" && existing == nil {
		return "", errors.New("a minimum safe version is required when no existing policy supplies one")
	}
	if floor != "" && !isRelease(floor) {
		return "", fmt.Errorf("minimum safe version %q is not a valid version", requested)
	}
	if existing != nil && existing.MinSafeVersion != "" && less(floor, normalize(existing.MinSafeVersion)) {
		return "", fmt.Errorf("minimum safe version %s is below the existing policy's %s (a floor can only rise)",
			floor, normalize(existing.MinSafeVersion))
	}
	return floor, nil
}

// appendRevocations appends the requested versions to the existing revocation
// list, dropping ones already revoked (compared after normalization).
func appendRevocations(existing *Policy, revoke []string) ([]Revocation, error) {
	var revoked []Revocation
	if existing != nil {
		revoked = slices.Clone(existing.Revoked)
	}
	for _, v := range revoke {
		if !isRelease(v) {
			return nil, fmt.Errorf("revoked version %q is not a valid version", v)
		}
		already := slices.ContainsFunc(revoked, func(r Revocation) bool {
			return r.Version != "" && sameVersion(r.Version, v)
		})
		if !already {
			revoked = append(revoked, Revocation{Version: normalize(v)})
		}
	}
	return revoked, nil
}

// MarshalPolicy renders p in the canonical published form — two-space-indented
// JSON with a trailing newline. These are the exact bytes the detached
// signature covers, so authoring tools must publish them unmodified.
func MarshalPolicy(p *Policy) ([]byte, error) {
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}
