// Copyright 2026 Bitwise Media Group Ltd.
// SPDX-License-Identifier: MIT

// Package integrity implements gh-claude's runtime self-protection: a signed,
// freshness-protected security policy that can revoke known-bad versions (the
// "kill switch" for a disclosed vulnerability), checked on launch, and on-demand
// verification of the running binary's build provenance via `gh attestation
// verify`.
//
// The two mechanisms deliberately use different trust roots and cadences:
//
//   - Build provenance (VerifyBinary) answers "did bitwise-media-group's CI build
//     this exact binary?" against GitHub's Sigstore-backed attestation store. It
//     is thorough, needs the network, and runs only when the user asks for it
//     (`gh claude verify`). It reuses the `gh` CLI — always present, since this is
//     a gh extension — so it costs no extra dependency and carries Sigstore's
//     trusted root for offline bundle checks.
//
//   - The security policy (Checker) answers "is this version known-bad right
//     now?". It is a small JSON document signed by a long-lived policy key that is
//     embedded in the binary (a TUF-root-style trust anchor), fetched from a
//     well-known URL, cached, and evaluated on throttled launch. Decoupling it
//     from the release identity lets a revocation ship without cutting a new
//     binary release, and keeps the policy's trust from depending on a possibly
//     compromised release path.
//
// Sigstore keyless signatures cannot be revoked in the CRL/OCSP sense, so
// revocation here is additive: the policy names bad versions/digests and the
// client refuses to run them. Rollback and freeze attacks on the policy channel
// are countered by a monotonic Sequence and an expiry timestamp (see Checker).
package integrity

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// SchemaVersion is the policy document schema this build understands. A policy
// carrying a different schema is treated as unusable — the client must not guess
// at fields it does not know — rather than silently partially applied.
const SchemaVersion = 1

// Policy is the signed security policy: the minimum safe version and an explicit
// revocation list, wrapped in freshness and rollback metadata. It is always
// transported alongside a detached signature over its exact bytes; nothing here
// is trusted until that signature verifies against the embedded policy key.
type Policy struct {
	Schema   int       `json:"schema"`
	Sequence uint64    `json:"sequence"`  // monotonic; a fetched policy below the cached value is a rollback and rejected
	IssuedAt time.Time `json:"issued_at"` // when this revision was cut
	// Expires bounds an "all clear": past it, a fresh policy must be fetched
	// before the good verdict is trusted again (freeze protection).
	Expires time.Time `json:"expires_at"`

	// MinSafeVersion is the lowest release considered free of known critical
	// advisories; anything below it is blocked. Empty means "no floor".
	MinSafeVersion string `json:"min_safe_version,omitempty"`

	// Revoked lists specific known-bad releases by version and/or artifact
	// digest, each with operator-facing context.
	Revoked []Revocation `json:"revoked,omitempty"`
}

// Revocation names one known-bad release. A match on either Version (exact, after
// normalization) or Digest (sha256 of the running binary) blocks launch. Reason
// and Advisory are surfaced to the user so a block is actionable, not mysterious.
type Revocation struct {
	Version  string `json:"version,omitempty"`
	Digest   string `json:"digest,omitempty"`   // "sha256:<hex>" over the raw binary
	Reason   string `json:"reason,omitempty"`   // human-facing: what is wrong
	Advisory string `json:"advisory,omitempty"` // GHSA / advisory URL
}

// ParsePolicy decodes and structurally validates a policy document. It does NOT
// check the signature — callers verify that over the raw bytes first (see
// Checker.loadCache and Checker.refresh); ParsePolicy runs only on
// already-authenticated bytes.
func ParsePolicy(b []byte) (*Policy, error) {
	var p Policy
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("malformed policy: %w", err)
	}
	if p.Schema != SchemaVersion {
		return nil, fmt.Errorf("unsupported policy schema %d (this build understands %d)", p.Schema, SchemaVersion)
	}
	if p.IssuedAt.IsZero() || p.Expires.IsZero() {
		return nil, fmt.Errorf("policy missing issued_at/expires_at")
	}
	if p.Expires.Before(p.IssuedAt) {
		return nil, fmt.Errorf("policy expires_at precedes issued_at")
	}
	return &p, nil
}

// Verdict is the outcome of evaluating a policy against the running build.
type Verdict int

const (
	// VerdictClear means the policy covers this version and it is neither revoked
	// nor below the minimum safe version.
	VerdictClear Verdict = iota
	// VerdictBlocked means the policy revokes this version/digest or it falls
	// below MinSafeVersion; the launch must be refused (fail-closed).
	VerdictBlocked
)

// Evaluation is a Verdict plus the human-facing context to show when blocked.
type Evaluation struct {
	Verdict  Verdict
	Reason   string // why blocked; empty when clear
	Advisory string // advisory URL when blocked, if the policy supplied one
}

// evaluate decides whether the given build is allowed by this policy. version is
// the normalized running version (no leading "v"); digest is "sha256:<hex>" of
// the running binary, or "" when it was not computed (no digest-based rule to
// check). A digest match takes precedence, then an exact version revocation, then
// the minimum-version floor.
func (p *Policy) evaluate(version, digest string) Evaluation {
	for _, r := range p.Revoked {
		if r.Digest != "" && digest != "" && strings.EqualFold(strings.TrimSpace(r.Digest), digest) {
			return blockedBy(r)
		}
		if r.Version != "" && version != "" && sameVersion(r.Version, version) {
			return blockedBy(r)
		}
	}
	if p.MinSafeVersion != "" && version != "" {
		floor := normalize(p.MinSafeVersion)
		if less(version, floor) {
			return Evaluation{
				Verdict: VerdictBlocked,
				Reason:  fmt.Sprintf("version %s is below the minimum safe version %s", version, floor),
			}
		}
	}
	return Evaluation{Verdict: VerdictClear}
}

// hasDigestRules reports whether any revocation matches on digest, so the caller
// only pays to hash the running binary when a rule actually needs it.
func (p *Policy) hasDigestRules() bool {
	for _, r := range p.Revoked {
		if r.Digest != "" {
			return true
		}
	}
	return false
}

func blockedBy(r Revocation) Evaluation {
	reason := strings.TrimSpace(r.Reason)
	if reason == "" {
		reason = "this version is revoked by the security policy"
	}
	return Evaluation{Verdict: VerdictBlocked, Reason: reason, Advisory: r.Advisory}
}
