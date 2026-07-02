// Copyright 2026 Bitwise Media Group Ltd.
// SPDX-License-Identifier: MIT

package integrity

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/bitwise-media-group/gh-claude/internal/atomicfile"
)

// State is the launch-time verdict the Checker hands back to the caller.
type State int

const (
	// StateDisabled: the policy channel is not configured for this build, or this
	// is not a release version. No message; launch proceeds unchanged.
	StateDisabled State = iota
	// StateClear: a trusted, sufficiently fresh policy covers this version and
	// does not revoke it. Launch proceeds.
	StateClear
	// StateBlocked: a trusted policy revokes this version/digest or it is below
	// the minimum safe version. The caller MUST refuse to launch (fail-closed).
	StateBlocked
	// StateUnknown: no trusted, fresh policy could be obtained (offline first
	// run, or a stale "all clear" that could not be refreshed). The caller warns
	// and proceeds (fail-open) — a network failure must never itself block work,
	// and, crucially, must never un-revoke a version (see Run).
	StateUnknown
)

// Result is the outcome of a launch-time check.
type Result struct {
	State    State
	Message  string // advisory text when Blocked; a staleness/offline note when Unknown
	Sequence uint64 // sequence of the trusted policy, when one was in play (diagnostics)
}

// Blocked reports whether the caller must refuse to launch.
func (r Result) Blocked() bool { return r.State == StateBlocked }

// Defaults for the policy channel. The signed policy and its detached signature
// live at docs/policy.json(.sig) in the repository and are published at
// policyURL (and policyURL+sigSuffix) by the docs site.
const (
	policyURL = "https://oss.bitwisemedia.uk/gh-claude/policy.json"

	sigSuffix       = ".sig"
	cacheFileName   = "security-policy.json"
	defaultRefresh  = 6 * time.Hour
	defaultTimeout  = 3 * time.Second
	maxPolicyBytes  = 1 << 20 // 1 MiB ceiling on a fetched policy/signature
	digestAlgPrefix = "sha256:"
)

// Fail-open messages surfaced to the user when no trusted, fresh policy applies.
const (
	msgNoPolicy = "could not obtain a signed security policy; " +
		"proceeding without a revocation check"
	msgStalePolicy = "the cached security policy is stale and could not be refreshed; " +
		"proceeding without an up-to-date revocation check"
)

// Checker performs the launch-time policy check. Every external dependency is a
// field so the whole flow is unit-testable offline; New wires the production
// defaults.
type Checker struct {
	Version  string                                                // running version (raw; normalized internally)
	URL      string                                                // policy endpoint; "" disables the channel
	Verify   Verifier                                              // policy signature verifier; nil disables the channel
	CacheDir string                                                // directory for the cached, re-verifiable policy
	Now      func() time.Time                                      // injectable clock
	Refresh  time.Duration                                         // max cache age before a network refresh is attempted
	Timeout  time.Duration                                         // per-request network timeout
	Fetch    func(ctx context.Context, url string) ([]byte, error) // fetch one URL's bytes
	Digest   func() (string, error)                                // "sha256:<hex>" of the running binary (lazy)
}

// New builds a Checker with production defaults: the embedded OpenSSH policy key(s),
// the hosted policy URL, the gh-claude config dir for caching, and an HTTP
// fetcher. The URL may be overridden by the caller (e.g. from an env var) before
// Run. When no policy key is embedded, Verify is left nil and the channel is
// disabled — Run then reports StateDisabled and never touches the network.
func New(version, cacheDir string) *Checker {
	v, err := EmbeddedVerifier()
	if err != nil {
		v = nil // errNoPolicyKey (or a malformed embedded key): channel disabled
	}
	return &Checker{
		Version:  version,
		URL:      policyURL,
		Verify:   v,
		CacheDir: cacheDir,
		Now:      time.Now,
		Refresh:  defaultRefresh,
		Timeout:  defaultTimeout,
		Fetch:    httpFetch,
		Digest:   runningDigest,
	}
}

// enabled reports whether the policy channel is configured and applicable to this
// build. A non-release version (dev build, snapshot) is never gated.
func (c *Checker) enabled() bool {
	return c.URL != "" && c.Verify != nil && isRelease(c.Version)
}

// Run performs the check and returns the verdict. It never returns an error: a
// failure to reach or verify the policy degrades to StateUnknown (fail-open), so
// the caller's policy — not an incident on our side — decides what to do.
//
// The ordering encodes two invariants:
//   - A known-bad verdict from any trusted policy (freshly fetched OR previously
//     cached and re-verified) stands even when the network is down: losing
//     connectivity must not silently un-revoke a vulnerable build.
//   - A stale "all clear" that cannot be refreshed decays to Unknown rather than
//     being trusted forever, so an attacker cannot freeze clients on an old
//     good policy (the Expires field, backed by the monotonic Sequence).
func (c *Checker) Run(ctx context.Context) Result {
	if !c.enabled() {
		return Result{State: StateDisabled}
	}
	now := c.Now()

	cached, cachedRaw := c.loadCache() // nil when absent/tampered/unverifiable

	trusted := cached
	if c.shouldRefresh(cached, cachedRaw, now) {
		if fetched, note := c.refresh(ctx, cached); fetched != nil {
			trusted = fetched
		} else if note != "" && cached == nil {
			// Nothing trusted at all and the refresh failed: fail-open below, but
			// carry the reason so the caller can explain the warning.
			return Result{State: StateUnknown, Message: note}
		}
	}

	if trusted == nil {
		return Result{State: StateUnknown, Message: msgNoPolicy}
	}

	eval := c.evaluate(trusted)
	if eval.Verdict == VerdictBlocked {
		return Result{State: StateBlocked, Sequence: trusted.Sequence, Message: blockMessage(c.Version, eval)}
	}

	// Clear — but do not trust an "all clear" past its expiry if we could not
	// refresh it (freeze protection).
	if !now.Before(trusted.Expires) {
		return Result{State: StateUnknown, Sequence: trusted.Sequence, Message: msgStalePolicy}
	}
	return Result{State: StateClear, Sequence: trusted.Sequence}
}

// evaluate computes the policy verdict, hashing the running binary only when a
// digest-based rule is present (and treating a hashing failure as "no digest",
// so a version/floor rule can still match).
func (c *Checker) evaluate(p *Policy) Evaluation {
	digest := ""
	if p.hasDigestRules() && c.Digest != nil {
		if d, err := c.Digest(); err == nil {
			digest = d
		}
	}
	return p.evaluate(normalize(c.Version), digest)
}

// shouldRefresh decides whether to hit the network: when there is no usable
// cache, when the cache is older than Refresh, or when the cached policy has
// expired and must be renewed before its "all clear" can be trusted again.
func (c *Checker) shouldRefresh(cached *Policy, raw *cachedEnvelope, now time.Time) bool {
	if cached == nil || raw == nil {
		return true
	}
	if now.Sub(raw.FetchedAt) >= c.Refresh {
		return true
	}
	return !now.Before(cached.Expires)
}

// refresh fetches, verifies, and rollback-checks a new policy. On success it
// persists the new envelope and returns the parsed policy. On any failure it
// returns (nil, note) and the caller keeps whatever it already trusted; note is
// a human-facing reason used only when there was no prior trusted policy.
func (c *Checker) refresh(ctx context.Context, cached *Policy) (*Policy, string) {
	ctx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()

	raw, err := c.Fetch(ctx, c.URL)
	if err != nil {
		return nil, "security policy is unreachable"
	}
	sig, err := c.Fetch(ctx, c.URL+sigSuffix)
	if err != nil {
		return nil, "security-policy signature is unreachable"
	}
	if err := c.Verify.Verify(raw, sig); err != nil {
		// A served-but-unverifiable policy is a red flag, not a soft miss.
		return nil, "security policy failed signature verification and was ignored"
	}
	p, err := ParsePolicy(raw)
	if err != nil {
		return nil, "security policy was malformed and was ignored"
	}
	// Rollback guard: never accept a policy older than one we have already
	// trusted, even though it is validly signed (an attacker replaying an old
	// revision that predates a revocation).
	if cached != nil && p.Sequence < cached.Sequence {
		return nil, "served security policy is older than the cached one and was rejected as a rollback"
	}
	c.saveCache(&cachedEnvelope{Policy: raw, Signature: sig, FetchedAt: c.Now()})
	return p, ""
}

// cachedEnvelope is the on-disk cache: the exact signed bytes and their detached
// signature (so the cache is re-verified on load and a tampered cache is treated
// as absent), plus when it was fetched (to throttle refreshes).
type cachedEnvelope struct {
	Policy    []byte    `json:"policy"` // base64 via encoding/json
	Signature []byte    `json:"signature"`
	FetchedAt time.Time `json:"fetched_at"`
}

// loadCache reads and re-verifies the cached policy. A missing, unreadable,
// signature-invalid, or malformed cache yields (nil, nil): the caller then treats
// the channel as having no prior trusted policy.
func (c *Checker) loadCache() (*Policy, *cachedEnvelope) {
	b, err := os.ReadFile(c.cachePath())
	if err != nil {
		return nil, nil
	}
	var env cachedEnvelope
	if err := json.Unmarshal(b, &env); err != nil {
		return nil, nil
	}
	if err := c.Verify.Verify(env.Policy, env.Signature); err != nil {
		return nil, nil
	}
	p, err := ParsePolicy(env.Policy)
	if err != nil {
		return nil, nil
	}
	return p, &env
}

// saveCache atomically writes the envelope (best-effort; a cache write failure
// must not fail a launch).
func (c *Checker) saveCache(env *cachedEnvelope) {
	b, err := json.Marshal(env)
	if err != nil {
		return
	}
	if err := os.MkdirAll(c.CacheDir, 0o700); err != nil {
		return
	}
	_ = atomicfile.Write(c.cachePath(), b, 0o600)
}

func (c *Checker) cachePath() string { return filepath.Join(c.CacheDir, cacheFileName) }

// blockMessage renders the user-facing refusal, including the advisory link when
// the policy supplied one.
func blockMessage(version string, e Evaluation) string {
	msg := fmt.Sprintf("gh-claude %s is blocked by the security policy: %s", version, e.Reason)
	if e.Advisory != "" {
		msg += "\nAdvisory: " + e.Advisory
	}
	msg += "\nUpgrade with: gh extension upgrade claude"
	return msg
}

// httpFetch is the default fetcher: a plain GET with a bounded body. The caller
// supplies the timeout via the request context.
func httpFetch(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxPolicyBytes))
}

// runningDigest returns "sha256:<hex>" over the bytes of the running executable.
func runningDigest() (string, error) {
	path, err := RunningBinaryPath()
	if err != nil {
		return "", err
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return digestAlgPrefix + hex.EncodeToString(h.Sum(nil)), nil
}
