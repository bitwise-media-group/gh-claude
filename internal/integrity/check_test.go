// Copyright 2026 Bitwise Media Group Ltd.
// SPDX-License-Identifier: MIT

package integrity

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// signer is a test-only policy signer holding a fresh Ed25519 SSH key, standing in
// for the operator's ssh-keygen signing key (a software key here; production uses
// a FIDO2 sk-ssh-ed25519 YubiKey, which produces the same sshsig format).
type signer struct {
	ssh     ssh.Signer
	pubLine string // authorized_keys line, as embedded in production
}

func newSigner(t *testing.T) *signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	sshSigner, err := ssh.NewSignerFromSigner(priv)
	if err != nil {
		t.Fatalf("NewSignerFromSigner: %v", err)
	}
	return &signer{ssh: sshSigner, pubLine: string(ssh.MarshalAuthorizedKey(sshSigner.PublicKey()))}
}

func (s *signer) verifier() Verifier {
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(s.pubLine))
	if err != nil {
		panic(err)
	}
	return &sshVerifier{allowed: []ssh.PublicKey{pub}, namespace: PolicyNamespace}
}

// signBytes returns an OpenSSH signature (sshsig) over msg under PolicyNamespace,
// built exactly as `ssh-keygen -Y sign` builds it.
func (s *signer) signBytes(t *testing.T, msg []byte) []byte {
	t.Helper()
	return s.signBytesNS(t, msg, PolicyNamespace)
}

func (s *signer) signBytesNS(t *testing.T, msg []byte, namespace string) []byte {
	t.Helper()
	const hashAlg = "sha512"
	sum := sha512.Sum512(msg)
	toSign := append([]byte(sshSigMagic), ssh.Marshal(signedData{
		Namespace:     namespace,
		HashAlgorithm: hashAlg,
		Hash:          string(sum[:]),
	})...)
	sig, err := s.ssh.Sign(rand.Reader, toSign)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	blob := append([]byte(sshSigMagic), ssh.Marshal(wrappedSig{
		Version:       1,
		PublicKey:     string(s.ssh.PublicKey().Marshal()),
		Namespace:     namespace,
		HashAlgorithm: hashAlg,
		Signature:     string(ssh.Marshal(*sig)),
	})...)
	return armorSSHSig(blob)
}

// sign marshals p and returns its bytes plus a detached signature over them.
func (s *signer) sign(t *testing.T, p *Policy) (raw, sig []byte) {
	t.Helper()
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal policy: %v", err)
	}
	return raw, s.signBytes(t, raw)
}

// armorSSHSig wraps a raw sshsig blob in its PEM-style armor.
func armorSSHSig(blob []byte) []byte {
	b64 := base64.StdEncoding.EncodeToString(blob)
	var sb strings.Builder
	sb.WriteString("-----BEGIN SSH SIGNATURE-----\n")
	for i := 0; i < len(b64); i += 70 {
		end := min(i+70, len(b64))
		sb.WriteString(b64[i:end])
		sb.WriteByte('\n')
	}
	sb.WriteString("-----END SSH SIGNATURE-----\n")
	return []byte(sb.String())
}

// fetchStub serves fixed policy/signature bytes (or an error) and counts calls.
type fetchStub struct {
	raw   []byte
	sig   []byte
	err   error
	calls int
}

func (f *fetchStub) fetch(_ context.Context, url string) ([]byte, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	if strings.HasSuffix(url, sigSuffix) {
		return f.sig, nil
	}
	return f.raw, nil
}

func fixedClock(ts time.Time) func() time.Time { return func() time.Time { return ts } }

// fetchFunc is the shape of Checker.Fetch, aliased to keep test signatures short.
type fetchFunc = func(context.Context, string) ([]byte, error)

// baseChecker wires a Checker against a temp cache dir with the given signer,
// version, clock, and fetcher.
func baseChecker(t *testing.T, s *signer, version string, now time.Time, fetch fetchFunc) *Checker {
	t.Helper()
	return &Checker{
		Version:  version,
		URL:      "https://policy.test/policy.json",
		Verify:   s.verifier(),
		CacheDir: t.TempDir(),
		Now:      fixedClock(now),
		Refresh:  defaultRefresh,
		Timeout:  time.Second,
		Fetch:    fetch,
		Digest:   func() (string, error) { return "sha256:abc", nil },
	}
}

func clearPolicy(seq uint64, issued time.Time) *Policy {
	return &Policy{
		Schema:         SchemaVersion,
		Sequence:       seq,
		IssuedAt:       issued,
		Expires:        issued.Add(30 * 24 * time.Hour),
		MinSafeVersion: "1.0.0",
	}
}

func revokePolicy(seq uint64, issued time.Time, version string) *Policy {
	p := clearPolicy(seq, issued)
	p.Revoked = []Revocation{{Version: version, Reason: "known bad", Advisory: "https://example/adv"}}
	return p
}

func TestRunDisabled(t *testing.T) {
	s := newSigner(t)
	now := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)

	t.Run("dev version is never gated", func(t *testing.T) {
		c := baseChecker(t, s, "dev", now, (&fetchStub{err: errors.New("x")}).fetch)
		if got := c.Run(context.Background()); got.State != StateDisabled {
			t.Fatalf("state = %v, want Disabled", got.State)
		}
	})
	t.Run("empty URL disables the channel", func(t *testing.T) {
		c := baseChecker(t, s, "1.5.0", now, (&fetchStub{err: errors.New("x")}).fetch)
		c.URL = ""
		if got := c.Run(context.Background()); got.State != StateDisabled {
			t.Fatalf("state = %v, want Disabled", got.State)
		}
	})
	t.Run("nil verifier disables the channel", func(t *testing.T) {
		c := baseChecker(t, s, "1.5.0", now, (&fetchStub{err: errors.New("x")}).fetch)
		c.Verify = nil
		if got := c.Run(context.Background()); got.State != StateDisabled {
			t.Fatalf("state = %v, want Disabled", got.State)
		}
	})
}

func TestRunFreshFetch(t *testing.T) {
	s := newSigner(t)
	issued := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	now := time.Date(2026, 6, 15, 0, 0, 0, 0, time.UTC) // inside the 30-day validity window

	t.Run("clear above floor", func(t *testing.T) {
		raw, sig := s.sign(t, clearPolicy(1, issued))
		c := baseChecker(t, s, "1.5.0", now, (&fetchStub{raw: raw, sig: sig}).fetch)
		got := c.Run(context.Background())
		if got.State != StateClear {
			t.Fatalf("state = %v (%q), want Clear", got.State, got.Message)
		}
	})

	t.Run("below floor is blocked (fail-closed)", func(t *testing.T) {
		p := clearPolicy(1, issued)
		p.MinSafeVersion = "1.4.0"
		raw, sig := s.sign(t, p)
		c := baseChecker(t, s, "1.3.9", now, (&fetchStub{raw: raw, sig: sig}).fetch)
		got := c.Run(context.Background())
		if !got.Blocked() {
			t.Fatalf("state = %v, want Blocked", got.State)
		}
		if !strings.Contains(got.Message, "minimum safe version") {
			t.Errorf("message = %q, want it to mention the floor", got.Message)
		}
	})

	t.Run("explicitly revoked version is blocked with advisory", func(t *testing.T) {
		raw, sig := s.sign(t, revokePolicy(1, issued, "1.5.0"))
		c := baseChecker(t, s, "1.5.0", now, (&fetchStub{raw: raw, sig: sig}).fetch)
		got := c.Run(context.Background())
		if !got.Blocked() {
			t.Fatalf("state = %v, want Blocked", got.State)
		}
		if !strings.Contains(got.Message, "https://example/adv") {
			t.Errorf("message = %q, want it to include the advisory URL", got.Message)
		}
	})
}

func TestRunBadSignatureIsIgnored(t *testing.T) {
	s := newSigner(t)
	other := newSigner(t) // signs with a different key than the checker trusts
	issued := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	now := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)

	raw, sig := other.sign(t, clearPolicy(1, issued))
	c := baseChecker(t, s, "1.5.0", now, (&fetchStub{raw: raw, sig: sig}).fetch)
	got := c.Run(context.Background())
	if got.State != StateUnknown {
		t.Fatalf("state = %v, want Unknown (untrusted signature must not be honored)", got.State)
	}
}

func TestRunOfflineNoCacheFailsOpen(t *testing.T) {
	s := newSigner(t)
	now := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	c := baseChecker(t, s, "1.5.0", now, (&fetchStub{err: errors.New("network down")}).fetch)
	got := c.Run(context.Background())
	if got.State != StateUnknown {
		t.Fatalf("state = %v, want Unknown (fail-open)", got.State)
	}
	if got.Message == "" {
		t.Error("fail-open result should carry an explanatory message")
	}
}

func TestFreshCacheAvoidsNetwork(t *testing.T) {
	s := newSigner(t)
	issued := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	now := time.Date(2026, 6, 15, 0, 0, 0, 0, time.UTC) // inside the cached policy's validity

	// A fetch stub that fails the test if it is ever called.
	fetch := func(context.Context, string) ([]byte, error) {
		t.Fatal("network fetch attempted despite a fresh cache")
		return nil, nil
	}
	c := baseChecker(t, s, "1.5.0", now, fetch)

	raw, sig := s.sign(t, clearPolicy(3, issued))
	c.saveCache(&cachedEnvelope{Policy: raw, Signature: sig, FetchedAt: now}) // fresh

	if got := c.Run(context.Background()); got.State != StateClear {
		t.Fatalf("state = %v, want Clear from cache", got.State)
	}
}

func TestOfflineDoesNotUnrevoke(t *testing.T) {
	s := newSigner(t)
	issued := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	now := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)

	// Cache holds a policy that revokes the running version; the network is down.
	stale := now.Add(-24 * time.Hour) // older than Refresh -> a refresh is attempted
	c := baseChecker(t, s, "1.5.0", now, (&fetchStub{err: errors.New("down")}).fetch)
	raw, sig := s.sign(t, revokePolicy(4, issued, "1.5.0"))
	c.saveCache(&cachedEnvelope{Policy: raw, Signature: sig, FetchedAt: stale})

	if got := c.Run(context.Background()); !got.Blocked() {
		t.Fatalf("state = %v, want Blocked (a network failure must not un-revoke)", got.State)
	}
}

func TestRollbackIsRejected(t *testing.T) {
	s := newSigner(t)
	issued := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	now := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)

	// Cached policy (seq 5) revokes the running version. The endpoint serves an
	// older, validly-signed policy (seq 2) that would clear it — a rollback.
	stale := now.Add(-24 * time.Hour)
	rolledBackRaw, rolledBackSig := s.sign(t, clearPolicy(2, issued))
	c := baseChecker(t, s, "1.5.0", now, (&fetchStub{raw: rolledBackRaw, sig: rolledBackSig}).fetch)
	raw, sig := s.sign(t, revokePolicy(5, issued, "1.5.0"))
	c.saveCache(&cachedEnvelope{Policy: raw, Signature: sig, FetchedAt: stale})

	if got := c.Run(context.Background()); !got.Blocked() {
		t.Fatalf("state = %v, want Blocked (rollback to a pre-revocation policy must be rejected)", got.State)
	}
}

func TestStaleAllClearFreezesToUnknown(t *testing.T) {
	s := newSigner(t)
	issued := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	// now is past the cached policy's 30-day expiry, and the network is down.
	now := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)

	c := baseChecker(t, s, "1.5.0", now, (&fetchStub{err: errors.New("down")}).fetch)
	raw, sig := s.sign(t, clearPolicy(1, issued)) // expires 2026-05-31, before now
	c.saveCache(&cachedEnvelope{Policy: raw, Signature: sig, FetchedAt: issued})

	got := c.Run(context.Background())
	if got.State != StateUnknown {
		t.Fatalf("state = %v, want Unknown (a stale 'all clear' must not be trusted forever)", got.State)
	}
}

func TestTamperedCacheIsIgnored(t *testing.T) {
	s := newSigner(t)
	issued := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	now := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)

	// Cache present but its signature does not match its bytes; with the network
	// also down there is no trusted policy -> Unknown, not a crash or false clear.
	c := baseChecker(t, s, "1.5.0", now, (&fetchStub{err: errors.New("down")}).fetch)
	raw, _ := s.sign(t, clearPolicy(1, issued))
	c.saveCache(&cachedEnvelope{Policy: raw, Signature: []byte("not-a-valid-signature"), FetchedAt: now})

	if got := c.Run(context.Background()); got.State != StateUnknown {
		t.Fatalf("state = %v, want Unknown (a tampered cache must be discarded)", got.State)
	}
}
