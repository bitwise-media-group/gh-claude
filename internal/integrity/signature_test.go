// Copyright 2026 Bitwise Media Group Ltd.
// SPDX-License-Identifier: MIT

package integrity

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
)

func allowing(t *testing.T, signers ...*signer) *sshVerifier {
	t.Helper()
	keys := make([]ssh.PublicKey, 0, len(signers))
	for _, s := range signers {
		pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(s.pubLine))
		if err != nil {
			t.Fatalf("parse key: %v", err)
		}
		keys = append(keys, pub)
	}
	return &sshVerifier{allowed: keys, namespace: PolicyNamespace}
}

func TestSSHVerifierRejectsGarbage(t *testing.T) {
	v := newSigner(t).verifier()
	if err := v.Verify([]byte("policy"), []byte("not a signature")); err == nil {
		t.Error("expected an error for non-sshsig input")
	}
}

func TestVerifierAcceptsEitherKey(t *testing.T) {
	primary, backup, stranger := newSigner(t), newSigner(t), newSigner(t)
	v := allowing(t, primary, backup)
	msg := []byte(`{"schema":1}`)

	// A signature from either embedded key is accepted...
	if err := v.Verify(msg, primary.signBytes(t, msg)); err != nil {
		t.Errorf("primary signature should verify: %v", err)
	}
	if err := v.Verify(msg, backup.signBytes(t, msg)); err != nil {
		t.Errorf("backup signature should verify: %v", err)
	}
	// ...but a signature from an untrusted key is rejected.
	if err := v.Verify(msg, stranger.signBytes(t, msg)); err == nil {
		t.Error("a stranger's signature must not verify")
	}
}

func TestVerifierRejectsWrongNamespace(t *testing.T) {
	s := newSigner(t)
	msg := []byte("policy")
	sig := s.signBytesNS(t, msg, "some-other-namespace")
	if err := s.verifier().Verify(msg, sig); err == nil {
		t.Error("a signature under a different namespace must not verify")
	}
}

func TestVerifierRejectsTamperedMessage(t *testing.T) {
	s := newSigner(t)
	sig := s.signBytes(t, []byte("original"))
	if err := s.verifier().Verify([]byte("tampered"), sig); err == nil {
		t.Error("the signature must not verify over different bytes")
	}
}

// TestVerifierAgainstSSHKeygen validates the verifier against a signature made by
// real OpenSSH (ssh-keygen -Y sign), not just our in-process signer — the check
// that our sshsig parsing matches the format the operator will actually produce.
// Skipped when ssh-keygen is unavailable.
func TestVerifierAgainstSSHKeygen(t *testing.T) {
	keygen, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen not available")
	}
	dir := t.TempDir()
	key := filepath.Join(dir, "id")
	genCmd := exec.Command(keygen, "-t", "ed25519", "-N", "", "-C", "policy@test", "-f", key)
	if out, err := genCmd.CombinedOutput(); err != nil {
		t.Fatalf("keygen: %v\n%s", err, out)
	}

	msg := []byte(`{"schema":1,"sequence":1}`)
	msgFile := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(msgFile, msg, 0o600); err != nil {
		t.Fatal(err)
	}
	// ssh-keygen -Y sign writes <file>.sig
	signCmd := exec.Command(keygen, "-Y", "sign", "-n", PolicyNamespace, "-f", key, msgFile)
	if out, err := signCmd.CombinedOutput(); err != nil {
		t.Fatalf("sign: %v\n%s", err, out)
	}
	sig, err := os.ReadFile(msgFile + ".sig")
	if err != nil {
		t.Fatal(err)
	}
	pubLine, err := os.ReadFile(key + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(pubLine)
	if err != nil {
		t.Fatal(err)
	}

	v := &sshVerifier{allowed: []ssh.PublicKey{pub}, namespace: PolicyNamespace}
	if err := v.Verify(msg, sig); err != nil {
		t.Errorf("verifier rejected a real ssh-keygen signature: %v", err)
	}
	// A different namespace expectation, or tampered bytes, must fail.
	if err := (&sshVerifier{allowed: []ssh.PublicKey{pub}, namespace: "different"}).Verify(msg, sig); err == nil {
		t.Error("expected a namespace mismatch to fail")
	}
	if err := v.Verify([]byte("tampered"), sig); err == nil {
		t.Error("expected tampered bytes to fail")
	}
}
