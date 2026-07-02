// Copyright 2026 Bitwise Media Group Ltd.
// SPDX-License-Identifier: MIT

package integrity

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// The security-policy channel's trust anchors: the OpenSSH public keys (one line
// each, authorized_keys format) whose private halves may sign a policy revision.
// They are embedded in the binary — the channel's root of trust ships with the
// client, exactly like a TUF root — so a policy is only trusted if it was signed
// by an operator holding one of these keys, independent of the (Sigstore-keyless)
// release-signing identity.
//
// The signatures are OpenSSH signatures (the `ssh-keygen -Y sign` "sshsig"
// format), so the signing key can be a FIDO2 resident `sk-ssh-ed25519` key on a
// YubiKey (the `dot security-key sign` flow) or a plain `ssh-ed25519` key — both
// verify here. This is what lets a YubiKey FIPS device (firmware 5.4.x, no PIV
// Ed25519, no ECDSA keys on hand) sign the policy: its FIDO2 Ed25519 signature
// carries an authenticator flags+counter envelope that only the SSH signature
// format (not a raw Ed25519 signature) can represent.
//
// A policy is accepted if its signature was made by ANY embedded key, so:
//   - the backup key is break-glass: if the primary signer (a YubiKey) is lost or
//     destroyed, revocations keep flowing signed by the backup; and
//   - rotation is seamless: ship a build that promotes the backup and introduces
//     a fresh primary, with no window where old clients reject a valid policy.
//
// Keep BOTH keys on separate hardware, stored apart (two YubiKeys in two safes).
// Were both slots empty, the channel would stay inert — the Checker reports
// itself disabled and launches proceed unchanged. The backup slot is still
// empty: mint the break-glass key and embed it here before a lost primary can
// matter.
//
// See docs/security-policy.md for how to generate the keys and sign a policy.
const (
	// primary signer (authorized_keys line)
	policyPublicKeySSH = "sk-ssh-ed25519@openssh.com" +
		" AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIOAKrt9W1M4xxjMNehCiTSKUfGQYhTCKOk8pN+gC4+dxAAAADXNzaDpnaC1jbGF1ZGU=" +
		" gh-claude"
	// backup / break-glass signer
	policyBackupPublicKeySSH = ""
)

// PolicyNamespace is the SSH-signature namespace the policy is signed under
// (`ssh-keygen -Y sign -n <namespace>`). Binding to a fixed namespace stops a
// signature made for another purpose from being replayed as a policy signature.
const PolicyNamespace = "gh-claude-policy"

// sshSigMagic prefixes both the wire container and the signed-data preamble of an
// OpenSSH signature (see PROTOCOL.sshsig).
const sshSigMagic = "SSHSIG"

// errNoPolicyKey signals that no policy public key is embedded, so the policy
// channel is disabled rather than failing every launch.
var errNoPolicyKey = errors.New("no policy public key embedded")

// Verifier authenticates a detached signature over a message. It returns nil iff
// sig is a valid signature over msg under a trusted key. Abstracted so the signing
// scheme (OpenSSH signatures today; a `gh attestation verify` bundle or full TUF
// later) is a swap at the seam, not a rewrite of the Checker.
type Verifier interface {
	Verify(msg, sig []byte) error
}

// sshVerifier accepts an OpenSSH signature (sshsig) that was made under the fixed
// policy namespace by one of the allowed keys. It handles both `ssh-ed25519` and
// FIDO2 `sk-ssh-ed25519` keys — the sk authenticator envelope is validated by
// x/crypto/ssh's key-specific Verify.
type sshVerifier struct {
	allowed   []ssh.PublicKey
	namespace string
}

// EmbeddedVerifier builds the Verifier from the embedded policy keys, accepting a
// signature from any of them. It returns errNoPolicyKey when none are set so the
// caller can treat the channel as disabled instead of erroring. A configured but
// malformed key is a hard error (surfaced so it is caught before release, not
// silently trusted-nothing).
func EmbeddedVerifier() (Verifier, error) {
	var allowed []ssh.PublicKey
	for _, line := range []string{policyPublicKeySSH, policyBackupPublicKeySSH} {
		if strings.TrimSpace(line) == "" {
			continue
		}
		pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil {
			return nil, fmt.Errorf("policy key: %w", err)
		}
		allowed = append(allowed, pub)
	}
	if len(allowed) == 0 {
		return nil, errNoPolicyKey
	}
	return &sshVerifier{allowed: allowed, namespace: PolicyNamespace}, nil
}

// wrappedSig is the sshsig wire container, minus the leading 6-byte magic.
type wrappedSig struct {
	Version       uint32
	PublicKey     string
	Namespace     string
	Reserved      string
	HashAlgorithm string
	Signature     string
}

// signedData is the blob the signature actually covers: the magic preamble
// followed by this structure (see PROTOCOL.sshsig).
type signedData struct {
	Namespace     string
	Reserved      string
	HashAlgorithm string
	Hash          string
}

// Verify checks that sig is a valid OpenSSH signature over msg, made under the
// expected namespace by one of the allowed keys.
func (v *sshVerifier) Verify(msg, sig []byte) error {
	blob, err := decodeArmoredSig(sig)
	if err != nil {
		return err
	}
	if !bytes.HasPrefix(blob, []byte(sshSigMagic)) {
		return errors.New("policy signature: bad sshsig magic")
	}
	var ws wrappedSig
	if err := ssh.Unmarshal(blob[len(sshSigMagic):], &ws); err != nil {
		return fmt.Errorf("policy signature: %w", err)
	}
	if ws.Version != 1 {
		return fmt.Errorf("policy signature: unsupported version %d", ws.Version)
	}
	if ws.Namespace != v.namespace {
		return fmt.Errorf("policy signature: namespace %q, want %q", ws.Namespace, v.namespace)
	}

	signer, err := ssh.ParsePublicKey([]byte(ws.PublicKey))
	if err != nil {
		return fmt.Errorf("policy signature: %w", err)
	}
	if !v.trusts(signer) {
		return errors.New("policy signature: signer is not a trusted policy key")
	}

	digest, err := hashMessage(ws.HashAlgorithm, msg)
	if err != nil {
		return err
	}
	var sshSig ssh.Signature
	if err := ssh.Unmarshal([]byte(ws.Signature), &sshSig); err != nil {
		return fmt.Errorf("policy signature: %w", err)
	}
	toVerify := append([]byte(sshSigMagic), ssh.Marshal(signedData{
		Namespace:     ws.Namespace,
		HashAlgorithm: ws.HashAlgorithm,
		Hash:          string(digest),
	})...)
	if err := signer.Verify(toVerify, &sshSig); err != nil {
		return fmt.Errorf("policy signature does not verify: %w", err)
	}
	return nil
}

// trusts reports whether pub is one of the embedded allowed keys (compared by
// their exact wire encoding).
func (v *sshVerifier) trusts(pub ssh.PublicKey) bool {
	marshaled := pub.Marshal()
	for _, a := range v.allowed {
		if bytes.Equal(a.Marshal(), marshaled) {
			return true
		}
	}
	return false
}

// hashMessage applies the sshsig-named hash to the message.
func hashMessage(alg string, msg []byte) ([]byte, error) {
	switch alg {
	case "sha256":
		sum := sha256.Sum256(msg)
		return sum[:], nil
	case "sha512":
		sum := sha512.Sum512(msg)
		return sum[:], nil
	default:
		return nil, fmt.Errorf("policy signature: unsupported hash %q", alg)
	}
}

// decodeArmoredSig strips the PEM-style armor around an OpenSSH signature and
// base64-decodes the enclosed blob.
func decodeArmoredSig(sig []byte) ([]byte, error) {
	const begin = "-----BEGIN SSH SIGNATURE-----"
	const end = "-----END SSH SIGNATURE-----"
	s := string(sig)
	i := strings.Index(s, begin)
	j := strings.Index(s, end)
	if i < 0 || j < 0 || j < i {
		return nil, errors.New("policy signature: missing SSH SIGNATURE armor")
	}
	body := s[i+len(begin) : j]
	body = strings.Join(strings.Fields(body), "") // drop line wrapping/whitespace
	blob, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		return nil, fmt.Errorf("policy signature: %w", err)
	}
	return blob, nil
}
