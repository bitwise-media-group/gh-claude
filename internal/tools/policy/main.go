// Copyright 2026 Bitwise Media Group Ltd.
// SPDX-License-Identifier: MIT

// Command policy creates, updates, renews, and signs the gh-claude security
// policy (see docs/security-policy.md). It is a maintainer tool, run from the
// repository with `go run ./internal/tools/policy`, never shipped to users.
//
// With only --policy set it renews the existing policy: the sequence is bumped
// by one, the floor and revocations carry over, and the issue/expiry dates are
// refreshed over the same period. Flags override individual fields; --revoke
// appends versions to the revocation list. Without --policy a new policy is
// created, and --expires-days, --sequence, and --min-version are all required.
//
// The policy is signed with `ssh-keygen -Y sign` (so the key can be a FIDO2
// sk-ssh-ed25519 YubiKey — touch it when it blinks) and then verified against
// the policy keys embedded in this build — the exact trust anchors shipped
// clients enforce — before the policy and its .sig are moved into place. A
// signature made with an untrusted key never overwrites the published pair.
package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/bitwise-media-group/gh-claude/internal/integrity"
	"github.com/spf13/cobra"
)

// defaultOut is where a newly created policy lands when --policy is not given:
// the docs tree, from which the docs site publishes it at the client's policyURL.
const defaultOut = "docs/policy.json"

func main() {
	if err := newPolicyCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// policyOptions carries the parsed flags into run.
type policyOptions struct {
	policyPath  string
	expiresDays int
	sequence    uint64
	minVersion  string
	keyPath     string
	revoke      []string
}

// newPolicyCmd builds the tool's single command.
func newPolicyCmd() *cobra.Command {
	var opts policyOptions
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Create, renew, update, and sign the gh-claude security policy",
		Long: `Create, renew, update, and sign the gh-claude security policy.

With only --policy set, the existing policy is renewed: the sequence is bumped
by one, the minimum safe version and revocations carry over, and the
issue/expiry dates are refreshed over the same period. Without --policy a new
policy is created and --expires-days, --sequence, and --min-version are all
required.

The policy is signed with ssh-keygen (touch the YubiKey when it blinks) and the
signature is verified against the policy keys embedded in this build before the
policy and its .sig are moved into place.`,
		Example: `  go run ./internal/tools/policy --policy docs/policy.json
  go run ./internal/tools/policy --policy docs/policy.json --revoke 0.1.2 --min-version 0.1.3
  go run ./internal/tools/policy --expires-days 14 --sequence 1 --min-version 0.1.0`,
		Args:          cobra.NoArgs,
		SilenceUsage:  true, // errors are failures, not usage mistakes
		SilenceErrors: true, // main prints the error once
		RunE: func(_ *cobra.Command, _ []string) error {
			return run(opts)
		},
	}

	f := cmd.Flags()
	f.StringVar(&opts.policyPath, "policy", "",
		"existing policy to update and overwrite (omit to create "+defaultOut+")")
	f.IntVar(&opts.expiresDays, "expires-days", 0,
		"validity period in days (default: the existing policy's period)")
	f.Uint64Var(&opts.sequence, "sequence", 0,
		"policy sequence number, starting at 1 (default: one above the existing policy's)")
	f.StringVar(&opts.minVersion, "min-version", "",
		"minimum safe version; releases below it are blocked (default: the existing floor)")
	f.StringVar(&opts.keyPath, "key", defaultKeyPath(),
		"SSH private key or FIDO2 key handle that signs the policy")
	f.StringSliceVar(&opts.revoke, "revoke", nil,
		"version(s) to revoke, comma-separated; may be repeated")
	return cmd
}

func run(opts policyOptions) error {
	if opts.keyPath == "" {
		return errors.New("set --key to the SSH key that signs the policy")
	}

	var existing *integrity.Policy
	if opts.policyPath != "" {
		b, err := os.ReadFile(opts.policyPath)
		if err != nil {
			return fmt.Errorf("reading the existing policy: %w", err)
		}
		if existing, err = integrity.ParsePolicy(b); err != nil {
			return err
		}
	}

	// pflag's CSV splitting keeps empty fields (e.g. "0.1.0,,0.1.1"); drop them
	// rather than rejecting them as malformed versions.
	revoke := slices.DeleteFunc(opts.revoke, func(s string) bool { return strings.TrimSpace(s) == "" })

	next, err := integrity.NextPolicy(existing, integrity.AuthorOptions{
		ExpiresIn:      time.Duration(opts.expiresDays) * 24 * time.Hour,
		Sequence:       opts.sequence,
		MinSafeVersion: opts.minVersion,
		Revoke:         revoke,
	}, time.Now())
	if err != nil {
		return err
	}
	b, err := integrity.MarshalPolicy(next)
	if err != nil {
		return err
	}

	out := opts.policyPath
	if out == "" {
		out = defaultOut
	}
	if err := signAndPublish(out, b, opts.keyPath); err != nil {
		return err
	}
	fmt.Printf("wrote %s and %s.sig (sequence %d, expires %s)\n",
		out, out, next.Sequence, next.Expires.Format(time.RFC3339))
	return nil
}

// signAndPublish stages the policy bytes next to out, signs them with
// ssh-keygen, verifies the signature against the embedded policy keys, and only
// then moves the policy and its detached signature into place — so a failed or
// wrongly-keyed signing run never clobbers the published pair.
func signAndPublish(out string, policy []byte, keyPath string) error {
	staged := out + ".new"
	stagedSig := staged + ".sig"
	defer func() { _ = os.Remove(staged) }() // no-ops once renamed
	defer func() { _ = os.Remove(stagedSig) }()

	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(staged, policy, 0o644); err != nil {
		return err
	}

	// ssh-keygen writes <staged>.sig; stdio passes through for the touch prompt.
	cmd := exec.Command("ssh-keygen", "-Y", "sign", "-n", integrity.PolicyNamespace, "-f", keyPath, staged)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("signing the policy (is the signing key available?): %w", err)
	}

	sig, err := os.ReadFile(stagedSig)
	if err != nil {
		return fmt.Errorf("reading the signature ssh-keygen wrote: %w", err)
	}
	verifier, err := integrity.EmbeddedVerifier()
	if err != nil {
		return fmt.Errorf("this build embeds no policy key to verify against: %w", err)
	}
	if err := verifier.Verify(policy, sig); err != nil {
		return fmt.Errorf("the signature does not verify against the embedded policy keys "+
			"(signed with a key clients do not trust?): %w", err)
	}

	if err := os.Rename(staged, out); err != nil {
		return err
	}
	return os.Rename(stagedSig, out+".sig")
}

// defaultKeyPath mirrors the Makefile's POLICY_KEY default (~/.ssh/id_sk_current).
func defaultKeyPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".ssh", "id_sk_current")
}
