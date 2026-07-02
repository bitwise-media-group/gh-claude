// Copyright 2026 Bitwise Media Group Ltd.
// SPDX-License-Identifier: MIT

package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/bitwise-media-group/gh-claude/internal/integrity"
	"github.com/bitwise-media-group/gh-claude/internal/store"
	"github.com/spf13/cobra"
)

// verifyCmd verifies the running binary's build provenance against GitHub's
// attestation store via `gh attestation verify`. Unlike the launch-time policy
// check (which answers "is this version known-bad?"), this answers "did this
// org's CI actually build this exact binary?" and is run on demand.
func verifyCmd() *cobra.Command {
	var signerWorkflow, certIdentity string
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify this binary's build provenance via GitHub attestations",
		Long: `Verify that the running gh-claude binary was built by
bitwise-media-group's release workflow and recorded in GitHub's attestation
store, using "gh attestation verify". Needs network access to GitHub.

By default it asserts only that the binary was built by this org's CI from this
repository. Use --signer-workflow to pin the exact building workflow, or
--cert-identity for a signer-identity regexp.`,
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			path, err := integrity.RunningBinaryPath()
			if err != nil {
				return fmt.Errorf("locating the running binary: %w", err)
			}
			out, err := integrity.VerifyBinary(path, integrity.VerifyOptions{
				SignerWorkflow: signerWorkflow,
				CertIdentity:   certIdentity,
				JSON:           jsonOut,
			})
			if err != nil {
				return err
			}
			fmt.Println(out)
			return nil
		},
	}
	cmd.Flags().StringVar(&signerWorkflow, "signer-workflow", "",
		"require this exact building workflow (owner/repo/.github/workflows/file.yaml)")
	cmd.Flags().StringVar(&certIdentity, "cert-identity", "",
		"require a signer identity matching this regexp (alternative to --signer-workflow)")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print gh's JSON verification result")
	return cmd
}

// versionCmd prints the injected build version.
func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the gh-claude version",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			fmt.Println(version)
			return nil
		},
	}
}

// integrityGate runs the launch-time security-policy check before a token is
// provisioned. It fails closed — returning an error that stops the launch — only
// when a trusted policy revokes this version; it fails open (a stderr warning,
// launch proceeds) when the policy cannot be reached or verified, so an incident
// on our side never bricks a developer's workflow. It is a no-op for local/dev
// builds, when the policy channel is unconfigured, or when the user opts out with
// GH_CLAUDE_SKIP_INTEGRITY.
func integrityGate(ctx context.Context) error {
	if os.Getenv("GH_CLAUDE_SKIP_INTEGRITY") != "" {
		return nil
	}
	chk := integrity.New(version, store.ConfigDir())
	if url := os.Getenv("GH_CLAUDE_POLICY_URL"); url != "" {
		chk.URL = url // self-host / testing override
	}
	switch res := chk.Run(ctx); res.State {
	case integrity.StateBlocked:
		return errors.New(res.Message)
	case integrity.StateUnknown:
		_, _ = fmt.Fprintln(os.Stderr, "warning: "+res.Message)
	}
	return nil
}
