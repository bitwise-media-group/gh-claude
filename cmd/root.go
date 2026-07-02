// Copyright 2026 Bitwise Media Group Ltd.
// SPDX-License-Identifier: MIT

// Package cmd assembles the `gh claude` command tree: the root launch command
// and its login/logout/status/verify/version subcommands. main wires the
// ldflags-injected version in and calls Root().Execute().
package cmd

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"runtime"

	"github.com/bitwise-media-group/gh-claude/internal/browser"
	"github.com/bitwise-media-group/gh-claude/internal/launch"
	"github.com/bitwise-media-group/gh-claude/internal/store"
	"github.com/bitwise-media-group/gh-claude/internal/token"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// version is the running build's version, set by Root from the value main
// injects via -ldflags. A non-release value (e.g. "dev") leaves the launch-time
// integrity check un-gated. Package-scoped so the version and integrity commands
// can read it without threading it through every constructor.
var version = "dev"

// Root builds the top-level command tree. v is main's ldflags-injected build
// version.
func Root(v string) *cobra.Command {
	version = v

	var refresh bool
	root := &cobra.Command{
		Use:   "claude [-- claude-args...]",
		Short: "Launch Claude Code with a temporary, no-push GitHub token",
		Long: `Launch Claude Code with a temporary, least-privilege GitHub token.

The token is read-only on source code (no push) and read/write on issues and
pull requests, expires in 7 days, and is stored in your OS keychain (or an
encrypted file on systems without one, such as WSL2). An unexpired token is
reused; a new one is created in your browser only when needed. Claude is then
launched in the current directory with the token wired into gh and git.

Use --op to store the token in 1Password (via the op CLI) instead of the OS
keychain, and --vault to choose the vault.

Pass arguments through to claude after "--", e.g.:
  gh claude -- --resume`,
		Args:    cobra.ArbitraryArgs,
		Version: version,
		// Cobra honors the root's silence flags for subcommand failures too, so
		// they are set only here.
		SilenceUsage:  true, // errors are failures, not usage mistakes
		SilenceErrors: true, // main prints the error once
		RunE: func(cmd *cobra.Command, args []string) error {
			return runLaunch(cmd.Context(), refresh, storeOptions(cmd), passthroughArgs(cmd, args))
		},
	}
	root.Flags().BoolVar(&refresh, "refresh", false, "force creating a new token even if a valid one is stored")
	addStoreFlags(root)

	root.AddCommand(loginCmd(), logoutCmd(), statusCmd(), verifyCmd(), versionCmd())
	return root
}

// addStoreFlags registers the persistent flags that select the secret store, so
// they apply to `gh claude` and every subcommand.
func addStoreFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().Bool("op", false,
		"store the token in 1Password via the op CLI (instead of the OS keychain)")
	cmd.PersistentFlags().String("vault", "",
		`1Password vault for --op (default "Private"; overrides GH_CLAUDE_OP_VAULT)`)
}

// storeOptions reads the store-selection flags from cmd (or any subcommand that
// inherits them).
func storeOptions(cmd *cobra.Command) store.Options {
	useOP, _ := cmd.Flags().GetBool("op")
	vault, _ := cmd.Flags().GetString("vault")
	return store.Options{UseOnePassword: useOP, Vault: vault}
}

// passthroughArgs returns the args to forward to claude: everything after a
// "--" separator, or all positional args when no separator was used.
func passthroughArgs(cmd *cobra.Command, args []string) []string {
	if dash := cmd.ArgsLenAtDash(); dash >= 0 {
		return args[dash:]
	}
	return args
}

func runLaunch(ctx context.Context, refresh bool, opts store.Options, claudeArgs []string) error {
	if err := integrityGate(ctx); err != nil {
		return err
	}
	mgr, st, err := newManager(opts)
	if err != nil {
		return err
	}
	warnIfFileFallback(st)
	rec, err := mgr.Ensure(refresh, newProvisioner())
	if err != nil {
		return err
	}
	// Replaces this process with claude on success.
	return launch.Run(rec.Token, claudeArgs)
}

func newManager(opts store.Options) (*token.Manager, *store.Store, error) {
	st, err := store.New(opts)
	if err != nil {
		return nil, nil, err
	}
	return &token.Manager{Store: st, Out: os.Stderr}, st, nil
}

func newProvisioner() token.Provisioner {
	hostname, _ := os.Hostname()
	return token.Provisioner{
		Hostname:  hostname,
		OpenURL:   browser.Open,
		ReadToken: func() (string, error) { return readToken(os.Stdin, os.Stderr) },
	}
}

func warnIfFileFallback(st *store.Store) {
	// The encrypted file is the expected backend on Linux/BSD, so only warn on
	// platforms that have a native keychain we expected to use but couldn't reach.
	if !st.IsFileFallback() {
		return
	}
	if runtime.GOOS != "darwin" && runtime.GOOS != "windows" {
		return
	}
	_, _ = fmt.Fprintln(os.Stderr,
		"warning: OS keychain unavailable; storing the token in an encrypted file (see README: Security model).")
}

// readToken prompts for and reads the pasted token, hiding input on a terminal.
func readToken(in *os.File, out io.Writer) (string, error) {
	_, _ = fmt.Fprint(out, "Paste the new token (input hidden), then press Enter: ")
	defer func() { _, _ = fmt.Fprintln(out) }()

	fd := int(in.Fd())
	if term.IsTerminal(fd) {
		b, err := term.ReadPassword(fd)
		return string(b), err
	}
	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && err != io.EOF {
		return "", err
	}
	return line, nil
}
