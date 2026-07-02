// Copyright 2026 Bitwise Media Group Ltd.
// SPDX-License-Identifier: MIT

package cmd

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"
)

func loginCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "login",
		Short: "Create or refresh the stored token without launching Claude",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := integrityGate(cmd.Context()); err != nil {
				return err
			}
			mgr, st, err := newManager(storeOptions(cmd))
			if err != nil {
				return err
			}
			warnIfFileFallback(st)
			rec, err := mgr.Ensure(true, newProvisioner())
			if err != nil {
				return err
			}
			fmt.Printf("Logged in as @%s. Token expires %s.\n", rec.Login, rec.ExpiresAt.Format(time.RFC1123))
			return nil
		},
	}
}

func logoutCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Remove the stored token",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			mgr, _, err := newManager(storeOptions(cmd))
			if err != nil {
				return err
			}
			if err := mgr.Clear(); err != nil {
				return err
			}
			fmt.Println("Removed the stored token.")
			return nil
		},
	}
}

func statusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show the stored token's account and expiry",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			mgr, st, err := newManager(storeOptions(cmd))
			if err != nil {
				return err
			}
			rec, err := mgr.Current()
			if err != nil {
				return err
			}
			storage := st.Backend()
			if d := st.Detail(); d != "" {
				storage = fmt.Sprintf("%s (%s)", storage, d)
			}
			fmt.Printf("Storage:  %s\n", storage)
			if rec == nil {
				fmt.Println("Token:    none stored — run `gh claude` to create one")
				return nil
			}
			fmt.Printf("Account:  @%s\n", rec.Login)
			fmt.Printf("Host:     %s\n", rec.Host)
			fmt.Printf("Created:  %s\n", rec.CreatedAt.Format(time.RFC1123))
			remaining := time.Until(rec.ExpiresAt)
			if remaining <= 0 {
				fmt.Printf("Expires:  %s (EXPIRED — a new token will be created on next launch)\n",
					rec.ExpiresAt.Format(time.RFC1123))
			} else {
				fmt.Printf("Expires:  %s (%s remaining)\n",
					rec.ExpiresAt.Format(time.RFC1123), humanizeDuration(remaining))
			}
			return nil
		},
	}
}

// humanizeDuration renders a positive duration as a compact "Xd Yh Zm" string.
func humanizeDuration(d time.Duration) string {
	d = d.Round(time.Minute)
	days := d / (24 * time.Hour)
	d -= days * 24 * time.Hour
	hours := d / time.Hour
	d -= hours * time.Hour
	mins := d / time.Minute
	switch {
	case days > 0:
		return fmt.Sprintf("%dd %dh", days, hours)
	case hours > 0:
		return fmt.Sprintf("%dh %dm", hours, mins)
	default:
		return fmt.Sprintf("%dm", mins)
	}
}
