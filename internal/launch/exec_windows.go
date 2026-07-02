// Copyright 2026 Bitwise Media Group Ltd.
// SPDX-License-Identifier: MIT

//go:build windows

package launch

import (
	"errors"
	"os"
	"os/exec"
)

// execProcess runs claude as a child on Windows (which has no exec replacement),
// inheriting stdio and propagating the child's exit code. Native Windows is not
// a primary target — WSL2 uses the Linux build — but this keeps the binary
// functional everywhere.
func execProcess(bin string, argv, env []string) error {
	cmd := exec.Command(bin, argv[1:]...)
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		if exitErr, ok := errors.AsType[*exec.ExitError](err); ok {
			os.Exit(exitErr.ExitCode())
		}
		return err
	}
	os.Exit(0)
	return nil
}
