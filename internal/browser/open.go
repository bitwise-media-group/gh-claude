// Copyright 2026 Bitwise Media Group Ltd.
// SPDX-License-Identifier: MIT

// Package browser opens a URL in the user's default browser, with a fallback
// path for WSL2 where the Linux process must reach a Windows browser.
package browser

import (
	"os"
	"os/exec"
	"runtime"
	"strings"

	clibrowser "github.com/cli/browser"
)

// Open opens url in the user's browser. On WSL it routes to the Windows
// browser; elsewhere it uses the platform default. A non-nil error means the
// caller should print the URL for the user to open manually.
func Open(url string) error {
	if isWSL() {
		if err := openWSL(url); err == nil {
			return nil
		}
		// Fall through to the default opener as a last attempt.
	}
	return clibrowser.OpenURL(url)
}

// isWSL reports whether we are running under the Windows Subsystem for Linux.
func isWSL() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	if os.Getenv("WSL_DISTRO_NAME") != "" || os.Getenv("WSL_INTEROP") != "" {
		return true
	}
	b, err := os.ReadFile("/proc/version")
	if err != nil {
		return false
	}
	v := strings.ToLower(string(b))
	return strings.Contains(v, "microsoft") || strings.Contains(v, "wsl")
}

// openWSL opens the URL using Windows interop tooling reachable from WSL.
func openWSL(url string) error {
	if path, err := exec.LookPath("wslview"); err == nil {
		return exec.Command(path, url).Start()
	}
	if path, err := exec.LookPath("powershell.exe"); err == nil {
		// Single-quote for PowerShell so the URL's & characters are literal.
		return exec.Command(path, "-NoProfile", "-Command", "Start-Process", "'"+url+"'").Start()
	}
	return exec.Command("cmd.exe", "/c", "start", "", url).Start()
}
