// Copyright 2026 Bitwise Media Group Ltd.
// SPDX-License-Identifier: MIT

//go:build !darwin && !windows

package store

// newNativeBackend reports that there is no platform-native credential store on
// this OS (Linux, *BSD, WSL2, …), so New uses the encrypted file backend. The
// GNOME/KWallet Secret Service is intentionally not used: reaching it requires a
// D-Bus client, which would reintroduce a third-party dependency. The file
// backend is machine-bound and 0600; see README "Security model".
func newNativeBackend() (backend, string, error) {
	return nil, "", nil
}
