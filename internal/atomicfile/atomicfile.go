// Copyright 2026 Bitwise Media Group Ltd.
// SPDX-License-Identifier: MIT

// Package atomicfile writes a file via a same-directory temporary file and an
// atomic rename, so a reader never observes a partially written file.
package atomicfile

import (
	"os"
	"path/filepath"
)

// Write writes data to path with the given permissions. The data lands in a
// temporary file in path's directory that is renamed into place; on any
// failure the temporary file is removed and the existing file (if any) is left
// untouched.
func Write(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // no-op after a successful rename

	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
