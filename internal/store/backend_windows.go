// Copyright 2026 Bitwise Media Group Ltd.
// SPDX-License-Identifier: MIT

//go:build windows

package store

import (
	"errors"
	"fmt"
	"runtime"
	"syscall"
	"unsafe"
)

// Windows Credential Management API (advapi32.dll). Bound via the standard
// library's syscall package so no third-party dependency or cgo is required.
var (
	advapi32        = syscall.NewLazyDLL("advapi32.dll")
	procCredWriteW  = advapi32.NewProc("CredWriteW")
	procCredReadW   = advapi32.NewProc("CredReadW")
	procCredDeleteW = advapi32.NewProc("CredDeleteW")
	procCredFree    = advapi32.NewProc("CredFree")
)

const (
	credTypeGeneric         = 1    // CRED_TYPE_GENERIC
	credPersistLocalMachine = 2    // CRED_PERSIST_LOCAL_MACHINE
	errorNotFound           = 1168 // ERROR_NOT_FOUND
)

// filetime mirrors the Win32 FILETIME struct (unused fields, kept for layout).
type filetime struct {
	LowDateTime  uint32
	HighDateTime uint32
}

// credentialW mirrors the Win32 CREDENTIALW struct. Field order and types must
// match the C layout exactly so the syscall marshals correctly.
type credentialW struct {
	Flags              uint32
	Type               uint32
	TargetName         *uint16
	Comment            *uint16
	LastWritten        filetime
	CredentialBlobSize uint32
	CredentialBlob     *byte
	Persist            uint32
	AttributeCount     uint32
	Attributes         uintptr
	TargetAlias        *uint16
	UserName           *uint16
}

// credmanBackend persists each item as a generic credential in the Windows
// Credential Manager under the target name "gh-claude:<key>".
type credmanBackend struct {
	prefix string
}

// newNativeBackend returns the Credential Manager backend. advapi32 is always
// present on Windows, so there is nothing to probe.
func newNativeBackend() (backend, string, error) {
	return credmanBackend{prefix: ServiceName + ":"}, BackendCredentialManager, nil
}

func (c credmanBackend) target(key string) string { return c.prefix + key }

func (c credmanBackend) set(key string, data []byte) error {
	target, err := syscall.UTF16PtrFromString(c.target(key))
	if err != nil {
		return err
	}
	cred := credentialW{
		Type:               credTypeGeneric,
		TargetName:         target,
		Persist:            credPersistLocalMachine,
		CredentialBlobSize: uint32(len(data)),
	}
	if len(data) > 0 {
		cred.CredentialBlob = &data[0]
	}
	ret, _, callErr := procCredWriteW.Call(uintptr(unsafe.Pointer(&cred)), 0)
	runtime.KeepAlive(cred)
	runtime.KeepAlive(target)
	runtime.KeepAlive(data)
	if ret == 0 {
		return fmt.Errorf("CredWrite failed: %w", callErr)
	}
	return nil
}

func (c credmanBackend) get(key string) ([]byte, bool, error) {
	target, err := syscall.UTF16PtrFromString(c.target(key))
	if err != nil {
		return nil, false, err
	}
	var pcred *credentialW
	ret, _, callErr := procCredReadW.Call(
		uintptr(unsafe.Pointer(target)),
		credTypeGeneric,
		0,
		uintptr(unsafe.Pointer(&pcred)),
	)
	runtime.KeepAlive(target)
	if ret == 0 {
		if isCredNotFound(callErr) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("CredRead failed: %w", callErr)
	}
	defer procCredFree.Call(uintptr(unsafe.Pointer(pcred)))

	// Copy the blob out of the OS-allocated buffer before CredFree runs.
	blob := unsafe.Slice(pcred.CredentialBlob, pcred.CredentialBlobSize)
	out := make([]byte, len(blob))
	copy(out, blob)
	return out, true, nil
}

func (c credmanBackend) delete(key string) error {
	target, err := syscall.UTF16PtrFromString(c.target(key))
	if err != nil {
		return err
	}
	ret, _, callErr := procCredDeleteW.Call(uintptr(unsafe.Pointer(target)), credTypeGeneric, 0)
	runtime.KeepAlive(target)
	if ret == 0 {
		if isCredNotFound(callErr) {
			return nil // deleting a missing item is not an error
		}
		return fmt.Errorf("CredDelete failed: %w", callErr)
	}
	return nil
}

// isCredNotFound reports whether a Cred* syscall failed because the item does
// not exist (ERROR_NOT_FOUND).
func isCredNotFound(callErr error) bool {
	errno, ok := errors.AsType[syscall.Errno](callErr)
	return ok && errno == errorNotFound
}
