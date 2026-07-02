// Copyright 2026 Bitwise Media Group Ltd.
// SPDX-License-Identifier: MIT

package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"

	"github.com/bitwise-media-group/gh-claude/internal/atomicfile"
)

// fileFormatVersion tags the on-disk blob layout so a future format change can be
// detected. Blobs written by the old 99designs/keyring file backend (JWE) do not
// carry this byte and fail to decrypt; get() treats that as "no item" so the
// login flow transparently re-authenticates. See README "Security model".
const fileFormatVersion byte = 1

const (
	fileSaltLen  = 16
	fileNonceLen = 12 // AES-GCM standard nonce size
	fileKeyLen   = 32 // AES-256
)

// fileBackend persists each item as an individually encrypted file under dir.
// The symmetric key is derived from a machine-bound password (see filePassword)
// via HKDF-SHA256, and the payload is sealed with AES-256-GCM. HKDF (rather than
// a slow password hash like PBKDF2) is appropriate because the password is
// already 256-bit machine-derived entropy, not a human passphrase.
type fileBackend struct {
	dir      string
	password func(string) (string, error)
}

// newFileBackend prepares dir (0700) and returns a backend rooted there. It is
// the fallback store on every platform and the primary store on hosts without a
// native credential manager (e.g. Linux, WSL2).
func newFileBackend(dir string, password func(string) (string, error)) (*fileBackend, error) {
	if dir == "" {
		return nil, fmt.Errorf("no directory provided for file store")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("creating store directory: %w", err)
	}
	return &fileBackend{dir: dir, password: password}, nil
}

// filename maps a key to a path. The key is base64url-encoded so arbitrary key
// strings (e.g. "github.com") are always safe, reversible filenames.
func (b *fileBackend) filename(key string) string {
	return filepath.Join(b.dir, base64.RawURLEncoding.EncodeToString([]byte(key)))
}

// aead derives the per-item key from the machine-bound password and salt and
// returns an AES-256-GCM cipher for it.
func (b *fileBackend) aead(key string, salt []byte) (cipher.AEAD, error) {
	pw, err := b.password(key)
	if err != nil {
		return nil, err
	}
	dk, err := hkdf.Key(sha256.New, []byte(pw), salt, "gh-claude:"+key, fileKeyLen)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(dk)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// aad binds a ciphertext to its format version and key so a blob cannot be
// silently substituted between slots.
func aad(key string) []byte {
	return append([]byte{fileFormatVersion}, key...)
}

func (b *fileBackend) get(key string) ([]byte, bool, error) {
	blob, err := os.ReadFile(b.filename(key))
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}

	data, derr := b.decrypt(key, blob)
	if derr != nil {
		// An undecryptable blob is almost always one written by a previous
		// version (the keyring JWE format) or a corrupt/foreign file. Treat it
		// as absent so the caller re-provisions, and clear the stale file so the
		// next Set writes cleanly. See the clean-break note on fileFormatVersion.
		_ = os.Remove(b.filename(key))
		fmt.Fprintln(os.Stderr,
			"warning: stored token could not be read (re-authenticate with `gh claude login`).")
		return nil, false, nil
	}
	return data, true, nil
}

// decrypt parses and opens a blob of the form
// version(1) ‖ salt(fileSaltLen) ‖ nonce(fileNonceLen) ‖ AES-256-GCM(ciphertext‖tag).
func (b *fileBackend) decrypt(key string, blob []byte) ([]byte, error) {
	const header = 1 + fileSaltLen + fileNonceLen
	if len(blob) < header || blob[0] != fileFormatVersion {
		return nil, fmt.Errorf("unrecognized store format")
	}
	salt := blob[1 : 1+fileSaltLen]
	nonce := blob[1+fileSaltLen : header]
	ciphertext := blob[header:]

	aead, err := b.aead(key, salt)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, ciphertext, aad(key))
}

func (b *fileBackend) set(key string, data []byte) error {
	salt := make([]byte, fileSaltLen)
	nonce := make([]byte, fileNonceLen)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	if _, err := rand.Read(nonce); err != nil {
		return err
	}

	aead, err := b.aead(key, salt)
	if err != nil {
		return err
	}

	blob := make([]byte, 0, 1+fileSaltLen+fileNonceLen+len(data)+aead.Overhead())
	blob = append(blob, fileFormatVersion)
	blob = append(blob, salt...)
	blob = append(blob, nonce...)
	blob = aead.Seal(blob, nonce, data, aad(key))

	return atomicfile.Write(b.filename(key), blob, 0o600)
}

func (b *fileBackend) delete(key string) error {
	if err := os.Remove(b.filename(key)); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
