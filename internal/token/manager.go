// Copyright 2026 Bitwise Media Group Ltd.
// SPDX-License-Identifier: MIT

package token

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// secretStore is the subset of internal/store.Store the manager depends on,
// kept as an interface so the provisioning logic is unit-testable.
type secretStore interface {
	Get(key string) ([]byte, bool, error)
	Set(key string, data []byte) error
	Delete(key string) error
}

// Manager loads, reuses, and provisions the scoped token record.
type Manager struct {
	Store secretStore
	Out   io.Writer        // where status/warning messages are written
	Now   func() time.Time // injectable clock (defaults to time.Now)
	// Validate verifies a token against GitHub; defaults to the package
	// Validate. Injectable so the reuse/provision flow is testable offline.
	Validate func(host, token string) (*Identity, error)
}

// Provisioner supplies the interactive pieces of creating a new token: opening
// the browser and reading the pasted value. Kept injectable for testing.
type Provisioner struct {
	Hostname  string
	OpenURL   func(url string) error
	ReadToken func() (string, error)
}

func (m *Manager) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

func (m *Manager) validate(host, tok string) (*Identity, error) {
	if m.Validate != nil {
		return m.Validate(host, tok)
	}
	return Validate(host, tok)
}

// log and logf write user-facing diagnostics to m.Out. Write errors are ignored
// on purpose: these are best-effort messages, not part of the program's contract.
func (m *Manager) log(msg string)               { _, _ = fmt.Fprintln(m.Out, msg) }
func (m *Manager) logf(format string, a ...any) { _, _ = fmt.Fprintf(m.Out, format, a...) }

// Current returns the stored record (or nil if none) without provisioning.
func (m *Manager) Current() (*Record, error) {
	return m.load()
}

// Clear deletes the stored record.
func (m *Manager) Clear() error {
	return m.Store.Delete(storeKey)
}

// Ensure returns a usable token record. It reuses the stored token when it is
// unexpired and still accepted by GitHub, and otherwise provisions a new one
// interactively. Set forceRefresh to always provision.
func (m *Manager) Ensure(forceRefresh bool, p Provisioner) (*Record, error) {
	if !forceRefresh {
		rec, err := m.load()
		if err != nil {
			return nil, err
		}
		if rec != nil && !rec.needsRefresh(m.now()) && m.verifyReusable(rec) {
			return rec, nil
		}
	}
	return m.provision(p)
}

// verifyReusable probes a non-expired stored token. It returns true when the
// token is good to reuse — including on transient verification failures, where we
// trust the stored token rather than forcing recreation while offline — and false
// only when GitHub actively rejected it.
func (m *Manager) verifyReusable(rec *Record) bool {
	_, err := m.validate(rec.Host, rec.Token)
	switch {
	case err == nil:
		if rec.expiringSoon(m.now()) {
			m.logf("Note: the stored token expires %s — run `gh claude login` to refresh it.\n",
				rec.ExpiresAt.Format(time.RFC1123))
		}
		return true
	case IsAuthError(err):
		m.log("Stored token was rejected by GitHub; creating a new one.")
		return false
	default:
		m.logf("Warning: could not verify the stored token (%v); using it anyway.\n", err)
		return true
	}
}

// maxProvisionAttempts caps how many times we re-prompt for a pasted token that
// is empty, rejected by GitHub, or doesn't match the required type/expiry, so a
// non-interactive stdin (EOF) can't loop forever.
const maxProvisionAttempts = 3

// provision runs the interactive create-and-store flow.
func (m *Manager) provision(p Provisioner) (*Record, error) {
	url := CreationURL(p.Hostname)

	m.log("A new GitHub token is needed.")
	m.log("In the page that opens:")
	m.log("  1. Under \"Repository access\" choose \"All repositories\".")
	m.log("  2. Leave the pre-filled permissions (Contents: read, Issues: read/write, Pull requests: read/write).")
	m.log("  3. Click \"Generate token\" and copy the value (starts with github_pat_).")
	m.log("")

	if err := p.OpenURL(url); err != nil {
		m.logf("Open this URL in your browser:\n  %s\n\n", url)
	} else {
		m.logf("Opened your browser. If nothing happened, use this URL:\n  %s\n\n", url)
	}

	rec, err := m.readValidToken(p, url)
	if err != nil {
		return nil, err
	}

	if err := m.save(rec); err != nil {
		return nil, err
	}
	m.logf("Saved token for @%s (expires %s).\n", rec.Login, rec.ExpiresAt.Format(time.RFC1123))
	return rec, nil
}

// readValidToken prompts for a token, retrying on recoverable failures — empty
// input, a GitHub auth rejection (likely a mis-paste), or a token whose type or
// expiry doesn't match what the creation form pre-populated. It returns a
// ready-to-store Record, or an error once the attempts are exhausted or a
// non-recoverable (transient/network) failure occurs.
func (m *Manager) readValidToken(p Provisioner, url string) (*Record, error) {
	var lastErr error
	for attempt := 1; attempt <= maxProvisionAttempts; attempt++ {
		if attempt > 1 {
			m.logf("Recreate the token in the still-open form and paste again:\n  %s\n\n", url)
		}

		raw, err := p.ReadToken()
		if err != nil {
			return nil, err
		}
		tok := strings.TrimSpace(raw)
		if tok == "" {
			lastErr = errors.New("no token was entered")
			m.log(lastErr.Error())
			continue
		}

		id, err := m.validate(Host, tok)
		if err != nil {
			if !IsAuthError(err) {
				// Transient/network failure: retrying the paste won't help.
				return nil, fmt.Errorf("could not verify the pasted token: %w", err)
			}
			lastErr = fmt.Errorf("the pasted token was rejected by GitHub: %w", authErrorHint(err))
			m.log(lastErr.Error())
			continue
		}

		if err := checkGrant(id, tok, m.now()); err != nil {
			lastErr = err
			m.logf("Token doesn't match what's required: %v\n", err)
			continue
		}

		now := m.now()
		rec := &Record{
			Token:     tok,
			Login:     id.Login,
			Host:      Host,
			CreatedAt: now,
			ExpiresAt: id.ExpiresAt,
		}
		if rec.ExpiresAt.IsZero() {
			// Header was present but unparseable (checkGrant let it through); fall
			// back to the requested lifetime rather than storing a zero expiry.
			rec.ExpiresAt = now.Add(ExpiresInDays * 24 * time.Hour)
		}
		return rec, nil
	}
	return nil, lastErr
}

func (m *Manager) load() (*Record, error) {
	data, ok, err := m.Store.Get(storeKey)
	if err != nil || !ok {
		return nil, err
	}
	var rec Record
	if err := json.Unmarshal(data, &rec); err != nil {
		// Corrupt/unreadable record: treat as absent so we re-provision.
		return nil, nil
	}
	if rec.Host == "" {
		rec.Host = Host
	}
	return &rec, nil
}

func (m *Manager) save(rec *Record) error {
	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return m.Store.Set(storeKey, data)
}
