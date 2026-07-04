# Copyright 2026 Bitwise Media Group Ltd.
# SPDX-License-Identifier: MIT

# gh-claude — a `gh` CLI extension. The common Go build/lint/test/release
# machinery lives in the shared Makefile library (bitwise-media-group/make),
# consumed as the make/ submodule and included below. Only gh-claude's
# repo-specific knobs and long-tail targets (docs, install, policy) live here;
# the canonical lint/build/test/ci/pr contract comes from go-cli.mk.
APP     := gh-claude
APP_PKG := .

# gh-claude stamps its version into main.version (there is no internal/version
# package), so override the archetype's default LDFLAGS which target
# $(MODULE)/internal/version. `gh claude version` and the integrity check read
# this; releases inject the real tag via GoReleaser (see .goreleaser.yaml).
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

# Gate extension: gh-claude regenerates its CLI reference and builds the docs
# site as part of `pr`. Declared before the include so these prerequisites are
# made first, in this order — make runs each at most once, so the archetype's
# repeats are skipped and `commit` still lands last.
pr: tidy fmt lint test build docs commit

include make/go-cli.mk

# ---- repo-local targets (the long tail the library intentionally omits) ------

# Security-policy authoring (see docs/security-policy.md). The `policy` target
# drives internal/tools/policy, which builds the next revision, signs it with an
# OpenSSH signature (`ssh-keygen -Y sign`, so POLICY_KEY can be a FIDO2
# sk-ssh-ed25519 YubiKey handle), and verifies the result against the embedded
# policy keys before moving it into place.
POLICY     ?= docs/policy.json
POLICY_KEY ?= ${HOME}/.ssh/id_sk_gh-claude-policy

.PHONY: docs install policy

# Regenerate the CLI reference from the cobra command tree, then render the site.
# (Kept repo-local: generating a CLI reference is app-specific. `serve`, `sync`,
# and the zensical plumbing come from the library's docs.mk.) The extension is
# distributed only through `gh extension install` (no Homebrew cask), so no man
# pages are generated — the hidden `docs --format man` command keeps that format
# available for ad-hoc use.
docs: build ## regenerate the CLI reference (docs/cli) and build the docs site
	@ ./$(APP) docs --out docs/cli --format markdown
	@ uv run zensical build

install: build ## install the local build as a gh extension for end-to-end testing
	@ gh extension remove claude >/dev/null 2>&1 || true
	@ gh extension install .

# One-stop policy authoring: renew/update $(POLICY), sign it (touch the YubiKey
# when it blinks), and verify the signature against the embedded policy keys.
# Pass tool flags via ARGS, e.g. ARGS='--revoke 0.1.2 --min-version 0.1.3'; run
# `go run ./internal/tools/policy --help` for the full list, and invoke the tool
# directly (without --policy) to create the very first policy.
policy: ## renew or update and sign $(POLICY) (ARGS=... for revocations etc.)
	@ go run ./internal/tools/policy --policy $(POLICY) --key $(POLICY_KEY) $(ARGS)
