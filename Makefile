# Copyright 2026 Bitwise Media Group Ltd.
# SPDX-License-Identifier: MIT

# Developer tasks. `make help` lists targets; `make pr` is the full local gate, and
# `make ci` is exactly what the reusable CI workflow runs (lint, test, build).
#
# The Go developer CLIs (addlicense, golangci-lint, govulncheck, gotestsum,
# gocover-cobertura, goreleaser, syft) are pinned in tools/go.mod — a separate
# module so their dependency graphs never touch the application's go.mod — and
# invoked with `go tool -modfile=tools/go.mod <name>`: compiled into the build cache
# on first use, no GOBIN, no binaries to manage. -modfile anchors on the root go.mod
# and runs the tool in the current directory, so relative paths just work.

# one -ignore flag per non-empty line in .licenseignore (quoted to avoid shell globbing)
LICENSE_HOLDER := 'Bitwise Media Group Ltd.'
LICENSE_IGNORE := $(foreach pattern,$(shell cat .licenseignore 2>/dev/null),-ignore '$(pattern)')

APP     := gh-claude
APP_PKG := .
TOOL    := go tool -modfile=tools/go.mod
# Injected into main.version so `gh claude version` and the integrity check know
# the build. A local build reports a git describe (not a bare semver), which the
# integrity check treats as an un-gated dev build; releases inject the real tag
# via GoReleaser (see .goreleaser.yaml).
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

# Security-policy authoring (see docs/security-policy.md). The `policy` target
# drives internal/tools/policy, which builds the next revision, signs it with an
# OpenSSH signature (`ssh-keygen -Y sign`, so POLICY_KEY can be a FIDO2
# sk-ssh-ed25519 YubiKey handle), and verifies the result against the embedded
# policy keys before moving it into place.
POLICY     ?= docs/policy.json
POLICY_KEY ?= ${HOME}/.ssh/id_sk_current

.DEFAULT_GOAL := help

.PHONY: help
help: ## List available targets
	@ grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

.PHONY: pr
pr: tidy license fmt lint test build docs ## full local gate before opening a pull request

.PHONY: ci
ci: lint test build ## the gates the reusable CI workflow runs

.PHONY: tidy
tidy: ## tidy the app and tools module graphs
	@ rm -f go.sum; go mod tidy
	@ go -C tools mod tidy

# Install the pinned Node tools (prettier, markdownlint-cli2) exactly as locked
# in package-lock.json, and run them straight from node_modules via `npm run` —
# never a global or npx copy. Re-runs only when package.json / the lockfile change.
node_modules: package.json package-lock.json
	@ npm ci --ignore-scripts --no-fund
	@ touch node_modules

.PHONY: fmt
fmt: node_modules ## format the code and prose, and inject license headers
	@ go fmt ./...
	@ $(TOOL) golangci-lint run --fix
	@ $(TOOL) addlicense -l mit -c $(LICENSE_HOLDER) -s=only $(LICENSE_IGNORE) .
	@ npm run lint:fix
	@ npm run format

.PHONY: license
license: ## inject SPDX license headers (addlicense)
	@ $(TOOL) addlicense -l mit -c $(LICENSE_HOLDER) -s=only $(LICENSE_IGNORE) .

.PHONY: lint
lint: node_modules ## run all check-mode static analysis (addlicense, golangci-lint, govulncheck, markdownlint, prettier)
	@ $(TOOL) addlicense -l mit -c $(LICENSE_HOLDER) -s=only $(LICENSE_IGNORE) -check .
	@ $(TOOL) golangci-lint run
	@ $(TOOL) govulncheck ./...
	@ npm run lint
	@ npm run format:check

# -covermode=atomic is the race-safe counter mode `-race` requires. gotestsum runs
# the suite and writes a JUnit report in one pass (propagating the test exit code,
# which a bare `go test | …` pipe would swallow); gocover-cobertura turns the profile
# into Cobertura XML. Coverage (cobertura-coverage.xml) and test results (junit.xml)
# land in coverage/ where the reusable CI workflow uploads them to Codecov.
.PHONY: test
test: ## run the unit tests with coverage (coverage/ → Codecov in CI)
	@ mkdir -p coverage
	@ $(TOOL) gotestsum --junitfile coverage/junit.xml -- \
		-race -covermode=atomic -coverprofile=coverage/coverage.out ./...
	@ $(TOOL) gocover-cobertura <coverage/coverage.out >coverage/cobertura-coverage.xml

.PHONY: build
build: ## build the extension binary (./gh-claude)
	@ CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o $(APP) $(APP_PKG)

.PHONY: install
install: build ## install the local build as a gh extension for end-to-end testing
	@ gh extension remove claude >/dev/null 2>&1 || true
	@ gh extension install .

# The extension is distributed only through `gh extension install` (no Homebrew
# cask), so no man pages are generated here — the hidden docs command keeps the
# format available (`./gh-claude docs --format man`) for ad-hoc use.
.PHONY: docs
docs: build ## regenerate the CLI reference (docs/cli) and build the docs site
	@ ./$(APP) docs --out docs/cli --format markdown
	@ uv run zensical build

# Docs site (Zensical). Kept out of `ci` so that gate needs no Python; run
# these directly. `uv` provisions Python + zensical from pyproject.toml on first
# use. The built site/ is git-ignored.
.PHONY: serve
serve: ## serve the docs site locally (zensical)
	@ uv run zensical serve

# --skip=sign: cosign keyless signing needs the GitHub Actions OIDC token, so it
# only works in the release workflow — locally it would fail or prompt.
.PHONY: snapshot
snapshot: ## build a local release snapshot (binaries + SBOMs, no publish or signing)
	@ $(TOOL) goreleaser release --snapshot --clean --skip=sign

.PHONY: release
release: ## build and publish a release (needs a vX.Y.Z tag + creds)
	@ $(TOOL) goreleaser release --clean

# One-stop policy authoring: renew/update $(POLICY), sign it (touch the YubiKey
# when it blinks), and verify the signature against the embedded policy keys.
# Pass tool flags via ARGS, e.g. ARGS='--revoke 0.1.2 --min-version 0.1.3'; run
# `go run ./internal/tools/policy --help` for the full list, and invoke the tool
# directly (without --policy) to create the very first policy.
.PHONY: policy
policy: ## renew or update and sign $(POLICY) (ARGS=... for revocations etc.)
	@ go run ./internal/tools/policy --policy $(POLICY) --key $(POLICY_KEY) $(ARGS)
