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

.DEFAULT_GOAL := help

.PHONY: help
help: ## List available targets
	@ grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

.PHONY: pr
pr: tidy license fmt lint test build ## full local gate before opening a pull request

.PHONY: ci
ci: lint test build ## the gates the reusable CI workflow runs

.PHONY: tidy
tidy: ## tidy the app and tools module graphs
	@ rm -f go.sum; go mod tidy
	@ go -C tools mod tidy

.PHONY: fmt
fmt: ## format the code and inject license headers
	@ go fmt ./...
	@ $(TOOL) golangci-lint run --fix
	@ $(TOOL) addlicense -l mit -c $(LICENSE_HOLDER) -s=only $(LICENSE_IGNORE) .

.PHONY: license
license: ## inject SPDX license headers (addlicense)
	@ $(TOOL) addlicense -l mit -c $(LICENSE_HOLDER) -s=only $(LICENSE_IGNORE) .

.PHONY: lint
lint: ## run all check-mode static analysis (addlicense, golangci-lint, govulncheck)
	@ $(TOOL) addlicense -l mit -c $(LICENSE_HOLDER) -s=only $(LICENSE_IGNORE) -check .
	@ $(TOOL) golangci-lint run
	@ $(TOOL) govulncheck ./...

.PHONY: link
link: build ## install the local copy of gh-claude as an extension
	@ gh extensions remove claude 1>/dev/null 2>&1 || true
	@ gh extensions install .

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
	@ CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o $(APP) $(APP_PKG)

.PHONY: install
install: build ## install the local build as a gh extension for end-to-end testing
	@ gh extension install . 2>/dev/null || gh extension upgrade gh-claude

# --skip=sign: cosign keyless signing needs the GitHub Actions OIDC token, so it
# only works in the release workflow — locally it would fail or prompt.
.PHONY: snapshot
snapshot: ## build a local release snapshot (binaries + SBOMs, no publish or signing)
	@ $(TOOL) goreleaser release --snapshot --clean --skip=sign

.PHONY: release
release: ## build and publish a release (needs a vX.Y.Z tag + creds)
	@ $(TOOL) goreleaser release --clean
