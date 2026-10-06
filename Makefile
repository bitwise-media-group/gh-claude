# Copyright 2026 Bitwise Media Group Ltd.
# SPDX-License-Identifier: MIT

# gh-claude — a `gh` CLI extension. Everything lives in mise tasks: the go
# archetype (build/lint/test/release machinery) and the common tasks (license,
# prose, workflow, container, and shell lint) come from the shared toolchain
# submodule at .mise/, selected in the root mise.toml; tasks.toml carries the
# repo-local tasks (docs, install, policy), the main.version build stamping,
# and the pr gate that regenerates the docs. This Makefile is only the thin
# forwarding shim — `make <task>` == `mise run <task>`.
include .mise/archetypes/go/include.mk
