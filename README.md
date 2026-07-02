# gh-claude

A [GitHub CLI](https://cli.github.com) extension that launches
[Claude Code](https://claude.com/claude-code) with a **temporary,
least-privilege GitHub token** so Claude can work with your **private
repositories** without ever seeing your real credential.

The token is:

- **read-only on source code** (no `git push`),
- **read/write on issues and pull requests**,
- **scoped to all repositories you can access**,
- **expiring after 7 days**, and
- **stored in your OS keychain** — the macOS Keychain or Windows Credential
  Manager — falling back to an encrypted file where there is no OS keychain
  (Linux, WSL2), with
  [1Password as an optional alternative](#using-1password-optional).

Claude only ever receives the scoped token through the `GITHUB_TOKEN`
environment variable — it never touches your keychain or your real `gh`
credential.

## Why a manual browser step?

GitHub has **no API to mint a fine-grained personal access token** — they can
only be created in the browser. (The fully-automated alternative, a GitHub App,
would require shipping an app private key to every developer machine, which we
explicitly avoid.) So `gh-claude` automates everything _except_ the creation
click: it opens the token page **pre-filled** with the right name, 7-day expiry,
and permissions; you choose "All repositories" and click **Generate**; and from
then on the extension stores, reuses, validates, and wires up the token for you.
You only repeat the browser step about once a week, when the token expires.

## Install

```sh
gh extension install bitwise-media-group/gh-claude
```

Requires the `gh` CLI (authenticated), `git`, and the `claude` CLI on your
`PATH`.

## Usage

```sh
# Ensure a valid token (reuse or create), then launch Claude in the current dir:
gh claude

# Pass arguments through to claude after `--`:
gh claude -- --resume

# Force-create a fresh token without launching Claude:
gh claude login

# Show the stored token's account, expiry, and where it is stored:
gh claude status

# Remove the stored token:
gh claude logout

# Force a new token, then launch:
gh claude --refresh

# Store the token in 1Password instead of the OS keychain (see "Using 1Password"):
gh claude --op
```

On first run (or after expiry) your browser opens to the GitHub token page. In
it:

1. Under **Repository access** choose **All repositories**.
2. Leave the pre-filled permissions: **Contents: Read**, **Issues: Read and
   write**, **Pull requests: Read and write**.
3. Click **Generate token** and copy the value (starts with `github_pat_`).
4. Paste it back into the terminal (input is hidden).

The extension validates the token, records its exact expiry (from GitHub's
`GitHub-Authentication-Token-Expiration` response header), stores it, and
launches Claude. Subsequent runs reuse the stored token until it is within 5
minutes of expiry or has been revoked.

## How gh and git are wired

When launching Claude, `gh-claude` adds to the child process environment only
(your global git config and `gh` keychain entry are never modified):

- `GH_TOKEN` and `GITHUB_TOKEN` — set to the scoped token. `gh` prefers these
  over its keychain, so Claude's `gh` uses the scoped token and never reads the
  keychain.
- A per-process git credential helper, injected via git's `GIT_CONFIG_*`
  environment mechanism, pointing at `gh auth git-credential`. `git` then defers
  to `gh`, which returns the scoped token — so `git clone`/`fetch` over HTTPS
  work for private repos, while `git push` is rejected (the token is read-only
  on contents).

## Security model

- **Claude never sees your keychain or real credential.** It receives only the
  scoped, read-only-code token via an environment variable.
- **No push.** The token's `contents: read` scope means code cannot be pushed,
  bounding the blast radius if the token leaks.
- **Short-lived.** Tokens expire after 7 days; reuse stops 5 minutes before
  expiry.
- **Env-var exposure.** As with any `GITHUB_TOKEN`, the value is readable by
  your own processes (e.g. `/proc/<pid>/environ` on Linux). This is inherent to
  the env-var delivery model; the read-only scope is what limits the risk.
- **Native keychains.** On macOS the token is stored in the login Keychain (via
  the built-in `security` tool); on Windows, in the Credential Manager (via
  `advapi32`). These backends use only the Go standard library — there is no
  third-party keyring dependency and no cgo, so they work in the release
  binaries too.
- **Linux / WSL2 / no-keychain fallback.** On Linux (including WSL2) and any
  host without a native keychain, the token is stored in an encrypted file (mode
  `0600`) under your config directory — this is the standard Linux backend, not
  an error condition. The file is AES-256-GCM encrypted with a key derived
  (HKDF-SHA256) from a stable machine identifier (`/etc/machine-id`, or a
  generated per-install key where none exists); this is defense-in-depth,
  **not** a hardware-backed secret — the machine id is not itself secret, so the
  file's permissions are the primary protection. Run `gh claude status` to see
  which backend is in use.

## Using 1Password (optional)

If you prefer to keep the token in [1Password](https://1password.com) instead of
the OS keychain — handy for a consistent store across machines, and a real
secure store on **WSL** (where there is otherwise no keychain) — `gh-claude` can
store the token there via the
[1Password CLI](https://developer.1password.com/docs/cli/) (`op`). This is
**opt-in** and does **not** replace the OS keychain; the keychain/encrypted-file
backends remain the default when you don't enable it.

**Prerequisites:**

1. Install the [`op` CLI](https://developer.1password.com/docs/cli/get-started/)
   and the 1Password desktop app, and sign in.
2. Enable the desktop app integration: 1Password → **Settings → Developer** →
   **Integrate with 1Password CLI** (turn on _"Connect with 1Password CLI"_). On
   **WSL**, follow 1Password's
   [WSL setup](https://developer.1password.com/docs/cli/about-biometric-unlock/#turn-on-biometric-unlock-in-the-cli)
   so `op` in your distro talks to the Windows desktop app.

**Enable it** with the `--op` flag (available on every command):

```sh
gh claude --op                          # use 1Password for this launch
gh claude --op --vault "Engineering"    # choose a vault (default "Private")
gh claude login --op                    # works on subcommands too
gh claude status --op                   # Storage:  1password (vault: Private)
```

Or set it once for the shell session with environment variables:

```sh
export GH_CLAUDE_STORE=1password      # opt in (also accepts "op")
export GH_CLAUDE_OP_VAULT="Private"   # vault to use (name or ID; default "Private")
export GH_CLAUDE_OP_ACCOUNT="my-team" # optional: account for multi-account setups
```

Flags take precedence over the environment variables, and the token is stored as
an item named `gh-claude:github.com`.

The token is kept in a single concealed field of an _API Credential_ item, and
is only ever passed to `op` over stdin (never on the command line). Accessing it
prompts for 1Password's approval (biometric/system unlock, valid for a short
inactivity window). When `GH_CLAUDE_STORE` is set but `op` is missing or not
signed in, `gh-claude` fails with a clear error rather than silently falling
back.

## Development

The `Makefile` is the entry point (`make help` lists every target). The Go
developer CLIs (golangci-lint, govulncheck, gotestsum, gocover-cobertura,
addlicense, goreleaser, syft) are pinned in `tools/go.mod` and run via `go tool`
— no separate installs.

```sh
make pr        # full local gate: tidy, license headers, fmt, lint, test, build
make ci        # exactly what CI runs: lint, test, build
make lint      # addlicense + golangci-lint + govulncheck (check mode)
make test      # unit tests with coverage → coverage/
make build     # build ./gh-claude
make install   # build and install as a gh extension for end-to-end testing
make snapshot  # local release snapshot (binaries + SBOMs, no publish/signing)
```

## Continuous integration & automation

This repo uses the org's reusable workflows (thin callers in
`.github/workflows/`):

- **`ci.yaml`** — runs `make lint/build/test` on every push and PR and uploads
  coverage.
- **`security.yaml`** — CodeQL analysis of the Go module and the Actions
  workflows.
- **`merge.yaml`** + **`merge-review-ack.yaml`** — fast-forward `/merge` and
  `/auto-merge` flows that preserve commit signatures.
- **`dependabot-merge.yaml`** — auto-approves and fast-forwards Dependabot
  minor/patch PRs once CI is green (config in `.github/dependabot.yaml`).
- **`merge-notice.yaml`** — posts a one-time `/merge` explainer on new PRs.

The merge automation requires the org's "FF Merge" GitHub App (the
`FF_MERGE_CLIENT_ID` variable + `FF_MERGE_PRIVATE_KEY` secret) and branch
protection that requires PR review.

## Releases

Releases are driven by
[release-please](https://github.com/googleapis/release-please) through the org's
reusable release workflow (`.github/workflows/release.yaml`): Conventional
Commit history keeps a release PR up to date, and merging it cuts the `vX.Y.Z`
tag and a draft GitHub release. [GoReleaser](https://goreleaser.com)
(`.goreleaser.yaml`) then adopts that draft and uploads the per-platform
binaries named `gh-claude-<os>-<arch>[.exe]` — the exact asset names
`gh extension install` and `gh extension upgrade` match on — alongside
`checksums.txt`, keyless [cosign](https://github.com/sigstore/cosign)
signatures, SPDX SBOMs ([syft](https://github.com/anchore/syft)), and a SLSA
build-provenance attestation over the checksums. Verify the provenance with:

```sh
gh attestation verify --owner bitwise-media-group gh-claude-<os>-<arch>
```
