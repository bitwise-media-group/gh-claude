## claude verify

Verify this binary's build provenance via GitHub attestations

### Synopsis

Verify that the running gh-claude binary was built by
bitwise-media-group's release workflow and recorded in GitHub's attestation
store, using "gh attestation verify". Needs network access to GitHub.

By default it asserts that the binary was built from this repository by the
org's reusable release workflow (every release is built through it, and the
attestation's signer identity names that workflow, so a bare repository check
could never pass). Use --signer-workflow to assert a different building
workflow, or --cert-identity for a signer-identity regexp.

On Apple Silicon macOS, gh ad-hoc re-signs extension binaries when it installs
them, so the installed binary's digest matches no attestation. When direct
verification fails there, this command instead downloads this version's release
asset, verifies the asset's provenance, applies gh's install-time re-signature
to the copy, and checks that the result is byte-identical to the running
binary.

```
claude verify [flags]
```

### Options

```
      --cert-identity string     require a signer identity matching this regexp (alternative to --signer-workflow)
  -h, --help                     help for verify
      --json                     print gh's JSON verification result
      --signer-workflow string   require this exact building workflow (owner/repo/.github/workflows/file.yaml)
                                 (default: the org's reusable release workflow)
```

### Options inherited from parent commands

```
      --op             store the token in 1Password via the op CLI (instead of the OS keychain)
      --vault string   1Password vault for --op (default "Private"; overrides GH_CLAUDE_OP_VAULT)
```

### SEE ALSO

* [claude](claude.md)	 - Launch Claude Code with a temporary, no-push GitHub token

