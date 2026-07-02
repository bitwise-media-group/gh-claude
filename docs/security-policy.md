# Integrity: provenance verification & the security-policy kill switch

`gh-claude` ships two independent integrity mechanisms, implemented in
[`internal/integrity`](../internal/integrity) and wired in
[`cmd/integrity.go`](../cmd/integrity.go). They use **different trust roots and
cadences on purpose**.

|                     | Build provenance                      | Security policy                                               |
| ------------------- | ------------------------------------- | ------------------------------------------------------------- |
| Question it answers | "Did our CI build this exact binary?" | "Is this version known-bad right now?"                        |
| Trust root          | GitHub Sigstore attestation store     | Embedded OpenSSH policy keys — Ed25519, primary + backup      |
| When it runs        | On demand (`gh claude verify`)        | On launch (`gh claude`, `gh claude login`), throttled         |
| Needs network       | Yes                                   | Only to refresh a stale cache                                 |
| Failure mode        | Reports the error                     | **Fail-open** (warn) unless a trusted policy says **blocked** |

Why two roots? A Sigstore-keyless signature **cannot be revoked** (short-lived
Fulcio certs, permanent Rekor inclusion proofs). Revocation therefore has to be
_additive_: a separately-signed policy that **names** bad versions and that the
client consults. Keeping the policy key independent of the release-signing
identity means a revocation can ship **without cutting a new binary release**,
and the policy stays trustworthy even if the release path is compromised.

## 1. Build provenance — `gh claude verify`

Verifies the running binary against GitHub's attestation store using
`gh attestation verify` (the `gh` CLI is always present — this is a gh
extension — and carries Sigstore's trusted root):

```console
$ gh claude verify                 # asserts: built by our CI from this repo
$ gh claude verify --signer-workflow \
    bitwise-media-group/github-workflows/.github/workflows/release.yaml
$ gh claude verify --json          # machine-readable gh output
```

No setup needed — the release workflow already emits the SLSA build-provenance
attestation.

## 2. Security policy — the revocable kill switch

On launch the client fetches a small signed JSON policy (throttled: at most once
per 6h, cached under the gh-claude config dir), verifies its OpenSSH signature
against the embedded public keys, and refuses to launch a revoked or below-floor
version. A policy is trusted only if its signature was made under the
`gh-claude-policy` namespace by **either** the primary or the backup key.

### Policy document

Served at `policyURL` (`https://oss.bitwisemedia.uk/gh-claude/policy.json`),
with a detached OpenSSH signature (the `ssh-keygen -Y sign` "sshsig" format, an
`-----BEGIN SSH SIGNATURE-----` blob) at `policyURL + ".sig"`:

```json
{
  "schema": 1,
  "sequence": 7,
  "issued_at": "2026-07-01T00:00:00Z",
  "expires_at": "2026-07-15T00:00:00Z",
  "min_safe_version": "1.4.0",
  "revoked": [
    {
      "version": "1.3.0",
      "reason": "CVE-2026-1234: scoped token written to a world-readable log",
      "advisory": "https://github.com/bitwise-media-group/gh-claude/security/advisories/GHSA-xxxx-xxxx-xxxx"
    },
    { "digest": "sha256:2f0c…", "reason": "tampered artifact seen in the wild" }
  ]
}
```

- `sequence` — **monotonic**. A fetched policy with a lower sequence than the
  cached one is rejected as a rollback (an attacker replaying a pre-revocation
  policy).
- `expires_at` — **freshness bound**. Past it, an "all clear" is no longer
  trusted until a newer policy is fetched (defeats a freeze attack). It does
  **not** discard a _block_: a known-bad verdict stands even when stale/offline.
- `min_safe_version` — everything below it is blocked (semver, `v` optional).
- `revoked[]` — exact `version` and/or artifact `digest`, with `reason` /
  `advisory` shown to the user.

### Behaviour matrix

| Situation                                            | Verdict     | Launch                                                 |
| ---------------------------------------------------- | ----------- | ------------------------------------------------------ |
| Trusted policy, version fine                         | clear       | proceeds silently                                      |
| Trusted policy revokes version/digest or below floor | **blocked** | **refused** (fail-closed) with advisory + upgrade hint |
| No policy reachable, none cached                     | unknown     | proceeds with a stderr warning (fail-open)             |
| Cached "all clear" expired, refresh failed           | unknown     | proceeds with a staleness warning                      |
| Cached policy blocks, network down                   | **blocked** | **refused** — offline never un-revokes                 |

### Activation (one-time)

The channel is **inert until wired** — with no key and no URL the check is a
silent no-op, so unconfigured builds behave exactly as before.

Policies are signed with an **OpenSSH signature** (`ssh-keygen -Y sign`), so the
signing key can be a **FIDO2 resident `sk-ssh-ed25519` key on a YubiKey** — the
same hardware-backed flow used for commit signing. That is what lets a YubiKey
FIPS device (firmware 5.4.x — no PIV Ed25519, and no ECDSA keys on hand) sign the
policy: its FIDO2 Ed25519 signature carries an authenticator flags+counter
envelope that the SSH signature format represents and the client verifies (via
`golang.org/x/crypto/ssh`). A plain software `ssh-ed25519` key works too. Provision
**two** keys — a primary and a break-glass backup — held apart.

#### 1. Create a key on each YubiKey

A FIDO2 resident Ed25519 key, touch required per signature:

```console
$ ssh-keygen -t ed25519-sk -O resident -O application=ssh:gh-claude-policy \
    -C policy@bitwise -f id_ed25519_sk_policy
$ cat id_ed25519_sk_policy.pub      # -> the authorized_keys line to embed
```

(`-O resident` stores it on the key so it can be re-derived on another host with
`ssh-keygen -K`. For a software key instead, drop `-sk` and the `-O` flags.)

#### 2. Embed the public keys

Paste the primary `.pub` line into `policyPublicKeySSH` and the backup's into
`policyBackupPublicKeySSH` in
[`internal/integrity/signature.go`](../internal/integrity/signature.go), and
confirm `policyURL` in
[`internal/integrity/check.go`](../internal/integrity/check.go). Public keys only
— nothing secret ships in the binary. The signing namespace `gh-claude-policy` is
fixed in `signature.go` (`PolicyNamespace`); the authoring tool signs under it
automatically.

#### 3. Author and sign a policy

The [`policy` tool](../internal/tools/policy/main.go) creates or updates
`docs/policy.json` and signs it in one step. It enforces the channel's rules at
authoring time (every revision's sequence strictly exceeds its predecessor's —
bumped automatically unless `--sequence` says otherwise — `min_safe_version`
never drops, revocations only accumulate) and — after `ssh-keygen` signs with
the inserted YubiKey — verifies the signature against the **embedded** policy
keys before overwriting anything, so a wrongly-keyed signature can't be
published.

```console
$ make policy                                              # renew: bump sequence, fresh dates
$ make policy ARGS='--revoke 0.1.2 --min-version 0.1.3'    # revoke + raise the floor
$ go run ./internal/tools/policy --expires-days 14 --sequence 1 --min-version 0.1.0   # first policy
```

`--revoke` takes a comma-separated list and may be repeated. To sign and check
an existing `policy.json` by hand instead (`policy.allowed_signers` holds one
`principal <public-key>` line per policy key — the same public keys you
embedded):

```console
$ ssh-keygen -Y sign   -n gh-claude-policy -f id_ed25519_sk_policy policy.json
$ ssh-keygen -Y verify -n gh-claude-policy -f policy.allowed_signers \
    -I policy@bitwise -s policy.json.sig <policy.json
```

To sign with the **backup** key, insert the backup YubiKey instead; the client
trusts either signature, so no code change is needed to fail over.

#### 4. Publish

Commit `docs/policy.json` and `docs/policy.json.sig`; the docs site publishes
them at `policyURL` (`https://oss.bitwisemedia.uk/gh-claude/policy.json`) and
its `.sig` sibling. Optionally attest `policy.json` via CI too, for defence in
depth.

### Disclosure runbook

When a vulnerability is found in a released version:

1. Ship the fix, cut the patched release.
2. With the primary YubiKey inserted — or the backup if the primary is
   unavailable — author and sign the revision in one step (§3 above):
   `make policy ARGS='--revoke <bad-version> --min-version <fixed-version>'`
   (add a `reason`/`advisory` to the new `revoked` entry by hand if wanted, then
   re-sign).
3. Publish. Clients pick it up within the refresh window and refuse the
   vulnerable version, pointing users at `gh extension upgrade claude`.

**Rotating a policy key** = ship a build that moves the surviving key into
`policyPublicKeySSH` and a freshly generated key into `policyBackupPublicKeySSH`.
Because a policy is trusted if it matches _either_ embedded key, a lost or
compromised primary never locks you out: keep signing with the backup while the
replacement build rolls out.

## Environment toggles

| Variable                   | Effect                                                                                |
| -------------------------- | ------------------------------------------------------------------------------------- |
| `GH_CLAUDE_SKIP_INTEGRITY` | Any non-empty value disables the launch-time policy check (air-gapped / offline use). |
| `GH_CLAUDE_POLICY_URL`     | Override the policy endpoint (self-hosting / testing).                                |

Local `go build` / snapshot binaries report a non-release version and are never
gated.
