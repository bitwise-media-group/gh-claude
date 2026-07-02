# Changelog

## [0.2.2](https://github.com/bitwise-media-group/gh-claude/compare/v0.2.1...v0.2.2) (2026-07-02)


### Features

* **verify:** assert the reusable-workflow signer and show live progress ([871f0e7](https://github.com/bitwise-media-group/gh-claude/commit/871f0e781e5a72683c06aef9bd622a417f9d8fdd))

## [0.2.1](https://github.com/bitwise-media-group/gh-claude/compare/v0.2.0...v0.2.1) (2026-07-02)


### Bug Fixes

* **verify:** verify re-signed installs via release-asset equivalence ([3020f08](https://github.com/bitwise-media-group/gh-claude/commit/3020f08627f8093d854d0dab0acda082291cf7d7))

## [0.2.0](https://github.com/bitwise-media-group/gh-claude/compare/v0.1.1...v0.2.0) (2026-07-02)


### ⚠ BREAKING CHANGES

* **store:** the encrypted file-backend on-disk format changed. Tokens stored by earlier versions cannot be decrypted and are treated as absent, so users on the file backend (all Linux hosts, and macOS/Windows release builds that fell back to it) must re-run `gh claude login` once after upgrading. Tokens expire after 7 days regardless, so this is a one-time re-auth.

### Features

* add a hidden docs command that generates the CLI reference ([b5d1566](https://github.com/bitwise-media-group/gh-claude/commit/b5d1566976db8b1e73c3e240a186473bd907ca00))
* add a policy authoring and signing tool ([8f7c6e9](https://github.com/bitwise-media-group/gh-claude/commit/8f7c6e9b4dc204494f222aa5051981db5d2923df))
* **integrity:** embed the production policy key and export authoring seams ([24d7844](https://github.com/bitwise-media-group/gh-claude/commit/24d7844ba572c873e364c367670a005b3f1483d6))
* **integrity:** verify build provenance and add a revocable security-policy kill switch ([08a33ef](https://github.com/bitwise-media-group/gh-claude/commit/08a33ef2709dc6767f6f8581645542a97d14ff6a))
* **store:** replace 99designs/keyring with standard-library backends ([405375c](https://github.com/bitwise-media-group/gh-claude/commit/405375c571699bc60b0d09b7e0caac68340ba776))
* **token:** reject pasted PAT unless type and expiry match the form ([d05e206](https://github.com/bitwise-media-group/gh-claude/commit/d05e2061a832d632cbf1df171655fe819d5818fd))


### Bug Fixes

* **store:** check cleanup errors in the atomic file write ([71fdf1e](https://github.com/bitwise-media-group/gh-claude/commit/71fdf1eaadcb9e122dae91c1ea81ff45818a2a39))
* **token:** date-stamp the pre-filled token name to avoid renewal collisions ([f4125c0](https://github.com/bitwise-media-group/gh-claude/commit/f4125c065dc89c300842b6ba6cea7f14f6cfe2c4))

## [0.1.1](https://github.com/bitwise-media-group/gh-claude/compare/v0.1.0...v0.1.1) (2026-07-01)


### Features

* launch Claude Code with a temporary, no-push GitHub token ([20663d0](https://github.com/bitwise-media-group/gh-claude/commit/20663d03d08b8b175e14462e8b5ca3780a956dff))
* **store:** add optional 1Password backend via the op CLI ([53a48a0](https://github.com/bitwise-media-group/gh-claude/commit/53a48a00f8f2dcf86e71a2e75fd7f60dc3361d0c))
