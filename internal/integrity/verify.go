// Copyright 2026 Bitwise Media Group Ltd.
// SPDX-License-Identifier: MIT

package integrity

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	gh "github.com/cli/go-gh/v2"
)

// AttestRepo is the source repository a genuine gh-claude binary's build
// provenance must name — the assertion `gh claude verify` makes against
// GitHub's Sigstore attestation store.
const AttestRepo = "bitwise-media-group/gh-claude"

// DefaultSignerWorkflow is the org's reusable release workflow, which every
// release is intentionally built through. It must be asserted explicitly:
// the Fulcio certificate's signer identity (its SAN) names the reusable
// workflow's repository, not AttestRepo, so a bare `gh attestation verify
// --repo` — which requires a signer inside the artifact's own repository —
// can never pass. Passing --signer-workflow keeps the source-repository
// check on AttestRepo while pinning the signer to this workflow, which is
// both the claim that verifies and a stronger one.
const DefaultSignerWorkflow = "bitwise-media-group/github-workflows/.github/workflows/release.yaml"

// InstalledName is the filename gh gives every installed extension binary
// (~/.local/share/gh/extensions/gh-claude/gh-claude). The darwin/arm64
// fallback must sign its release-asset copy under this exact name: codesign
// derives the ad-hoc identifier from the filename, so any other name produces
// different bytes and the byte-comparison could never match.
const InstalledName = "gh-claude"

// VerifyOptions tunes the provenance assertion. The zero value asserts the
// default claim: built from AttestRepo by DefaultSignerWorkflow. Set
// SignerWorkflow or CertIdentity to assert a different signer.
type VerifyOptions struct {
	SignerWorkflow string    // overrides DefaultSignerWorkflow
	CertIdentity   string    // regexp alternative to SignerWorkflow
	JSON           bool      // request --format json instead of the human summary
	Tag            string    // release tag backing the darwin/arm64 re-signed-binary fallback ("" disables it)
	Progress       io.Writer // live step checklist, typically os.Stderr (nil silences it)
}

// execGH runs the gh CLI and returns combined stdout/stderr. It is a package
// variable so tests can stub the subprocess. gh is always on PATH here — this is
// a gh extension — and it ships Sigstore's trusted root, so verification needs no
// extra dependency and can run offline against a bundled root.
var execGH = func(args ...string) (stdout, stderr string, err error) {
	so, se, err := gh.Exec(args...)
	return so.String(), se.String(), err
}

// resignedOnInstall reports whether gh's extension installer rewrites binaries
// on this platform: on Apple Silicon macOS, `gh extension install` ad-hoc
// re-signs every downloaded arm64 binary (codesignBinary in cli/cli's
// pkg/cmd/extension/manager.go), changing its digest so it no longer matches
// any attested release asset. Package variable so tests can exercise the
// fallback on any platform.
var resignedOnInstall = func() bool {
	return runtime.GOOS == "darwin" && runtime.GOARCH == "arm64"
}

// execCodesign re-signs the binary at path with the exact codesign invocation
// gh's extension installer applies after downloading a darwin/arm64 extension.
// Ad-hoc signing is deterministic, so running it on the pristine release asset
// reproduces the installed binary byte for byte. Package variable so tests can
// stub the transform — codesign only exists on macOS.
var execCodesign = func(path string) error {
	codesign, err := exec.LookPath("codesign")
	if err != nil {
		return fmt.Errorf("codesign not found: %w", err)
	}
	out, err := exec.Command(codesign, "--sign", "-", "--force",
		"--preserve-metadata=entitlements,requirements,flags,runtime", path).CombinedOutput()
	if err != nil {
		return fmt.Errorf("codesign %s: %w\n%s", path, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// VerifyBinary asserts, via `gh attestation verify`, that the artifact at path
// was built by the expected repository's workflow and recorded in GitHub's
// attestation store. It returns gh's report (stdout, or stderr when gh writes the
// summary there) on success, and a wrapped error including gh's output on
// failure — a verification failure is a security signal the caller should show
// verbatim.
//
// On Apple Silicon macOS the direct check cannot succeed for an installed
// extension: gh re-signs the binary at install time (see resignedOnInstall),
// so its digest matches no attestation. When the direct check fails there and
// opts.Tag names the release this build came from, VerifyBinary instead
// downloads that release's asset for this platform, verifies the asset's
// provenance, applies gh's re-signature to the copy, and requires the result
// to be byte-identical to the running binary — the same trust statement,
// carried over the deterministic install-time transform.
func VerifyBinary(path string, opts VerifyOptions) (string, error) {
	list := newSteps(opts.Progress)
	list.start("Checking the running binary against GitHub's attestation store")
	report, directErr := verifyArtifact(path, opts)
	if directErr == nil {
		list.done()
		return report, nil
	}
	list.fail()
	if opts.Tag == "" || !resignedOnInstall() {
		return "", directErr
	}
	list.info("gh re-signs extension binaries when installing them on Apple Silicon, so the")
	list.info("installed binary matches no attestation; verifying via the release asset instead")
	report, err := verifyViaReleaseAsset(path, opts, list)
	if err != nil {
		return "", errors.Join(directErr, fmt.Errorf("release-asset fallback: %w", err))
	}
	return report, nil
}

// verifyArtifact runs `gh attestation verify` on a single artifact.
func verifyArtifact(path string, opts VerifyOptions) (string, error) {
	args := []string{"attestation", "verify", path, "--repo", AttestRepo}
	switch {
	case opts.SignerWorkflow != "":
		args = append(args, "--signer-workflow", opts.SignerWorkflow)
	case opts.CertIdentity != "":
		args = append(args, "--cert-identity-regex", opts.CertIdentity)
	default:
		args = append(args, "--signer-workflow", DefaultSignerWorkflow)
	}
	if opts.JSON {
		args = append(args, "--format", "json")
	}

	stdout, stderr, err := execGH(args...)
	if err != nil {
		return "", fmt.Errorf("attestation verification failed: %w\n%s", err, strings.TrimSpace(stderr+"\n"+stdout))
	}
	out := strings.TrimSpace(stdout)
	if out == "" {
		out = strings.TrimSpace(stderr) // gh prints its human summary to stderr
	}
	return out, nil
}

// resignNote explains a fallback success to a human reader (%s is the release
// tag). It is withheld in JSON mode to keep stdout parseable.
const resignNote = "\n\nNote: gh ad-hoc re-signs extension binaries on Apple Silicon when it\n" +
	"installs them, so the installed binary's digest matches no attestation.\n" +
	"Verified instead that the attested release asset for %s, re-signed\n" +
	"exactly as gh does at install time, is byte-identical to this binary."

// verifyViaReleaseAsset proves the running binary at path is the attested
// release asset modulo gh's install-time re-signature: download the asset for
// opts.Tag, verify the asset's provenance, re-sign the copy the way gh did,
// and byte-compare it with the running binary. Each stage is reported on
// list as it runs.
func verifyViaReleaseAsset(path string, opts VerifyOptions, list *steps) (string, error) {
	dir, err := os.MkdirTemp("", "gh-claude-verify-")
	if err != nil {
		return "", fmt.Errorf("create temp dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()

	list.start("Downloading " + assetName() + " from release " + opts.Tag)
	asset := filepath.Join(dir, InstalledName)
	if _, stderr, err := execGH("release", "download", opts.Tag, "--repo", AttestRepo,
		"--pattern", assetName(), "--output", asset); err != nil {
		list.fail()
		return "", fmt.Errorf("download %s from release %s: %w\n%s",
			assetName(), opts.Tag, err, strings.TrimSpace(stderr))
	}
	list.done()

	list.start("Verifying the release asset's build provenance")
	report, err := verifyArtifact(asset, opts)
	if err != nil {
		list.fail()
		return "", fmt.Errorf("release asset %s: %w", assetName(), err)
	}
	list.done()

	list.start("Re-signing the asset copy exactly as gh does at install")
	if err := execCodesign(asset); err != nil {
		list.fail()
		return "", fmt.Errorf("re-sign release asset: %w", err)
	}
	list.done()

	list.start("Comparing the running binary against the re-signed asset")
	same, err := filesEqual(asset, path)
	if err != nil {
		list.fail()
		return "", err
	}
	if !same {
		list.fail()
		return "", fmt.Errorf("running binary is not the attested %s asset from release %s, "+
			"even after applying gh's install-time re-signature — it was modified after "+
			"install or did not come from that release", assetName(), opts.Tag)
	}
	list.done()

	if !opts.JSON {
		report += fmt.Sprintf(resignNote, opts.Tag)
	}
	return report, nil
}

// assetName returns the release asset for the running platform, following the
// goreleaser name_template (gh-claude-<os>-<arch>[.exe]).
func assetName() string {
	name := "gh-claude-" + runtime.GOOS + "-" + runtime.GOARCH
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return name
}

// filesEqual reports whether the files at a and b have identical contents.
func filesEqual(a, b string) (bool, error) {
	ba, err := os.ReadFile(a)
	if err != nil {
		return false, fmt.Errorf("read %s: %w", a, err)
	}
	bb, err := os.ReadFile(b)
	if err != nil {
		return false, fmt.Errorf("read %s: %w", b, err)
	}
	return bytes.Equal(ba, bb), nil
}

// releaseVersion matches the plain X.Y.Z versions goreleaser stamps into
// release builds; the "dev" default and git-describe versions from local
// Makefile builds (v0.1.1-9-gabc1234-dirty) do not match.
var releaseVersion = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

// ReleaseTag maps a build version to the release tag that published it:
// "0.2.0" (goreleaser strips the v) and "v0.2.0" both yield "v0.2.0". It
// returns "" when the version is not a plain release — a local build has no
// release asset for VerifyBinary's darwin/arm64 fallback to compare against.
func ReleaseTag(version string) string {
	v := strings.TrimPrefix(version, "v")
	if !releaseVersion.MatchString(v) {
		return ""
	}
	return "v" + v
}

// RunningBinaryPath returns the absolute, symlink-resolved path of the running
// executable — the artifact `gh claude verify` should check.
func RunningBinaryPath() (string, error) {
	path, err := os.Executable()
	if err != nil {
		return "", err
	}
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		path = resolved
	}
	return filepath.Abs(path)
}
