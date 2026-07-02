// Copyright 2026 Bitwise Media Group Ltd.
// SPDX-License-Identifier: MIT

package integrity

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// withExecGH swaps the gh exec stub for the duration of a test.
func withExecGH(t *testing.T, fn func(args ...string) (string, string, error)) {
	t.Helper()
	prev := execGH
	execGH = fn
	t.Cleanup(func() { execGH = prev })
}

// withCodesign swaps the codesign stub for the duration of a test.
func withCodesign(t *testing.T, fn func(path string) error) {
	t.Helper()
	prev := execCodesign
	execCodesign = fn
	t.Cleanup(func() { execCodesign = prev })
}

// withResignedOnInstall forces the darwin/arm64 fallback gate so the fallback
// path is testable on any platform.
func withResignedOnInstall(t *testing.T, v bool) {
	t.Helper()
	prev := resignedOnInstall
	resignedOnInstall = func() bool { return v }
	t.Cleanup(func() { resignedOnInstall = prev })
}

// resignSuffix is the marker the stubbed codesign appends so tests can model
// gh's deterministic install-time re-signature as an observable transform.
const resignSuffix = "+adhoc"

// appendingCodesign stubs codesign as "append resignSuffix", recording the
// path it signed.
func appendingCodesign(t *testing.T, signed *string) {
	t.Helper()
	withCodesign(t, func(path string) error {
		*signed = path
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(path, append(b, []byte(resignSuffix)...), 0o755)
	})
}

// fallbackGH stubs execGH for the fallback flow: direct verification of
// running fails, `release download` writes pristine to --output, and
// verification of any other artifact succeeds. It records every gh call.
func fallbackGH(t *testing.T, running string, pristine []byte, calls *[][]string) {
	t.Helper()
	withExecGH(t, func(args ...string) (string, string, error) {
		*calls = append(*calls, args)
		switch args[0] {
		case "attestation":
			if args[2] == running {
				return "", "no attestations found", errors.New("exit status 1")
			}
			return "Verification succeeded!", "", nil
		case "release":
			out := args[slices.Index(args, "--output")+1]
			return "", "", os.WriteFile(out, pristine, 0o755)
		}
		return "", "", fmt.Errorf("unexpected gh call: %s", strings.Join(args, " "))
	})
}

// writeBinary creates a file named as the installed extension binary for the
// test to treat as the running binary.
func writeBinary(t *testing.T, dir string, content []byte) string {
	t.Helper()
	path := filepath.Join(dir, InstalledName)
	if err := os.WriteFile(path, content, 0o755); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

func TestVerifyBinaryDefaults(t *testing.T) {
	var got []string
	withExecGH(t, func(args ...string) (string, string, error) {
		got = args
		return "Verification succeeded!", "", nil
	})

	out, err := VerifyBinary("/path/to/gh-claude", VerifyOptions{})
	if err != nil {
		t.Fatalf("VerifyBinary: %v", err)
	}
	if out == "" {
		t.Error("expected gh's report to be returned")
	}
	joined := strings.Join(got, " ")
	// Every release is built by the org's reusable workflow, whose identity the
	// attestation certificate names — without --signer-workflow the default
	// claim could never verify.
	wants := []string{
		"attestation verify /path/to/gh-claude",
		"--repo " + AttestRepo,
		"--signer-workflow " + DefaultSignerWorkflow,
	}
	for _, want := range wants {
		if !strings.Contains(joined, want) {
			t.Errorf("args %q missing %q", joined, want)
		}
	}
	// --owner and --repo are mutually exclusive in gh; the default must send only --repo.
	if strings.Contains(joined, "--owner") {
		t.Errorf("args %q must not pass --owner alongside --repo", joined)
	}
}

func TestVerifyBinaryCertIdentityOverridesDefaultSigner(t *testing.T) {
	var got []string
	withExecGH(t, func(args ...string) (string, string, error) {
		got = args
		return "ok", "", nil
	})
	if _, err := VerifyBinary("/bin/x", VerifyOptions{CertIdentity: "^https://github.com/acme/"}); err != nil {
		t.Fatalf("VerifyBinary: %v", err)
	}
	joined := strings.Join(got, " ")
	if !strings.Contains(joined, "--cert-identity-regex ^https://github.com/acme/") {
		t.Errorf("args %q missing cert-identity regex", joined)
	}
	if strings.Contains(joined, "--signer-workflow") {
		t.Errorf("args %q must not combine --signer-workflow with --cert-identity-regex", joined)
	}
}

func TestVerifyBinarySignerWorkflow(t *testing.T) {
	var got []string
	withExecGH(t, func(args ...string) (string, string, error) {
		got = args
		return "ok", "", nil
	})
	opts := VerifyOptions{SignerWorkflow: "o/r/.github/workflows/release.yaml", JSON: true}
	if _, err := VerifyBinary("/bin/x", opts); err != nil {
		t.Fatalf("VerifyBinary: %v", err)
	}
	joined := strings.Join(got, " ")
	if !strings.Contains(joined, "--signer-workflow o/r/.github/workflows/release.yaml") {
		t.Errorf("args %q missing signer-workflow", joined)
	}
	if !strings.Contains(joined, "--format json") {
		t.Errorf("args %q missing json format", joined)
	}
}

func TestVerifyBinaryPropagatesFailure(t *testing.T) {
	withExecGH(t, func(args ...string) (string, string, error) {
		return "", "no attestations found", errors.New("exit status 1")
	})
	_, err := VerifyBinary("/bin/x", VerifyOptions{})
	if err == nil {
		t.Fatal("expected error on verification failure")
	}
	if !strings.Contains(err.Error(), "no attestations found") {
		t.Errorf("error %q should include gh's output", err.Error())
	}
}

func TestVerifyBinaryFallbackMatchesResignedAsset(t *testing.T) {
	withResignedOnInstall(t, true)
	pristine := []byte("pristine release asset")
	running := writeBinary(t, t.TempDir(), append(pristine, []byte(resignSuffix)...))

	var calls [][]string
	fallbackGH(t, running, pristine, &calls)
	var signed string
	appendingCodesign(t, &signed)

	out, err := VerifyBinary(running, VerifyOptions{Tag: "v0.2.0"})
	if err != nil {
		t.Fatalf("VerifyBinary: %v", err)
	}
	if !strings.Contains(out, "Verification succeeded!") {
		t.Errorf("report %q should include gh's verification report", out)
	}
	if !strings.Contains(out, "re-sign") {
		t.Errorf("report %q should explain the re-signature fallback", out)
	}

	var download string
	for _, c := range calls {
		if c[0] == "release" {
			download = strings.Join(c, " ")
		}
	}
	for _, want := range []string{"release download v0.2.0", "--repo " + AttestRepo, "--pattern " + assetName()} {
		if !strings.Contains(download, want) {
			t.Errorf("download call %q missing %q", download, want)
		}
	}
	// codesign derives the ad-hoc identifier from the filename, so the copy
	// must be signed under the exact name gh gave the installed binary.
	if got := filepath.Base(signed); got != InstalledName {
		t.Errorf("re-signed copy named %q, want %q", got, InstalledName)
	}
}

func TestVerifyBinaryFallbackRejectsMismatch(t *testing.T) {
	withResignedOnInstall(t, true)
	running := writeBinary(t, t.TempDir(), []byte("tampered binary"+resignSuffix))

	var calls [][]string
	fallbackGH(t, running, []byte("pristine release asset"), &calls)
	var signed string
	appendingCodesign(t, &signed)

	_, err := VerifyBinary(running, VerifyOptions{Tag: "v0.2.0"})
	if err == nil {
		t.Fatal("expected error when the running binary is not the re-signed asset")
	}
	if !strings.Contains(err.Error(), "is not the attested") {
		t.Errorf("error %q should call out the mismatch", err.Error())
	}
}

func TestVerifyBinaryFallbackPropagatesAssetFailure(t *testing.T) {
	withResignedOnInstall(t, true)
	running := writeBinary(t, t.TempDir(), []byte("installed"))

	withExecGH(t, func(args ...string) (string, string, error) {
		if args[0] == "release" {
			out := args[slices.Index(args, "--output")+1]
			return "", "", os.WriteFile(out, []byte("asset"), 0o755)
		}
		return "", "no attestations found", errors.New("exit status 1")
	})

	_, err := VerifyBinary(running, VerifyOptions{Tag: "v0.2.0"})
	if err == nil {
		t.Fatal("expected error when the release asset fails verification too")
	}
	for _, want := range []string{"no attestations found", "release asset " + assetName()} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q should include %q", err.Error(), want)
		}
	}
}

func TestVerifyBinarySkipsFallback(t *testing.T) {
	cases := []struct {
		name     string
		resigned bool
		tag      string
	}{
		{"no release tag", true, ""},
		{"platform not re-signed by gh", false, "v0.2.0"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			withResignedOnInstall(t, c.resigned)
			var calls [][]string
			withExecGH(t, func(args ...string) (string, string, error) {
				calls = append(calls, args)
				return "", "no attestations found", errors.New("exit status 1")
			})

			_, err := VerifyBinary("/bin/x", VerifyOptions{Tag: c.tag})
			if err == nil {
				t.Fatal("expected the direct verification failure")
			}
			if len(calls) != 1 {
				t.Errorf("gh called %d times, want only the direct verification", len(calls))
			}
		})
	}
}

func TestVerifyBinaryReportsProgress(t *testing.T) {
	withResignedOnInstall(t, true)
	pristine := []byte("pristine release asset")
	running := writeBinary(t, t.TempDir(), append(pristine, []byte(resignSuffix)...))

	var calls [][]string
	fallbackGH(t, running, pristine, &calls)
	var signed string
	appendingCodesign(t, &signed)

	var progress strings.Builder
	if _, err := VerifyBinary(running, VerifyOptions{Tag: "v0.2.0", Progress: &progress}); err != nil {
		t.Fatalf("VerifyBinary: %v", err)
	}

	// Off-terminal a strings.Builder gets plain finished lines: the failed
	// direct check, then one green-check line per fallback stage.
	wants := []string{
		"✗ Checking the running binary",
		"✓ Downloading " + assetName() + " from release v0.2.0",
		"✓ Verifying the release asset's build provenance",
		"✓ Re-signing the asset copy",
		"✓ Comparing the running binary",
	}
	lines := strings.Split(strings.TrimSpace(progress.String()), "\n")
	var marked []string
	for _, l := range lines {
		if !strings.HasPrefix(l, "  ") { // skip the indented explanation
			marked = append(marked, l)
		}
	}
	if len(marked) != len(wants) {
		t.Fatalf("progress lines = %q, want %d step lines", lines, len(wants))
	}
	for i, want := range wants {
		if !strings.HasPrefix(marked[i], want) {
			t.Errorf("step %d = %q, want prefix %q", i, marked[i], want)
		}
	}
}

func TestVerifyBinaryProgressMarksFailedStep(t *testing.T) {
	withResignedOnInstall(t, true)
	running := writeBinary(t, t.TempDir(), []byte("tampered"+resignSuffix))

	var calls [][]string
	fallbackGH(t, running, []byte("pristine release asset"), &calls)
	var signed string
	appendingCodesign(t, &signed)

	var progress strings.Builder
	if _, err := VerifyBinary(running, VerifyOptions{Tag: "v0.2.0", Progress: &progress}); err == nil {
		t.Fatal("expected mismatch error")
	}
	if !strings.Contains(progress.String(), "✗ Comparing the running binary") {
		t.Errorf("progress %q should mark the comparison step failed", progress.String())
	}
}

func TestReleaseTag(t *testing.T) {
	cases := []struct {
		version string
		want    string
	}{
		{"0.2.0", "v0.2.0"},
		{"v0.2.0", "v0.2.0"},
		{"dev", ""},
		{"v0.1.1-9-g2772579-dirty", ""},
		{"0.3.0-snapshot-abc1234", ""},
		{"1.2", ""},
		{"", ""},
	}
	for _, c := range cases {
		t.Run(c.version, func(t *testing.T) {
			if got := ReleaseTag(c.version); got != c.want {
				t.Errorf("ReleaseTag(%q) = %q, want %q", c.version, got, c.want)
			}
		})
	}
}
