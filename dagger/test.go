package main

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"dagger/x-509-ce/internal/dagger"
)

// Test runs unit tests via gotestsum with the race detector enabled
// and a coverage profile saved. The race detector requires CGO, which
// on Alpine pulls gcc + musl-dev.
func (m *X509Ce) Test(ctx context.Context) (string, error) {
	return goBase(m.Source).
		WithExec([]string{"apk", "add", "--no-cache", "gcc", "musl-dev"}).
		WithEnvVariable("CGO_ENABLED", "1").
		WithExec([]string{"go", "install", "gotest.tools/gotestsum@" + gotestsumModule}).
		WithExec([]string{
			"gotestsum",
			"--format=pkgname-and-test-fails",
			"--junitfile=/tmp/junit.xml",
			"--",
			"-race",
			"-coverprofile=/tmp/coverage.out",
			"./...",
		}).
		Stdout(ctx)
}

// TestHelmExamples runs `helm lint` on the chart against every example
// values file under docs/examples/ and asserts each one is accepted.
// Behavioral test, not a style check: it proves the documented
// configurations still validate against the chart-as-implemented.
//
// File enumeration uses Directory.Glob so we stay in Go: each lint
// runs as its own WithExec on a shared base container, and a non-zero
// exit surfaces as a *dagger.ExecError carrying both stdout and stderr.
func (m *X509Ce) TestHelmExamples(ctx context.Context) (string, error) {
	examples := m.Source.Directory("docs/examples")
	files, err := examples.Glob(ctx, "**/*.values.yaml")
	if err != nil {
		return "", fmt.Errorf("listing example values files: %w", err)
	}
	if len(files) == 0 {
		return "", errors.New("no *.values.yaml files found under docs/examples/")
	}
	sort.Strings(files)

	base := dag.Container().
		From(helmImage).
		WithWorkdir("/src").
		WithDirectory("/src/chart", m.Source.Directory("chart")).
		WithDirectory("/src/docs/examples", examples)

	var report strings.Builder
	var failed []string
	for _, f := range files {
		fmt.Fprintf(&report, "\n== docs/examples/%s ==\n", f)
		_, err := base.WithExec([]string{
			"helm", "lint", "chart", "--values", "docs/examples/" + f,
		}).Sync(ctx)
		if err == nil {
			report.WriteString("  OK\n")
			continue
		}
		var execErr *dagger.ExecError
		if !errors.As(err, &execErr) {
			return report.String(), fmt.Errorf("dagger error linting %s: %w", f, err)
		}
		writeIndented(&report, execErr.Stdout, "  ")
		writeIndented(&report, execErr.Stderr, "  ")
		failed = append(failed, f)
	}
	if len(failed) > 0 {
		return report.String(), fmt.Errorf("helm lint failed for %d example(s): %s",
			len(failed), strings.Join(failed, ", "))
	}
	return report.String(), nil
}

// TestHelmFixtures runs `helm lint` on the chart against every fixture
// under test/schema/{valid,invalid}/ and asserts:
//
//   - test/schema/valid/*.yaml             — must pass.
//   - test/schema/invalid/<name>.yaml      — must fail, AND the helm
//     output must contain every non-comment, non-blank line listed in
//     the paired test/schema/invalid/<name>.expect.txt as a substring.
//
// Companion to TestHelmExamples: that one proves the documented
// configurations stay valid; this one proves the schema rejects what
// it claims to reject. Together they form a regression net around the
// chart's values.schema.json so a future loosening (intentional or
// not) is caught at PR time, not by a downstream user in production.
func (m *X509Ce) TestHelmFixtures(ctx context.Context) (string, error) {
	schemaDir := m.Source.Directory("test/schema")
	validFiles, err := schemaDir.Glob(ctx, "valid/*.yaml")
	if err != nil {
		return "", fmt.Errorf("listing valid fixtures: %w", err)
	}
	invalidFiles, err := schemaDir.Glob(ctx, "invalid/*.yaml")
	if err != nil {
		return "", fmt.Errorf("listing invalid fixtures: %w", err)
	}
	if len(validFiles) == 0 && len(invalidFiles) == 0 {
		return "", errors.New("no fixtures found under test/schema/{valid,invalid}/")
	}
	sort.Strings(validFiles)
	sort.Strings(invalidFiles)

	base := dag.Container().
		From(helmImage).
		WithWorkdir("/src").
		WithDirectory("/src/chart", m.Source.Directory("chart")).
		WithDirectory("/src/test/schema", schemaDir)

	var report strings.Builder
	var failed []string

	// Positive cases: helm lint must succeed.
	for _, f := range validFiles {
		fmt.Fprintf(&report, "\n== %s ==\n", f)
		_, err := base.WithExec([]string{
			"helm", "lint", "chart", "--values", "test/schema/" + f,
		}).Sync(ctx)
		if err == nil {
			report.WriteString("  OK\n")
			continue
		}
		var execErr *dagger.ExecError
		if !errors.As(err, &execErr) {
			return report.String(), fmt.Errorf("dagger error on %s: %w", f, err)
		}
		report.WriteString("  EXPECTED PASS, GOT FAIL:\n")
		writeIndented(&report, execErr.Stdout, "    ")
		writeIndented(&report, execErr.Stderr, "    ")
		failed = append(failed, f)
	}

	// Negative cases: helm lint must fail AND output must contain every
	// expected substring listed in the paired .expect.txt.
	for _, f := range invalidFiles {
		fmt.Fprintf(&report, "\n== %s ==\n", f)
		expectPath := strings.TrimSuffix("test/schema/"+f, ".yaml") + ".expect.txt"
		expectContents, err := m.Source.File(expectPath).Contents(ctx)
		if err != nil {
			report.WriteString("  MISSING " + expectPath + "\n")
			failed = append(failed, f+" (missing "+expectPath+")")
			continue
		}
		var expects []string
		for _, line := range strings.Split(expectContents, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			expects = append(expects, line)
		}

		_, err = base.WithExec([]string{
			"helm", "lint", "chart", "--values", "test/schema/" + f,
		}).Sync(ctx)
		if err == nil {
			report.WriteString("  EXPECTED FAIL, GOT PASS\n")
			failed = append(failed, f+" (expected fail, got pass)")
			continue
		}
		var execErr *dagger.ExecError
		if !errors.As(err, &execErr) {
			return report.String(), fmt.Errorf("dagger error on %s: %w", f, err)
		}
		out := execErr.Stdout + "\n" + execErr.Stderr
		var missing []string
		for _, e := range expects {
			if !strings.Contains(out, e) {
				missing = append(missing, e)
			}
		}
		if len(missing) == 0 {
			report.WriteString("  OK\n")
			continue
		}
		report.WriteString("  MISSING SUBSTRINGS:\n")
		for _, m := range missing {
			fmt.Fprintf(&report, "    %q\n", m)
		}
		report.WriteString("  ── helm output ──\n")
		writeIndented(&report, out, "    ")
		failed = append(failed, f+" (missing substrings)")
	}

	if len(failed) > 0 {
		return report.String(), fmt.Errorf("schema fixture failures: %d case(s)", len(failed))
	}
	return report.String(), nil
}

// writeIndented appends s to w with each non-empty line prefixed by
// indent. Trailing newlines are normalized to a single one.
func writeIndented(w *strings.Builder, s, indent string) {
	s = strings.TrimRight(s, "\n")
	if s == "" {
		return
	}
	for _, line := range strings.Split(s, "\n") {
		w.WriteString(indent)
		w.WriteString(line)
		w.WriteByte('\n')
	}
}
