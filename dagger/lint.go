package main

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"dagger/x-509-ce/internal/dagger"
)

// lintGoBase stages golangci-lint compiled from source against the
// project's Go toolchain. The official prebuilt images embed
// go/parser+go/types of whatever Go they were built with; compiling
// here keeps the analyzer aligned with go.mod's `go` directive.
func (m *X509Ce) lintGoBase() *dagger.Container {
	return goBase(m.Source).
		WithExec([]string{
			"go", "install",
			"github.com/golangci/golangci-lint/v2/cmd/golangci-lint@" + golangciLint,
		})
}

// LintGo runs golangci-lint over the project's Go code.
//
// `mode` selects the rule subset:
//   - "" (default) — the full configured set (.golangci.yml).
//   - "gocritic"   — only the gocritic linter (opinionated style).
//   - "no-critic"  — the full set minus gocritic, for a quick
//     "is anything actually broken?" check that skips the noisy
//     opinionated category.
func (m *X509Ce) LintGo(
	ctx context.Context,
	// Rule subset to run: "" (default — full set), "gocritic" (only
	// the gocritic linter), or "no-critic" (full set minus gocritic).
	// +optional
	mode string,
) (string, error) {
	cmd := []string{"golangci-lint", "run"}
	switch mode {
	case "":
		// full configured set
	case "gocritic":
		cmd = append(cmd, "--enable-only=gocritic")
	case "no-critic":
		cmd = append(cmd, "--disable=gocritic")
	default:
		return "", fmt.Errorf(`unknown mode %q (expected "", "gocritic", or "no-critic")`, mode)
	}
	cmd = append(cmd, "./...")
	return m.lintGoBase().WithExec(cmd).Stdout(ctx)
}

// LintHelm runs `helm lint` on the chart.
func (m *X509Ce) LintHelm(ctx context.Context) (string, error) {
	return dag.Container().
		From(helmImage).
		WithWorkdir("/src").
		WithDirectory("/src/chart", m.Source.Directory("chart")).
		WithExec([]string{"helm", "lint", "chart"}).
		Stdout(ctx)
}

// LintHelmExamples runs `helm lint` on the chart against every example
// values file under docs/examples/.
//
// File enumeration uses Directory.Glob so we stay in Go: each lint runs
// as its own WithExec on a shared base container, and a non-zero exit
// surfaces as a *dagger.ExecError carrying both stdout and stderr.
func (m *X509Ce) LintHelmExamples(ctx context.Context) (string, error) {
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

// LintRenovate validates renovate.json5 against the schema.
func (m *X509Ce) LintRenovate(ctx context.Context) (string, error) {
	return dag.Container().
		From(renovateImage).
		WithWorkdir("/src").
		WithFile("/src/renovate.json5", m.Source.File("renovate.json5")).
		WithExec([]string{"renovate-config-validator", "--strict"}).
		Stdout(ctx)
}

// LintMarkdown runs markdownlint-cli2 on the project's hand-written
// Markdown. The image's ENTRYPOINT is `markdownlint-cli2` (which
// expands globs natively, no shell needed). UseEntrypoint=true tells
// Dagger to prepend that ENTRYPOINT — without it, `WithExec` would
// try to fork/exec the glob string itself. Globs + ignores live in
// `.markdownlint-cli2.jsonc` at the repo root.
func (m *X509Ce) LintMarkdown(ctx context.Context) (string, error) {
	return dag.Container().
		From(markdownlintImage).
		WithWorkdir("/src").
		WithDirectory("/src", m.Source).
		WithExec(
			[]string{"**/*.md"},
			dagger.ContainerWithExecOpts{UseEntrypoint: true},
		).
		Stdout(ctx)
}
