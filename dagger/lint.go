package main

import (
	"context"
	"fmt"

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
