package main

import (
	"dagger/x-509-ce/internal/dagger"
)

// HelmDocs regenerates chart/README.md from chart/README.md.gotmpl +
// the docstrings on each value in chart/values.yaml.
//
// Returns a *File — Dagger doesn't write to the host filesystem on
// its own, so a bare `dagger call helm-docs` only builds the graph
// and prints the file's identifier. To actually overwrite
// chart/README.md, chain the `export` verb (the Taskfile target
// `task doc:helm` does this for you):
//
//	dagger call helm-docs export --path=chart/README.md
//	# or, equivalently:
//	task doc:helm
func (m *X509Ce) HelmDocs() *dagger.File {
	return dag.Container().
		From(helmDocsImage).
		WithWorkdir("/src").
		WithDirectory("/src/chart", m.Source.Directory("chart")).
		WithExec([]string{
			"helm-docs",
			"--skip-version-footer",
			"--sort-values-order=file",
			"--chart-search-root=chart",
		}).
		File("/src/chart/README.md")
}

// ChartSchema regenerates chart/values.schema.json from chart/values.yaml
// + the `# @schema` annotations embedded next to each value. The
// inferred baseline is type + default + additionalProperties:false +
// required (every key declared in values.yaml). Annotations layer
// constraints on top: enums, ranges, patterns, item shapes, and
// `additionalProperties:true` on free-form override maps.
//
// `--skip-auto-generation=title,description` strips two noise
// categories: titles (duplicate field names) and descriptions
// (helm-docs already produces chart/README.md as the human reference,
// duplicating it in the schema would split the source of truth).
// `--append-newline` keeps the file POSIX-clean.
//
// Returns a *File — see HelmDocs for the export-vs-call semantics.
// `task doc:helm` regenerates this alongside chart/README.md.
//
// The image's default USER (10001 / `helm-schema`) cannot write to the
// chart directory we mount in (Dagger preserves source ownership) and
// helm-schema silently swallows the resulting write error. Overriding
// to root sidesteps the issue — the sandbox has no security implications.
func (m *X509Ce) ChartSchema() *dagger.File {
	return dag.Container().
		From(helmSchemaImage).
		WithUser("root").
		WithWorkdir("/src").
		WithDirectory("/src/chart", m.Source.Directory("chart")).
		WithExec(
			[]string{
				"--chart-search-root=chart",
				"--skip-auto-generation=title,description",
				"--append-newline",
			},
			dagger.ContainerWithExecOpts{UseEntrypoint: true},
		).
		File("/src/chart/values.schema.json")
}
