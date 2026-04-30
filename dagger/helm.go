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
