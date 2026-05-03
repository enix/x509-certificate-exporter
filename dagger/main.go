// X509Ce — sandboxed QA/CI pipelines for x509-certificate-exporter.
//
// Each exported method on the X509Ce struct is exposed as a Dagger
// function and callable via the CLI. Because `dagger.json` lives at
// the repo root (with `source: "dagger"` pointing at this directory),
// `dagger call` finds the module via "find-up" without any -m flag:
//
//	dagger call lint-go
//	dagger call test
//	dagger call helm-docs export --path=chart/README.md
//
// Taskfile.yml wraps these calls under the same task names as before
// (lint:go, test:unit, doc:helm, etc.).
//
// Container image builds (release AND dev) live in .goreleaser.yaml,
// not here — single Dockerfile path for every image in the repo.
package main

import (
	"dagger/x-509-ce/internal/dagger"
)

// X509Ce holds the source directory shared across all functions. It is
// supplied once via `--source=.` (CLI) or via the New constructor's
// default and reused by every call.
type X509Ce struct {
	// +private
	Source *dagger.Directory
}

// New is invoked by the Dagger CLI to construct the module instance.
// `source` is the working tree to operate on. `defaultPath="/"`
// resolves to the module root (repo root, since dagger.json lives
// there). Build outputs and VCS junk are excluded so the cache key
// isn't busted by a stray `dist/` change.
func New(
	// +defaultPath="/"
	// +ignore=["dist/", ".git/", "kubeconfig.yaml", "renovate-debug.log", "node_modules/", "dagger/"]
	source *dagger.Directory,
) *X509Ce {
	return &X509Ce{Source: source}
}
