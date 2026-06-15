package main

import (
	"dagger/x-509-ce/internal/dagger"
)

// Pinned image versions. Renovate's `regex` manager (configured in
// renovate.json5) tracks the `<name>Image = "..."` literals here.
const (
	golangImage = "golang:1.26.4-alpine@sha256:7a3e50096189ad57c9f9f865e7e4aa8585ed1585248513dc5cda498e2f41812c"
	alpineImage = "alpine:3.23.4@sha256:5b10f432ef3da1b8d4c7eb6c487f2f5a8f096bc91145e68878dd4a5019afde11"
	helmImage = "alpine/helm:4.2.1@sha256:8647f126de3578d74f947ba735e4cfa0ea6aea7d6e2f36bceb86f31415944dca"
	renovateImage = "renovate/renovate:43.195.4@sha256:32a0a9cefd0b0b8587bb1caa73b6600a299ae7f2566cf0350eba4fe2375c24cb"
	helmDocsImage = "jnorwood/helm-docs:v1.14.2@sha256:7e562b49ab6b1dbc50c3da8f2dd6ffa8a5c6bba327b1c6335cc15ce29267979c"
	helmSchemaImage = "ghcr.io/dadav/helm-schema:0.23.2@sha256:4807d868cb489e8160e0cece1aba51d2101a9c307b76bdda4f88929c75bd5c29"
	markdownlintImage = "davidanson/markdownlint-cli2:v0.22.1@sha256:0ed9a5f4c77ef447da2a2ac6e67caf74b214a7f80288819565e8b7d2ac148fe5"
	trivyImage = "aquasec/trivy:0.71.1@sha256:53570e6911c2361ebe7995228088cf83a6b9b73e7f3cdca44bd8f8f425e80fa7"
	golangciLint      = "v2.12.2" // installed via `go install`
	gotestsumModule   = "v1.13.0" // ditto
	govulncheckPath   = "latest"  // tracking latest, no Renovate pin
)

// goBase returns a base Go container with go.mod/sum prefetched and
// build/module caches mounted. Every Go-flavoured method starts here.
func goBase(source *dagger.Directory) *dagger.Container {
	return dag.Container().
		From(golangImage).
		WithEnvVariable("GOTOOLCHAIN", "auto").
		WithEnvVariable("CGO_ENABLED", "0").
		WithMountedCache("/go/pkg/mod", dag.CacheVolume("go-mod")).
		WithMountedCache("/root/.cache/go-build", dag.CacheVolume("go-build")).
		WithWorkdir("/src").
		WithFile("/src/go.mod", source.File("go.mod")).
		WithFile("/src/go.sum", source.File("go.sum")).
		WithExec([]string{"go", "mod", "download"}).
		WithDirectory("/src", source)
}
