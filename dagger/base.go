package main

import (
	"dagger/x-509-ce/internal/dagger"
)

// Pinned image versions. Renovate's `regex` manager (configured in
// renovate.json5) tracks the `<name>Image = "..."` literals here.
const (
	golangImage = "golang:1.26.2-alpine@sha256:f85330846cde1e57ca9ec309382da3b8e6ae3ab943d2739500e08c86393a21b1"
	alpineImage = "alpine:3.23.4@sha256:5b10f432ef3da1b8d4c7eb6c487f2f5a8f096bc91145e68878dd4a5019afde11"
	helmImage = "alpine/helm:4.1.4@sha256:4b0bdd2cf18ff6bca12aba0b2c5671384dab5035c19c57f0c58b854a0baf65be"
	renovateImage = "renovate/renovate:43.162.0@sha256:d847140cb0fb08184d4450f185e8fb8e7ae08c60e38d687429008d99f725aee2"
	helmDocsImage = "jnorwood/helm-docs:v1.14.2@sha256:7e562b49ab6b1dbc50c3da8f2dd6ffa8a5c6bba327b1c6335cc15ce29267979c"
	helmSchemaImage = "ghcr.io/dadav/helm-schema:0.23.2@sha256:4807d868cb489e8160e0cece1aba51d2101a9c307b76bdda4f88929c75bd5c29"
	markdownlintImage = "davidanson/markdownlint-cli2:v0.22.1@sha256:0ed9a5f4c77ef447da2a2ac6e67caf74b214a7f80288819565e8b7d2ac148fe5"
	trivyImage = "aquasec/trivy:0.70.0@sha256:be1190afcb28352bfddc4ddeb71470835d16462af68d310f9f4bca710961a41e"
	golangciLint      = "v2.12.1" // installed via `go install`
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
