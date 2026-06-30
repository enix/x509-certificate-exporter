package main

import (
	"dagger/x-509-ce/internal/dagger"
)

// Pinned image versions. Renovate's `regex` manager (configured in
// renovate.json5) tracks the `<name>Image = "..."` literals here.
const (
	golangImage = "golang:1.26.4-alpine@sha256:3ad57304ad93bbec8548a0437ad9e06a455660655d9af011d58b993f6f615648"
	alpineImage = "alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b"
	helmImage = "alpine/helm:4.2.2@sha256:ee6fe3e96d9f8ea8dd1af9ecd7bbb3e233616a25f145392376f020fd2a51eb33"
	renovateImage = "renovate/renovate:43.249.2@sha256:00dbd1158d86fda20bd5f144e8b9e40d2f6f306c48ea008244d8a6708e5f2de3"
	helmDocsImage     = "jnorwood/helm-docs:v1.14.2@sha256:7e562b49ab6b1dbc50c3da8f2dd6ffa8a5c6bba327b1c6335cc15ce29267979c"
	helmSchemaImage   = "ghcr.io/dadav/helm-schema:0.23.2@sha256:4807d868cb489e8160e0cece1aba51d2101a9c307b76bdda4f88929c75bd5c29"
	markdownlintImage = "davidanson/markdownlint-cli2:v0.22.1@sha256:0ed9a5f4c77ef447da2a2ac6e67caf74b214a7f80288819565e8b7d2ac148fe5"
	trivyImage = "aquasec/trivy:0.72.0@sha256:cffe3f5161a47a6823fbd23d985795b3ed72a4c806da4c4df16266c02accdd6f"
	gitleaksImage     = "ghcr.io/gitleaks/gitleaks:v8.30.1@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f"
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
