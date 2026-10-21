package main

import (
	"dagger/x-509-ce/internal/dagger"
)

// Pinned image versions. Renovate's `regex` manager (configured in
// renovate.json5) tracks the `<name>Image = "..."` literals here.
const (
	golangImage = "golang:1.27.3-alpine@sha256:f2c872bcee949b7be9c490efd02b48a8a2fbf947cdf533f1c58525ec9d8170fd"
	alpineImage = "alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6"
	helmImage = "alpine/helm:4.3.1@sha256:e3f8d5c462d75470fbb1fce79ad5c20063657096d1f98c0fcea869e2600e2e5e"
	renovateImage = "renovate/renovate:44.175.0@sha256:e9279a5df7697622f880306c84460be14a0492d5dcf5b20cdae1995c836cc4d7"
	helmDocsImage     = "jnorwood/helm-docs:v1.14.2@sha256:7e562b49ab6b1dbc50c3da8f2dd6ffa8a5c6bba327b1c6335cc15ce29267979c"
	helmSchemaImage = "ghcr.io/dadav/helm-schema:v0.24.0@sha256:efa1a88d082728c81eb1734a263b0ec0eb353b99f49dc199f22e2567bf0fef9f"
	markdownlintImage = "davidanson/markdownlint-cli2:v0.23.3@sha256:d5f3f3f04b2e285dcbcdcd13b4454d119e273e3c393a9dabd163dba4abad526d"
	trivyImage = "aquasec/trivy:0.76.0@sha256:2416d1f74045b57274df1a340eee6b510cacd73c66a6ccb8da092b117eb7d222"
	gitleaksImage     = "ghcr.io/gitleaks/gitleaks:v8.30.1@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f"
	golangciLint      = "v2.15.0" // installed via `go install`
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
