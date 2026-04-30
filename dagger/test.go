package main

import (
	"context"
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
