package main

import (
	"context"
	"fmt"

	"dagger/x-509-ce/internal/dagger"
)

// Gitleaks scans the working tree for committed secrets (`gitleaks
// dir`, not git history: .git is excluded from the source and the
// delivered file contents are what matter). Exits non-zero on any
// finding, which Dagger surfaces as an error and CI as a failed job;
// findings print (redacted) to the log.
func (m *X509Ce) Gitleaks(
	ctx context.Context,
	// Working tree to scan. Drops build artifacts and vendored trees
	// that would only add scan noise, but — unlike the module-wide
	// source filter — KEEPS dagger/ so hand-written code stays in scope.
	// +defaultPath="/"
	// +ignore=[".git/", "dist/", "node_modules/", "kubeconfig.yaml", "renovate-debug.log"]
	source *dagger.Directory,
) (string, error) {
	return dag.Container().
		From(gitleaksImage).
		WithMountedDirectory("/scan", source).
		// Workdir at the scan root so finding paths/fingerprints are
		// relative (not /scan/...) and any `.gitleaks.toml` / inline
		// `//gitleaks:allow` directives in the tree resolve correctly.
		WithWorkdir("/scan").
		WithExec([]string{
			"gitleaks", "dir", ".",
			"--no-banner",
			"--redact",
			"--verbose",
			"--exit-code", "1",
		}).
		Stdout(ctx)
}

// Govulncheck runs Go's reachability-based CVE scanner. The
// vulnerability database is fetched from vuln.go.dev at run time —
// dataset is never stale. The analyzer itself tracks @latest;
// tamper-resistance is via the Go module proxy + checksum DB.
func (m *X509Ce) Govulncheck(ctx context.Context) (string, error) {
	return goBase(m.Source).
		WithExec([]string{"go", "install", "golang.org/x/vuln/cmd/govulncheck@" + govulncheckPath}).
		WithExec([]string{"govulncheck", "./..."}).
		Stdout(ctx)
}

// Trivy runs Aqua Security's Trivy scanner against the working tree.
// One function, two scan families:
//
//   - scanType=fs      → filesystem scan: detects vulnerabilities in
//     Go module deps, lockfiles, OS packages,
//     etc. Use for dependency CVE checks.
//   - scanType=config  → IaC misconfig scan: catches security
//     misconfigurations in Helm / Kubernetes /
//     Dockerfile / Terraform manifests. Use
//     against `chart/`.
//
// Threshold is HIGH,CRITICAL with a non-zero exit on any finding.
// The Trivy DB cache is mounted as a Dagger CacheVolume so successive
// runs don't re-download (~50 MB).
func (m *X509Ce) Trivy(
	ctx context.Context,
	// Scan family: "fs" or "config".
	scanType string,
	// Path inside the source to scan. Use "." (default) for whole-repo
	// fs scans, or e.g. "chart" for a chart-only config scan.
	// +optional
	// +default="."
	scanRef string,
	// For "fs" scans: skip CVEs whose upstream has no patch yet —
	// avoids alert fatigue on findings nobody can act on. Ignored for
	// "config" scans. Default matches the previous CI policy.
	// +optional
	// +default=true
	ignoreUnfixed bool,
) (string, error) {
	switch scanType {
	case "fs", "config":
	default:
		return "", fmt.Errorf(`unknown scan type %q (expected "fs" or "config")`, scanType)
	}

	args := []string{
		"trivy", scanType,
		"--severity", "HIGH,CRITICAL",
		"--exit-code", "1",
		// Always points at the repo-root .trivyignore. Trivy's default
		// is to look in the scan root, which changes with --scan-ref —
		// pinning it explicitly here keeps suppressions in one place.
		"--ignorefile", "/src/.trivyignore",
	}
	if scanType == "fs" && ignoreUnfixed {
		args = append(args, "--ignore-unfixed")
	}
	target := "/src"
	if scanRef != "" && scanRef != "." {
		target = "/src/" + scanRef
	}
	args = append(args, target)

	return dag.Container().
		From(trivyImage).
		WithMountedCache("/root/.cache/trivy", dag.CacheVolume("trivy")).
		WithDirectory("/src", m.Source).
		WithExec(args).
		Stdout(ctx)
}
