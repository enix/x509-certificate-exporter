package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"

	"dagger/x-509-ce/internal/dagger"
	"gopkg.in/yaml.v3"
)

// TestHelmRender drives two render-time checks against the chart:
//
//  1. POSITIVE — renders the chart with `test/render/all-watch-modes.yaml`
//     (covers every host-path watch mode the chart supports) and verifies
//     cross-template alignment between the rendered ConfigMap's scan
//     paths and the rendered DaemonSet's volume mounts. Catches the
//     class of bugs where the chart's volume mount path and the in-pod
//     scan path disagree on the directory boundary — resolved files
//     end up at the wrong in-pod location, the scan finds nothing, and
//     no `x509_cert_*` series are emitted. Silent for users (no error,
//     just no metrics); e2e catches it eventually in minutes — this
//     check renders the chart in seconds.
//
//  2. NEGATIVE — every `test/render/*.yaml` paired with a
//     `<name>.expect.txt` is rendered and MUST fail at template time,
//     with each non-blank, non-comment line of the .expect.txt
//     appearing as a substring in the helm stderr/stdout. Companion to
//     TestHelmFixtures, which covers schema-validation failures (`helm
//     lint`); this one covers template-fail rejections that helm lint
//     surfaces only as `[INFO] Fail:` (exit 0).
//
// Alignment rule: for every `paths:` entry in the rendered exporter
// config, the corresponding required mount is derived as
//   - the parent directory, when the entry is a literal file path; or
//   - the static prefix (segments before the first glob meta), when the
//     entry contains a shell-glob (`*`, `?`, `[`, or `**`).
// One of the DaemonSet's `volumeMounts[].mountPath` values must equal
// that required mount, or the check fails.
func (m *X509Ce) TestHelmRender(ctx context.Context) (string, error) {
	base := dag.Container().
		From(helmImage).
		WithWorkdir("/src").
		WithDirectory("/src/chart", m.Source.Directory("chart")).
		WithDirectory("/src/test/render", m.Source.Directory("test/render"))

	var report strings.Builder

	// Positive: render the comprehensive fixture and validate alignment.
	rendered, err := base.
		WithExec([]string{"helm", "template", "release-name", "chart", "--values", "test/render/all-watch-modes.yaml"}).
		Stdout(ctx)
	if err != nil {
		return "", fmt.Errorf("helm template all-watch-modes: %w", err)
	}
	posReport, err := validateMountAlignment(rendered)
	if err != nil {
		return posReport, err
	}
	fmt.Fprintf(&report, "all-watch-modes: %s", posReport)

	// Negative: every <name>.yaml under test/render/ with a paired
	// <name>.expect.txt MUST cause `helm template` to fail, and each
	// non-blank, non-comment line of the .expect.txt MUST appear as a
	// substring in the combined stderr/stdout.
	renderDir := m.Source.Directory("test/render")
	expectFiles, err := renderDir.Glob(ctx, "*.expect.txt")
	if err != nil {
		return report.String(), fmt.Errorf("globbing render fixtures: %w", err)
	}
	sort.Strings(expectFiles)
	for _, expect := range expectFiles {
		name := strings.TrimSuffix(expect, ".expect.txt")
		yamlPath := "test/render/" + name + ".yaml"
		expectContents, err := m.Source.File("test/render/" + expect).Contents(ctx)
		if err != nil {
			return report.String(), fmt.Errorf("reading %s: %w", expect, err)
		}
		var expects []string
		for _, line := range strings.Split(expectContents, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			expects = append(expects, line)
		}

		_, err = base.
			WithExec([]string{"helm", "template", "release-name", "chart", "--values", yamlPath}).
			Sync(ctx)
		if err == nil {
			return report.String(), fmt.Errorf("%s: expected helm template to fail, got success", yamlPath)
		}
		var execErr *dagger.ExecError
		if !errors.As(err, &execErr) {
			return report.String(), fmt.Errorf("%s: dagger error: %w", yamlPath, err)
		}
		combined := execErr.Stdout + "\n" + execErr.Stderr
		var missing []string
		for _, e := range expects {
			if !strings.Contains(combined, e) {
				missing = append(missing, e)
			}
		}
		if len(missing) > 0 {
			return report.String(), fmt.Errorf("%s: rendered failed (good) but stderr/stdout missing expected substrings: %v\n--- combined output ---\n%s",
				yamlPath, missing, combined)
		}
		fmt.Fprintf(&report, "%s: OK (failed with expected substrings)\n", name)
	}

	return report.String(), nil
}

// validateMountAlignment is the alignment-check core, factored out of
// the Dagger function so it can be unit-tested without spinning up a
// container.
func validateMountAlignment(rendered string) (string, error) {
	type bundle struct {
		mounts []string
		paths  []string
	}
	bundles := map[string]*bundle{} // dsName → bundle

	get := func(name string) *bundle {
		if b, ok := bundles[name]; ok {
			return b
		}
		b := &bundle{}
		bundles[name] = b
		return b
	}

	decoder := yaml.NewDecoder(strings.NewReader(rendered))
	for {
		var raw map[string]any
		err := decoder.Decode(&raw)
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("yaml decode: %w", err)
		}
		if len(raw) == 0 {
			continue
		}
		kind, _ := raw["kind"].(string)
		meta, _ := raw["metadata"].(map[string]any)
		name, _ := meta["name"].(string)

		switch kind {
		case "DaemonSet":
			b := get(name)
			spec, _ := raw["spec"].(map[string]any)
			tmpl, _ := spec["template"].(map[string]any)
			podSpec, _ := tmpl["spec"].(map[string]any)
			containers, _ := podSpec["containers"].([]any)
			for _, c := range containers {
				cm, _ := c.(map[string]any)
				vms, _ := cm["volumeMounts"].([]any)
				for _, vm := range vms {
					vmm, _ := vm.(map[string]any)
					vname, _ := vmm["name"].(string)
					mp, _ := vmm["mountPath"].(string)
					if mp == "" {
						continue
					}
					// Only consider host-path-related mounts.
					if strings.HasPrefix(vname, "dir-") ||
						strings.HasPrefix(vname, "file-") ||
						strings.HasPrefix(vname, "kube-") {
						b.mounts = append(b.mounts, path.Clean(mp))
					}
				}
			}
		case "ConfigMap":
			// The DaemonSet's ConfigMap is named the same as the DaemonSet.
			b := get(name)
			data, _ := raw["data"].(map[string]any)
			cfgStr, _ := data["config.yaml"].(string)
			if cfgStr == "" {
				continue
			}
			var cfg map[string]any
			if err := yaml.Unmarshal([]byte(cfgStr), &cfg); err != nil {
				return "", fmt.Errorf("nested config.yaml in %q: %w", name, err)
			}
			sources, _ := cfg["sources"].([]any)
			for _, s := range sources {
				sm, _ := s.(map[string]any)
				// Both `file` and `kubeconfig` sources read from on-host
				// paths that the chart binds via volume mounts; both
				// participate in the alignment check.
				kind, _ := sm["kind"].(string)
				if kind != "file" && kind != "kubeconfig" {
					continue
				}
				ps, _ := sm["paths"].([]any)
				for _, p := range ps {
					if ps, ok := p.(string); ok {
						b.paths = append(b.paths, path.Clean(ps))
					}
				}
			}
		}
	}

	// Stable iteration for deterministic output.
	var names []string
	for n := range bundles {
		names = append(names, n)
	}
	sort.Strings(names)

	var fails []string
	var ok int
	for _, name := range names {
		b := bundles[name]
		if len(b.paths) == 0 {
			continue // ConfigMap without scan paths (e.g. secretsExporter-only releases).
		}
		if len(b.mounts) == 0 {
			fails = append(fails, fmt.Sprintf("%s: configmap has %d scan path(s) but daemonset has 0 host-path volume mounts", name, len(b.paths)))
			continue
		}
		mountSet := map[string]bool{}
		for _, mp := range b.mounts {
			mountSet[mp] = true
		}
		for _, p := range b.paths {
			req := requiredMount(p)
			if !mountSet[req] {
				fails = append(fails, fmt.Sprintf("%s: scan path %q requires mountPath %q\n        available mounts: %v", name, p, req, b.mounts))
			} else {
				ok++
			}
		}
	}

	if len(fails) > 0 {
		// Bundle the details into the error itself — the Dagger CLI
		// suppresses the (string, _) tuple's first element when the
		// second is non-nil, so without this the operator only sees
		// "1 issue(s)" with no actionable context.
		return "", fmt.Errorf("chart render misaligned: %d issue(s) across %d daemonset(s):\n  %s",
			len(fails), len(bundles), strings.Join(fails, "\n  "))
	}
	return fmt.Sprintf("OK — %d scan path(s) aligned across %d daemonset(s)\n", ok, len(bundles)), nil
}

// requiredMount returns the mountPath that must exist for the given
// configmap scan path. See TestHelmRender for the rule.
func requiredMount(p string) string {
	p = path.Clean(p)
	parts := strings.Split(p, "/")
	for i, seg := range parts {
		if seg == "**" || strings.ContainsAny(seg, "*?[") {
			// First glob segment found — mount is everything before it.
			return path.Clean("/" + strings.Join(parts[:i], "/"))
		}
	}
	// No glob — literal file path. Mount is the parent directory.
	return path.Dir(p)
}
