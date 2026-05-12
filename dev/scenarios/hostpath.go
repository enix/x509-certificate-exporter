// HostPath scenarios — files to be materialised onto cluster nodes by the
// seed-hostpath Job, watched by the chart's hostPathsExporter DaemonSet,
// and asserted on by the e2e test.
//
// All paths used here are rooted at HostPathRoot, which the Job mounts as
// a hostPath volume in RW mode. Using a dedicated subtree keeps the test
// fixtures away from anything real on the node and makes cleanup a `rm
// -rf` away (k3d's node container is throw-away anyway).
package scenarios

import (
	"path"
	"sync"
	"time"
)

// HostPathRoot is the on-host directory the seed Job populates and the
// chart-deployed DaemonSet mounts. Test/e2e/values.yaml configures
// hostPathsExporter.daemonSets.nodes to watch a subtree under this root.
const HostPathRoot = "/var/lib/x509ce-e2e"

// HostPathScenario describes one file (or symlink) to write under
// HostPathRoot. The CertSpec, when non-zero, makes the seed materialise
// a self-signed PEM either directly at Path or at SymlinkActualPath.
//
//   - Plain file: SymlinkTarget == ""
//   - Relative symlink (kubelet-rotation pattern): SymlinkTarget is a
//     relative path; the seed writes the cert at SymlinkActualPath
//   - Absolute host-path symlink (the path-mappings smoke test):
//     SymlinkTarget is an absolute path within HostPathRoot — recorded
//     verbatim, the in-pod walker only resolves it via pathMappings
//   - Escape symlink (containment smoke test): SymlinkTarget contains
//     enough ".." segments to leave HostPathRoot. No SymlinkActualPath
//     is needed; the walker emits out_of_scope_symlink before any read.
type HostPathScenario struct {
	// Path is the absolute on-host path of the file or symlink. Must
	// live under HostPathRoot.
	Path string

	// SymlinkTarget, when non-empty, makes Path a symlink with this
	// literal target string (relative or absolute, the seed does not
	// transform it).
	SymlinkTarget string
	// SymlinkActualPath is the absolute on-host path the seed writes
	// the certificate to. Required when SymlinkTarget is non-empty
	// and ExpectReason is empty. Ignored otherwise.
	SymlinkActualPath string

	// Cert describes the self-signed PEM to write. Zero value means
	// "do not write a cert" — the only such case is the escape
	// symlink scenario.
	Cert HostPathCert

	// Watched is true when the chart's hostPathsExporter is configured
	// to surface this path; false-cases verify exclusion.
	Watched bool

	// FilepathLabel is the value of the `filepath` Prometheus label
	// expected on the resulting x509_cert_* series. The chart strips
	// the in-pod /mnt/watch/<kind>-<sha1> prefix via the source's
	// trimPathComponents=3, so the label reads as the original on-host
	// path WITHOUT its leading slash (e.g. "var/lib/x509ce-e2e/...").
	// Empty for ExpectReason scenarios.
	FilepathLabel string

	// SubjectCN is the CN to assert on the metric series. Empty for
	// ExpectReason scenarios.
	SubjectCN string

	// ExpectReason, when non-empty, asserts the source emits
	// x509_source_errors_total{reason=ExpectReason} > 0 instead of a
	// cert series.
	ExpectReason ParseError
}

// HostPathCert is a slim cert spec — same shape as CertSpec used elsewhere
// but fixed to the fields we exercise here.
type HostPathCert struct {
	CN        string
	NotBefore time.Time
	NotAfter  time.Time
	Algo      Algo
	Lifecycle Lifecycle
}

// IsZero returns true when no cert is to be written (escape scenario).
func (c HostPathCert) IsZero() bool { return c.CN == "" }

var (
	hostPathOnce   sync.Once
	hostPathCached []HostPathScenario
)

// AllHostPath returns the hostPath scenarios, computed once per process.
func AllHostPath() []HostPathScenario {
	hostPathOnce.Do(buildHostPath)
	return hostPathCached
}

func buildHostPath() {
	now := time.Now().UTC().Truncate(time.Second)
	year := 365 * 24 * time.Hour
	pkiDir := path.Join(HostPathRoot, "pki")

	var sc []HostPathScenario

	// 1. Plain file — sanity check that the chart's DaemonSet + watchFiles
	//    mounts a single file correctly.
	sc = append(sc, HostPathScenario{
		Path:          path.Join(pkiDir, "static.pem"),
		Watched:       true,
		FilepathLabel: trimLabel(path.Join(pkiDir, "static.pem")),
		SubjectCN:     "static.example.test",
		Cert: HostPathCert{
			CN: "static.example.test", Algo: AlgoECDSAP256,
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(year),
			Lifecycle: LifecycleValid,
		},
	})

	// 2. Relative symlink — kubelet rotation pattern. Symlink at
	//    `live.pem` -> `rotated-2026.pem` (same dir, no path mapping
	//    needed, but exercises the relative-symlink resolution path).
	sc = append(sc, HostPathScenario{
		Path:              path.Join(pkiDir, "kubelet-client-current.pem"),
		SymlinkTarget:     "kubelet-client-2026.pem",
		SymlinkActualPath: path.Join(pkiDir, "kubelet-client-2026.pem"),
		Watched:           true,
		FilepathLabel:     trimLabel(path.Join(pkiDir, "kubelet-client-current.pem")),
		SubjectCN:         "kubelet-client",
		Cert: HostPathCert{
			CN: "kubelet-client", Algo: AlgoECDSAP256,
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(year),
			Lifecycle: LifecycleValid,
		},
	})

	// 3. Absolute host-path symlink — exercises the chart's pathMappings.
	//    The symlink's recorded target is the on-host path (which doesn't
	//    exist verbatim from inside the pod); pathMappings rewrites the
	//    /var/lib/x509ce-e2e/pki prefix to the in-pod mount path.
	absDated := path.Join(pkiDir, "absolute-target-2026.pem")
	sc = append(sc, HostPathScenario{
		Path:              path.Join(pkiDir, "absolute-link.pem"),
		SymlinkTarget:     absDated, // absolute on-host path
		SymlinkActualPath: absDated,
		Watched:           true,
		FilepathLabel:     trimLabel(path.Join(pkiDir, "absolute-link.pem")),
		SubjectCN:         "abs-link.example.test",
		Cert: HostPathCert{
			CN: "abs-link.example.test", Algo: AlgoECDSAP256,
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(year),
			Lifecycle: LifecycleValid,
		},
	})

	// 4. Escape symlink — relative target with enough ".." segments to
	//    leave HostPathRoot. Containment must reject this with the
	//    "out_of_scope_symlink" reason; no cert is materialised.
	sc = append(sc, HostPathScenario{
		Path:          path.Join(pkiDir, "escape.pem"),
		SymlinkTarget: "../../../../../../etc/passwd",
		Watched:       true,
		ExpectReason:  "out_of_scope_symlink",
	})

	// 5. Recursive subtree — file two levels deep under a separate root.
	//    test/e2e/values.yaml configures the chart's `watchDirectories`
	//    with a `**` glob anchored at HostPathRoot/recursive-pki, which
	//    exercises the static-prefix extraction in the chart template
	//    (HostPath volume + mountPath bind the smallest containing dir,
	//    not the wildcard tail) and the fileglob walker.
	recursiveLeaf := path.Join(HostPathRoot, "recursive-pki", "team-alpha", "service-x", "leaf.pem")
	sc = append(sc, HostPathScenario{
		Path:          recursiveLeaf,
		Watched:       true,
		FilepathLabel: trimLabel(recursiveLeaf),
		SubjectCN:     "recursive-leaf.example.test",
		Cert: HostPathCert{
			CN: "recursive-leaf.example.test", Algo: AlgoECDSAP256,
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(year),
			Lifecycle: LifecycleValid,
		},
	})

	// 6. Recursive subtree with a literal directory segment AFTER `**`
	//    (`recursive-pki/**/tls/*.pem`). Verifies the walker still
	//    descends through arbitrary subtrees while requiring the `tls`
	//    component just above the leaf. Shares the same static prefix
	//    as scenario 5, so the chart binds a single HostPath volume.
	recursiveMidLeaf := path.Join(HostPathRoot, "recursive-pki", "team-beta", "service-y", "tls", "inner.pem")
	sc = append(sc, HostPathScenario{
		Path:          recursiveMidLeaf,
		Watched:       true,
		FilepathLabel: trimLabel(recursiveMidLeaf),
		SubjectCN:     "recursive-mid-leaf.example.test",
		Cert: HostPathCert{
			CN: "recursive-mid-leaf.example.test", Algo: AlgoECDSAP256,
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(year),
			Lifecycle: LifecycleValid,
		},
	})

	// 7. watchSpecificExtensionDirectories — file at
	//    HostPathRoot/extdir/leaf.crt, configured via
	//    {directory: HostPathRoot/extdir, extension: crt}. Regression
	//    guard: if the chart's mountPath uses the parent of the
	//    directory (`.directory | dir`) instead of the directory
	//    itself, the file ends up at the wrong in-pod path and the
	//    scan finds nothing. This scenario then has no series, and
	//    the e2e suite fails the Watched=true assertion.
	extDirLeaf := path.Join(HostPathRoot, "extdir", "leaf.crt")
	sc = append(sc, HostPathScenario{
		Path:          extDirLeaf,
		Watched:       true,
		FilepathLabel: trimLabel(extDirLeaf),
		SubjectCN:     "ext-leaf.example.test",
		Cert: HostPathCert{
			CN: "ext-leaf.example.test", Algo: AlgoECDSAP256,
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(year),
			Lifecycle: LifecycleValid,
		},
	})

	hostPathCached = sc
}

// trimLabel mirrors the chart's metrics.trimPathComponents=3 transformation
// applied to host-path file sources: the in-pod /mnt/watch/<kind>-<sha1>
// prefix is stripped (3 path components), and the registry's trimPath helper
// re-prepends the leading slash. So a hostPath of `/var/lib/x509ce-e2e/...`
// — mounted in-pod at `/mnt/watch/file-<sha1>/var/lib/x509ce-e2e/...` —
// surfaces in metrics as exactly `/var/lib/x509ce-e2e/...`.
func trimLabel(absPath string) string { return absPath }
