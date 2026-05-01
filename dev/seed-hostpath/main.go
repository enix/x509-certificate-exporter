// seed-hostpath writes the dev/scenarios.AllHostPath() fixtures (PEM files
// and symlinks) to a local directory tree. It is run as a privileged Job
// in the e2e cluster with a hostPath volume mounted RW at the path passed
// via --root.
//
// Idempotent: existing files are overwritten, existing symlinks are
// replaced.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/enix/x509-certificate-exporter/v4/dev/scenarios"
)

func main() {
	root := flag.String("root", "/mnt/host"+scenarios.HostPathRoot, "directory inside this Pod that maps onto the on-host HostPathRoot")
	flag.Parse()

	if err := os.MkdirAll(*root, 0o755); err != nil {
		log.Fatalf("mkdir root: %v", err)
	}

	for _, sc := range scenarios.AllHostPath() {
		if err := apply(*root, sc); err != nil {
			log.Fatalf("apply %s: %v", sc.Path, err)
		}
	}
	fmt.Printf("[seed-hostpath] %d hostPath scenario(s) written under %s\n", len(scenarios.AllHostPath()), *root)
}

// apply materialises one scenario. Path / SymlinkActualPath are absolute
// on-host paths; we rewrite the HostPathRoot prefix to root for the
// in-Pod write side, but symlink TARGETS are kept verbatim — that's what
// the on-host inode must record.
func apply(root string, sc scenarios.HostPathScenario) error {
	localPath := mapHost(root, sc.Path)
	if err := os.MkdirAll(filepath.Dir(localPath), 0o755); err != nil {
		return fmt.Errorf("mkdir parent: %w", err)
	}

	switch {
	case sc.SymlinkTarget != "" && !sc.Cert.IsZero():
		// Write the cert at SymlinkActualPath then point Path at it via
		// SymlinkTarget (verbatim).
		if sc.SymlinkActualPath == "" {
			return fmt.Errorf("symlink scenario must set SymlinkActualPath")
		}
		actualLocal := mapHost(root, sc.SymlinkActualPath)
		if err := os.MkdirAll(filepath.Dir(actualLocal), 0o755); err != nil {
			return fmt.Errorf("mkdir actual parent: %w", err)
		}
		if err := writeCert(actualLocal, sc.Cert); err != nil {
			return fmt.Errorf("write actual cert: %w", err)
		}
		if err := replaceSymlink(localPath, sc.SymlinkTarget); err != nil {
			return fmt.Errorf("replace symlink: %w", err)
		}
		fmt.Printf("[seed-hostpath] %s -> %s (cert at %s, CN=%s)\n",
			sc.Path, sc.SymlinkTarget, sc.SymlinkActualPath, sc.Cert.CN)
	case sc.SymlinkTarget != "" && sc.Cert.IsZero():
		// Escape / no-target symlink — no cert to write.
		if err := replaceSymlink(localPath, sc.SymlinkTarget); err != nil {
			return fmt.Errorf("replace symlink: %w", err)
		}
		fmt.Printf("[seed-hostpath] %s -> %s (no cert: ExpectReason=%s)\n",
			sc.Path, sc.SymlinkTarget, sc.ExpectReason)
	case sc.SymlinkTarget == "" && !sc.Cert.IsZero():
		if err := writeCert(localPath, sc.Cert); err != nil {
			return fmt.Errorf("write cert: %w", err)
		}
		fmt.Printf("[seed-hostpath] %s (cert CN=%s)\n", sc.Path, sc.Cert.CN)
	default:
		return fmt.Errorf("scenario %s: nothing to do (no symlink, no cert)", sc.Path)
	}
	return nil
}

// mapHost rewrites an absolute on-host path under HostPathRoot into the
// equivalent path under root (the directory mounted into this Pod).
func mapHost(root, hostPath string) string {
	rel := strings.TrimPrefix(hostPath, scenarios.HostPathRoot)
	rel = strings.TrimPrefix(rel, "/")
	return filepath.Join(root, rel)
}

func writeCert(p string, c scenarios.HostPathCert) error {
	cert, _, err := scenarios.Selfsigned(scenarios.CertSpec{
		CN:        c.CN,
		DNSNames:  []string{c.CN},
		NotBefore: c.NotBefore,
		NotAfter:  c.NotAfter,
		Algo:      c.Algo,
	})
	if err != nil {
		return err
	}
	return os.WriteFile(p, scenarios.EncodeCertsPEM(cert), 0o644)
}

func replaceSymlink(p, target string) error {
	tmp := p + ".tmp"
	_ = os.Remove(tmp)
	if err := os.Symlink(target, tmp); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}
