package file

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	encpem "encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/enix/x509-certificate-exporter/v4/internal/fileglob"
	"github.com/enix/x509-certificate-exporter/v4/pkg/cert"
	"github.com/enix/x509-certificate-exporter/v4/pkg/cert/pem"
)

func nopLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

type fakeSink struct {
	mu     sync.Mutex
	upsert []cert.Bundle
	delete []cert.SourceRef
}

func (s *fakeSink) Upsert(b cert.Bundle) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.upsert = append(s.upsert, b)
}
func (s *fakeSink) Delete(r cert.SourceRef) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.delete = append(s.delete, r)
}

func writePEM(t *testing.T, path string, cn string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	out := encpem.EncodeToMemory(&encpem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestRunOnceDiscoversAndDeletes(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.pem")
	b := filepath.Join(dir, "b.pem")
	writePEM(t, a, "a")
	writePEM(t, b, "b")
	pat, _ := fileglob.Compile(filepath.Join(dir, "*.pem"))
	sink := &fakeSink{}
	src := New(Options{
		Name:           "test",
		Patterns:       []fileglob.Pattern{pat},
		Formats:        []cert.FormatParser{pem.New()},
		FollowSymlinks: true,
		Jitter:         0,
	}, nopLogger())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = src.Run(ctx, sink) }()
	// give it a beat to do the initial sync
	time.Sleep(50 * time.Millisecond)
	cancel()

	sink.mu.Lock()
	upserts := append([]cert.Bundle{}, sink.upsert...)
	sink.mu.Unlock()
	if len(upserts) < 2 {
		t.Fatalf("want >=2 upserts, got %d", len(upserts))
	}
	for _, b := range upserts {
		if len(b.Items) == 0 || b.Items[0].Cert == nil {
			t.Fatalf("bad bundle: %+v", b)
		}
	}
}

func TestRunOnceReadError(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.pem")
	_ = os.WriteFile(bad, []byte("not a cert"), 0o600)
	pat, _ := fileglob.Compile(filepath.Join(dir, "*.pem"))
	sink := &fakeSink{}
	src := New(Options{
		Name: "test", Patterns: []fileglob.Pattern{pat},
		Formats: []cert.FormatParser{pem.New()},
		Jitter:  0, FollowSymlinks: true,
	}, nopLogger())
	src.runOnce(context.Background(), sink, true)
	if len(sink.upsert) == 0 {
		t.Fatal("expected an upsert")
	}
	if !sink.upsert[0].HasFatalError() {
		t.Fatal("expected fatal error in bundle")
	}
}

type errReader struct{ err error }

func (e errReader) Read(p string) ([]byte, error) { return nil, e.err }

func TestProcessEntryReadFailureReason(t *testing.T) {
	src := New(Options{Name: "x", Formats: []cert.FormatParser{pem.New()}}, nopLogger())
	src.opts.Reader = errReader{err: os.ErrPermission}
	sink := &fakeSink{}
	src.processEntry(context.Background(), sink, fileglob.Entry{Path: "/a"})
	if len(sink.upsert) != 1 || sink.upsert[0].Errors[0].Reason != cert.ReasonPermissionDenied {
		t.Fatalf("got %v", sink.upsert)
	}
	src.opts.Reader = errReader{err: os.ErrNotExist}
	sink.upsert = nil
	src.processEntry(context.Background(), sink, fileglob.Entry{Path: "/a"})
	if sink.upsert[0].Errors[0].Reason != cert.ReasonNotFound {
		t.Fail()
	}
	src.opts.Reader = errReader{err: errors.New("io broke")}
	sink.upsert = nil
	src.processEntry(context.Background(), sink, fileglob.Entry{Path: "/a"})
	if sink.upsert[0].Errors[0].Reason != cert.ReasonReadFailed {
		t.Fail()
	}
}

func TestSkipUnchanged(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.pem")
	writePEM(t, a, "a")
	pat, _ := fileglob.Compile(filepath.Join(dir, "*.pem"))
	src := New(Options{
		Name: "x", Patterns: []fileglob.Pattern{pat},
		Formats:        []cert.FormatParser{pem.New()},
		FollowSymlinks: true,
		SkipUnchanged:  true,
		Jitter:         0,
	}, nopLogger())
	sink1 := &fakeSink{}
	src.runOnce(context.Background(), sink1, true)
	if len(sink1.upsert) != 1 {
		t.Fatalf("first run should upsert once: %d", len(sink1.upsert))
	}
	sink2 := &fakeSink{}
	src.runOnce(context.Background(), sink2, false)
	if len(sink2.upsert) != 0 {
		t.Fatalf("second run with no change should skip: %d", len(sink2.upsert))
	}
}

func TestFirstSyncSignal(t *testing.T) {
	dir := t.TempDir()
	pat, _ := fileglob.Compile(filepath.Join(dir, "*.pem"))
	done := make(chan struct{})
	src := New(Options{
		Name: "x", Patterns: []fileglob.Pattern{pat},
		Formats: []cert.FormatParser{pem.New()}, FirstSyncDone: done,
	}, nopLogger())
	src.runOnce(context.Background(), &fakeSink{}, true)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("FirstSyncDone never closed")
	}
}

func TestNameAndDefaults(t *testing.T) {
	src := New(Options{Name: "x"}, nopLogger())
	if src.Name() != "x" {
		t.Fail()
	}
}

// swapSymlinkAtomic mirrors what certbot/kubelet do on cert renewal:
// create a fresh symlink under a temp name pointing at `target`, then
// rename it over `dst`. The visible inode at `dst` is brand new and
// carries a fresh mtime stamped at creation time.
func swapSymlinkAtomic(t *testing.T, dst, target string) {
	t.Helper()
	tmp := dst + ".tmp"
	if err := os.Symlink(target, tmp); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, dst); err != nil {
		t.Fatal(err)
	}
}

// fsHasSubSecondMtime probes whether the filesystem backing `dir` stores
// sub-second mtime values. Linux ext4/tmpfs/btrfs/zfs/xfs do; HFS+ on
// older macOS and some FAT-family filesystems don't (1s granularity).
// When sub-second resolution is missing, two same-second operations
// produce identical mtimes — meaningful only for the test below, which
// needs a guaranteed mtime delta between two successive symlink swaps.
func fsHasSubSecondMtime(t *testing.T, dir string) bool {
	t.Helper()
	probe := filepath.Join(dir, ".mtime-probe")
	if err := os.WriteFile(probe, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(probe) }()
	want := time.Unix(0, 123456789) // arbitrary non-zero sub-second value
	if err := os.Chtimes(probe, want, want); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(probe)
	if err != nil {
		t.Fatal(err)
	}
	return info.ModTime().Nanosecond() == want.Nanosecond()
}

// TestSkipUnchangedSymlinkTargetSwap covers the certbot / kubelet renewal
// pattern: a watched path is a symlink whose target is atomically swapped
// onto a new file. The (mtime, size) cache key must invalidate via either
// branch independently. We exercise both:
//
//  1. size branch — swap to a target with a different path-string length
//     so the symlink's stored size differs. Mtime may or may not collide
//     under coarse-resolution filesystems; size alone must invalidate.
//  2. mtime branch — swap back to a target with the SAME path string, so
//     size is identical. Only mtime can differ. Probe the filesystem
//     mtime resolution; sleep past 1 s when sub-second support is absent
//     so two consecutive swaps are guaranteed to produce distinct mtimes.
func TestSkipUnchangedSymlinkTargetSwap(t *testing.T) {
	dir := t.TempDir()
	archive := filepath.Join(dir, "archive")
	if err := os.Mkdir(archive, 0o755); err != nil {
		t.Fatal(err)
	}

	// Three real PEMs. `long` and `short` have different path-string
	// lengths so the symlink's size differs across branch 1; `replaced`
	// has the same path as `short` but holds a fresh certificate so we
	// can assert the bundle was actually re-parsed in branch 2.
	long := filepath.Join(archive, "fullchain-renewed-1.pem")
	short := filepath.Join(archive, "f.pem")
	if len(long) == len(short) {
		t.Fatalf("test bug: long and short paths must differ in length")
	}
	writePEM(t, long, "v1")
	writePEM(t, short, "v2")

	live := filepath.Join(dir, "fullchain.pem")
	if err := os.Symlink(long, live); err != nil {
		t.Fatal(err)
	}

	pat, _ := fileglob.Compile(live)
	src := New(Options{
		Name:           "x",
		Patterns:       []fileglob.Pattern{pat},
		Formats:        []cert.FormatParser{pem.New()},
		FollowSymlinks: true,
		SkipUnchanged:  true,
		Jitter:         0,
	}, nopLogger())

	// Initial sync: one bundle for `live` parsed from `long`.
	sink1 := &fakeSink{}
	src.runOnce(context.Background(), sink1, true)
	if len(sink1.upsert) != 1 {
		t.Fatalf("first run: want 1 upsert, got %d", len(sink1.upsert))
	}

	// === Branch 1: size differs ===
	// Swap onto `short` (different path length → different symlink size).
	swapSymlinkAtomic(t, live, short)
	sink2 := &fakeSink{}
	src.runOnce(context.Background(), sink2, false)
	if len(sink2.upsert) != 1 {
		t.Fatalf("size branch: swap to shorter target should re-parse, got %d upserts", len(sink2.upsert))
	}

	// === Branch 2: only mtime differs ===
	// Re-swap onto `short` again. Symlink string length is identical, so
	// size is unchanged; only mtime can differ. Force a >1 s gap when the
	// filesystem rounds mtime to second granularity so the new symlink's
	// mtime is guaranteed to differ from the one cached above.
	if !fsHasSubSecondMtime(t, dir) {
		time.Sleep(1100 * time.Millisecond)
	}
	swapSymlinkAtomic(t, live, short)
	sink3 := &fakeSink{}
	src.runOnce(context.Background(), sink3, false)
	if len(sink3.upsert) != 1 {
		t.Fatalf("mtime branch: same-target swap should re-parse, got %d upserts", len(sink3.upsert))
	}
}

// TestPathMappingResolvesAbsoluteSymlink covers the kubelet-PKI-via-DaemonSet
// scenario: the watched symlink records an absolute path in the host's
// namespace; the file source must rewrite it through the configured
// PathMapping to find the file under the in-pod mount.
func TestPathMappingResolvesAbsoluteSymlink(t *testing.T) {
	root := t.TempDir()
	// Mimics the chart layout: the host dir /var/lib/kubelet/pki is bind-
	// mounted at $TMPDIR/watch/file-X/var/lib/kubelet/pki inside the pod.
	const hostPrefix = "/var/lib/kubelet/pki"
	podPrefix := filepath.Join(root, "watch/file-X/var/lib/kubelet/pki")
	if err := os.MkdirAll(podPrefix, 0o755); err != nil {
		t.Fatal(err)
	}
	dated := filepath.Join(podPrefix, "kubelet-client-2024.pem")
	writePEM(t, dated, "kubelet-client")
	current := filepath.Join(podPrefix, "kubelet-client-current.pem")
	// Symlink target as kubelet records it: an absolute host-namespace path.
	if err := os.Symlink(hostPrefix+"/kubelet-client-2024.pem", current); err != nil {
		t.Fatal(err)
	}

	pat, _ := fileglob.Compile(current)
	src := New(Options{
		Name:           "x",
		Patterns:       []fileglob.Pattern{pat},
		Formats:        []cert.FormatParser{pem.New()},
		FollowSymlinks: true,
		Jitter:         0,
		PathMappings: []fileglob.PathMapping{
			{From: hostPrefix, To: podPrefix},
		},
	}, nopLogger())

	sink := &fakeSink{}
	src.runOnce(context.Background(), sink, true)

	if len(sink.upsert) != 1 {
		t.Fatalf("want 1 upsert, got %d: %+v", len(sink.upsert), sink.upsert)
	}
	b := sink.upsert[0]
	if len(b.Errors) != 0 {
		t.Fatalf("unexpected errors in bundle: %+v", b.Errors)
	}
	if len(b.Items) == 0 || b.Items[0].Cert == nil {
		t.Fatalf("expected one parsed certificate, got %+v", b)
	}
	if cn := b.Items[0].Cert.Subject.CommonName; cn != "kubelet-client" {
		t.Errorf("CN: want kubelet-client, got %q", cn)
	}
}

// TestRelativeSymlinkEscapeRejected verifies that a relative symlink with
// enough dot-dot segments to escape the configured scope is reported as
// out_of_scope_symlink and never reaches the parser.
func TestRelativeSymlinkEscapeRejected(t *testing.T) {
	root := t.TempDir()
	podPrefix := filepath.Join(root, "watch/file-X/var/lib/kubelet/pki")
	if err := os.MkdirAll(podPrefix, 0o755); err != nil {
		t.Fatal(err)
	}
	// Place a real (private-but-not-cert) file outside the scope so the
	// test fails loudly if the walker were to read it.
	outsideDir := filepath.Join(root, "outside")
	if err := os.MkdirAll(outsideDir, 0o755); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(outsideDir, "secret")
	if err := os.WriteFile(outside, []byte("must-not-be-read"), 0o600); err != nil {
		t.Fatal(err)
	}

	link := filepath.Join(podPrefix, "current.pem")
	// "../../../" + ... + "/outside/secret" — enough levels to exit podPrefix
	// regardless of root's depth, since filepath.Clean caps at /.
	rel := strings.Repeat("../", 32) + strings.TrimPrefix(outside, "/")
	if err := os.Symlink(rel, link); err != nil {
		t.Fatal(err)
	}

	pat, _ := fileglob.Compile(link)
	src := New(Options{
		Name:           "x",
		Patterns:       []fileglob.Pattern{pat},
		Formats:        []cert.FormatParser{pem.New()},
		FollowSymlinks: true,
		Jitter:         0,
		PathMappings: []fileglob.PathMapping{
			{From: "/var/lib/kubelet/pki", To: podPrefix},
		},
	}, nopLogger())

	sink := &fakeSink{}
	src.runOnce(context.Background(), sink, true)

	if len(sink.upsert) != 1 {
		t.Fatalf("want exactly 1 (error) bundle, got %d: %+v", len(sink.upsert), sink.upsert)
	}
	b := sink.upsert[0]
	if len(b.Items) != 0 {
		t.Fatalf("escaping symlink must not yield parsed items: %+v", b)
	}
	if len(b.Errors) != 1 || b.Errors[0].Reason != "out_of_scope_symlink" {
		t.Fatalf("want one out_of_scope_symlink error, got %+v", b.Errors)
	}
}
