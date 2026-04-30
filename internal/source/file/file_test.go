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
