package kubeconfig

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	encpem "encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/enix/x509-certificate-exporter/v4/pkg/cert"
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

func makeCert(t *testing.T, cn string) []byte {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	return encpem.EncodeToMemory(&encpem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestKubeconfigEmbeddedData(t *testing.T) {
	dir := t.TempDir()
	caPEM := makeCert(t, "ca")
	clientPEM := makeCert(t, "admin")
	yaml := "apiVersion: v1\nkind: Config\nclusters:\n- name: c1\n  cluster:\n    certificate-authority-data: " +
		base64.StdEncoding.EncodeToString(caPEM) +
		"\nusers:\n- name: u1\n  user:\n    client-certificate-data: " +
		base64.StdEncoding.EncodeToString(clientPEM) + "\n"
	p := filepath.Join(dir, "kc.yaml")
	if err := os.WriteFile(p, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	src := New(Options{Name: "kc", Paths: []string{p}}, nopLogger())
	sink := &fakeSink{}
	src.runOnce(context.Background(), sink, true)
	if len(sink.upsert) != 2 {
		t.Fatalf("want 2 upserts, got %d", len(sink.upsert))
	}
	gotKinds := map[string]bool{}
	for _, b := range sink.upsert {
		gotKinds[b.Source.Attributes["embedded_kind"]] = true
	}
	if !gotKinds["cluster"] || !gotKinds["user"] {
		t.Fatalf("missing kinds: %v", gotKinds)
	}
}

func TestKubeconfigFileRef(t *testing.T) {
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(caPath, makeCert(t, "ca"), 0o600); err != nil {
		t.Fatal(err)
	}
	yaml := "clusters:\n- name: c1\n  cluster:\n    certificate-authority: " + caPath + "\n"
	p := filepath.Join(dir, "kc.yaml")
	if err := os.WriteFile(p, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	src := New(Options{Name: "kc", Paths: []string{p}}, nopLogger())
	sink := &fakeSink{}
	src.runOnce(context.Background(), sink, true)
	if len(sink.upsert) != 1 {
		t.Fatalf("want 1 upsert, got %d", len(sink.upsert))
	}
	if sink.upsert[0].HasFatalError() {
		t.Fatalf("unexpected error: %v", sink.upsert[0].Errors)
	}
}

func TestKubeconfigBadPath(t *testing.T) {
	src := New(Options{Name: "kc", Paths: []string{"/nope.yaml"}}, nopLogger())
	sink := &fakeSink{}
	src.runOnce(context.Background(), sink, true)
	if len(sink.upsert) != 1 {
		t.Fatalf("want 1 upsert, got %d", len(sink.upsert))
	}
	if !sink.upsert[0].HasFatalError() {
		t.Fatal("expected fatal")
	}
}

func TestKubeconfigBadYAML(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "x")
	if err := os.WriteFile(p, []byte("not-yaml: ["), 0o600); err != nil {
		t.Fatal(err)
	}
	src := New(Options{Name: "kc", Paths: []string{p}}, nopLogger())
	sink := &fakeSink{}
	src.runOnce(context.Background(), sink, true)
	if !sink.upsert[0].HasFatalError() {
		t.Fail()
	}
	if sink.upsert[0].Errors[0].Reason != cert.ReasonDecodeFailed {
		t.Fail()
	}
}

func TestKubeconfigBadBase64(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "x")
	if err := os.WriteFile(p, []byte("clusters:\n- name: c1\n  cluster:\n    certificate-authority-data: \"!!!\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	src := New(Options{Name: "kc", Paths: []string{p}}, nopLogger())
	sink := &fakeSink{}
	src.runOnce(context.Background(), sink, true)
	if !sink.upsert[0].HasFatalError() {
		t.Fatal("expected error")
	}
}

func TestKubeconfigDeleteOnDisappear(t *testing.T) {
	dir := t.TempDir()
	caPEM := makeCert(t, "ca")
	yaml := "clusters:\n- name: c1\n  cluster:\n    certificate-authority-data: " +
		base64.StdEncoding.EncodeToString(caPEM) + "\n"
	p := filepath.Join(dir, "kc.yaml")
	if err := os.WriteFile(p, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	src := New(Options{Name: "kc", Paths: []string{p}}, nopLogger())
	sink := &fakeSink{}
	src.runOnce(context.Background(), sink, true)
	// Now point at a different path so the previous one is "stale".
	src.opts.Paths = []string{filepath.Join(dir, "missing")}
	src.runOnce(context.Background(), sink, false)
	if len(sink.delete) == 0 {
		t.Fatalf("expected at least one delete, got %d", len(sink.delete))
	}
}

func TestNameAndFirstSyncSignal(t *testing.T) {
	done := make(chan struct{})
	src := New(Options{Name: "kc", FirstSyncDone: done}, nopLogger())
	if src.Name() != "kc" {
		t.Fail()
	}
	src.runOnce(context.Background(), &fakeSink{}, true)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("FirstSyncDone never closed")
	}
}
