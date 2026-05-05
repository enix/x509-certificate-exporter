package k8s

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	encpem "encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"regexp"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

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

func makeCertPEM(t *testing.T) []byte {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	return encpem.EncodeToMemory(&encpem.Block{Type: "CERTIFICATE", Bytes: der})
}

func waitFor(t *testing.T, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for: %s", msg)
}

func TestSecretsWatchEmits(t *testing.T) {
	pemData := makeCertPEM(t)
	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "s1", Namespace: "ns", Labels: map[string]string{"app": "demo"}},
		Type:       corev1.SecretTypeTLS,
		Data:       map[string][]byte{"tls.crt": pemData, "tls.key": []byte("ignored")},
	}
	client := fake.NewSimpleClientset(sec)
	src := New(Options{
		Name: "kube", Client: client, ResyncEvery: 10 * time.Minute,
		SecretRules: []SecretTypeRule{{
			Type: "kubernetes.io/tls", KeyRe: regexp.MustCompile(`^tls\.crt$`), Parser: pem.New(),
		}},
		ExposedSecretLabels: []string{"app"},
	}, nopLogger())
	sink := &fakeSink{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = src.Run(ctx, sink) }()

	waitFor(t, func() bool {
		sink.mu.Lock()
		defer sink.mu.Unlock()
		return len(sink.upsert) >= 1
	}, "secret upsert")

	sink.mu.Lock()
	b := sink.upsert[0]
	sink.mu.Unlock()
	if b.Source.Kind != "kube-secret" || b.Source.Location != "ns/s1" || b.Source.Key != "tls.crt" {
		t.Fatalf("unexpected ref %+v", b.Source)
	}
	if b.Source.Attributes["secret_label/app"] != "demo" {
		t.Fatalf("missing exposed label, attrs=%v", b.Source.Attributes)
	}
	if len(b.Items) != 1 {
		t.Fatalf("want 1 item, got %d", len(b.Items))
	}
}

func TestSecretsWatchHandlesDelete(t *testing.T) {
	pemData := makeCertPEM(t)
	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "s1", Namespace: "ns"},
		Type:       corev1.SecretTypeTLS,
		Data:       map[string][]byte{"tls.crt": pemData},
	}
	client := fake.NewSimpleClientset(sec)
	src := New(Options{
		Name: "k", Client: client, ResyncEvery: 10 * time.Minute,
		SecretRules: []SecretTypeRule{{
			Type: "kubernetes.io/tls", KeyRe: regexp.MustCompile(`^tls\.crt$`), Parser: pem.New(),
		}},
	}, nopLogger())
	sink := &fakeSink{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = src.Run(ctx, sink) }()
	waitFor(t, func() bool {
		sink.mu.Lock()
		defer sink.mu.Unlock()
		return len(sink.upsert) >= 1
	}, "initial upsert")

	if err := client.CoreV1().Secrets("ns").Delete(ctx, "s1", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool {
		sink.mu.Lock()
		defer sink.mu.Unlock()
		return len(sink.delete) >= 1
	}, "delete event")
}

func TestConfigMapsWatchEmits(t *testing.T) {
	pemData := string(makeCertPEM(t))
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "c1", Namespace: "ns"},
		Data:       map[string]string{"ca.crt": pemData, "ignored": "x"},
	}
	client := fake.NewSimpleClientset(cm)
	src := New(Options{
		Name: "kube", Client: client, ResyncEvery: 10 * time.Minute,
		ConfigMapRules: []SecretTypeRule{{KeyRe: regexp.MustCompile(`\.crt$`), Parser: pem.New()}},
	}, nopLogger())
	sink := &fakeSink{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = src.Run(ctx, sink) }()
	waitFor(t, func() bool {
		sink.mu.Lock()
		defer sink.mu.Unlock()
		return len(sink.upsert) >= 1
	}, "configmap upsert")
	sink.mu.Lock()
	b := sink.upsert[0]
	sink.mu.Unlock()
	if b.Source.Kind != "kube-configmap" || b.Source.Key != "ca.crt" {
		t.Fatalf("unexpected ref %+v", b.Source)
	}
}

func TestSecretFilterExclude(t *testing.T) {
	pemData := makeCertPEM(t)
	sec1 := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "good", Namespace: "ns"},
		Type:       corev1.SecretTypeTLS,
		Data:       map[string][]byte{"tls.crt": pemData},
	}
	sec2 := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "bad", Namespace: "ns"},
		Type:       corev1.SecretTypeTLS,
		Data:       map[string][]byte{"tls.crt": pemData},
	}
	client := fake.NewSimpleClientset(sec1, sec2)
	src := New(Options{
		Name: "k", Client: client, ResyncEvery: 10 * time.Minute,
		SecretRules: []SecretTypeRule{{
			Type: "kubernetes.io/tls", KeyRe: regexp.MustCompile(`^tls\.crt$`), Parser: pem.New(),
		}},
		SecretFilter: SecretFilter{ExcludeNames: []string{"bad"}},
	}, nopLogger())
	sink := &fakeSink{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = src.Run(ctx, sink) }()
	waitFor(t, func() bool {
		sink.mu.Lock()
		defer sink.mu.Unlock()
		return len(sink.upsert) >= 1
	}, "first upsert")
	time.Sleep(100 * time.Millisecond)
	sink.mu.Lock()
	defer sink.mu.Unlock()
	for _, b := range sink.upsert {
		if b.Source.Location == "ns/bad" {
			t.Fatal("bad secret should have been excluded")
		}
	}
}

// Note: the previous TestTransform* tests covered transform functions that
// pre-stripped fields before objects entered the SharedInformer's cache.
// Both Secret and ConfigMap paths now use a direct paginated LIST + WATCH
// (no informer cache, no transform), so those tests were removed alongside
// the transform functions.

func TestRunNoClient(t *testing.T) {
	src := New(Options{Name: "k"}, nopLogger())
	if err := src.Run(context.Background(), &fakeSink{}); err == nil {
		t.Fatal("expected error with nil client")
	}
}

func TestParseTrackedKey(t *testing.T) {
	r := parseTrackedKey("kube-secret:ns/n#tls.crt", "src")
	if r.Kind != "kube-secret" || r.Location != "ns/n" || r.Key != "tls.crt" || r.SourceName != "src" {
		t.Fatalf("got %+v", r)
	}
	r = parseTrackedKey("file:/x", "src")
	if r.Kind != "file" || r.Location != "/x" || r.Key != "" {
		t.Fatalf("got %+v", r)
	}
	r = parseTrackedKey("nopcolon", "src")
	if r.Kind != "" {
		t.Fatalf("got %+v", r)
	}
}

func TestNameAndAcceptName(t *testing.T) {
	src := New(Options{Name: "x"}, nopLogger())
	if src.Name() != "x" {
		t.Fail()
	}
	f := SecretFilter{IncludeNames: []string{"foo"}}
	if !src.acceptName("foo", f) || src.acceptName("bar", f) {
		t.Fail()
	}
	f = SecretFilter{IncludeNames: []string{"*"}}
	if !src.acceptName("anything", f) {
		t.Fail()
	}
}
