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
	"runtime"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/enix/x509-certificate-exporter/v4/pkg/cert"
	"github.com/enix/x509-certificate-exporter/v4/pkg/cert/pem"
)

// kruntimeObj is an alias used by the bulk-seeding helpers to keep the
// signatures readable without dragging the long type name into every line.
type kruntimeObj = kruntime.Object

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

func TestConfigMapsWatchHandlesDelete(t *testing.T) {
	pemData := string(makeCertPEM(t))
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "c1", Namespace: "ns"},
		Data:       map[string]string{"ca.crt": pemData},
	}
	client := fake.NewSimpleClientset(cm)
	src := New(Options{
		Name: "k", Client: client, ResyncEvery: 10 * time.Minute,
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
	}, "initial configmap upsert")

	if err := client.CoreV1().ConfigMaps("ns").Delete(ctx, "c1", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool {
		sink.mu.Lock()
		defer sink.mu.Unlock()
		return len(sink.delete) >= 1
	}, "configmap delete event")
}

// TestSecretsListPagesDoesNotCacheData is a memory-regression smoke test for
// the direct LIST+WATCH path. It seeds N secrets each carrying a sizeable
// "garbage" Data key (mimicking large Helm release secrets) alongside the
// matched tls.crt key, runs the source until first sync, then forces GC and
// asserts the post-run heap stays well under "everything cached" territory.
//
// If a regression reintroduces a per-Secret cache (or fails to release the
// LIST page), the garbage bytes stay rooted on the source's heap and the
// assertion trips.
func TestSecretsListPagesDoesNotCacheData(t *testing.T) {
	const (
		nSecrets    = 200
		garbageSize = 50 * 1024 // 50 KiB per secret => 10 MiB total of garbage
		// Budget catches the "source caches every Secret" failure mode. A
		// healthy run holds parsed certs (~5 KiB each) + Prometheus series,
		// totalling under 4 MiB for 200 entries; a fully-cached regression
		// would push this past 10 MiB.
		budgetBytes = 6 * 1024 * 1024
	)
	pemData := makeCertPEM(t)
	objs := make([]kruntimeObj, 0, nSecrets)
	for i := 0; i < nSecrets; i++ {
		// Each secret carries a unique 50 KiB garbage payload that the
		// configured rule does NOT match, so it should never be retained
		// by anything in our pipeline.
		garbage := make([]byte, garbageSize)
		for j := range garbage {
			garbage[j] = byte(i + j)
		}
		objs = append(objs, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "tls-" + itoa(i),
				Namespace: "ns",
			},
			Type: corev1.SecretTypeTLS,
			Data: map[string][]byte{"tls.crt": pemData, "garbage": garbage},
		})
	}
	client := fake.NewSimpleClientset(objs...)
	src := New(Options{
		Name: "k", Client: client, ResyncEvery: 10 * time.Minute, ListPageSize: 50,
		SecretRules: []SecretTypeRule{{
			Type: "kubernetes.io/tls", KeyRe: regexp.MustCompile(`^tls\.crt$`), Parser: pem.New(),
		}},
	}, nopLogger())
	sink := &fakeSink{}
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() { _ = src.Run(ctx, sink); close(done) }()
	waitFor(t, func() bool {
		sink.mu.Lock()
		defer sink.mu.Unlock()
		return len(sink.upsert) >= nSecrets
	}, "all secrets emitted")

	// Stop the source and wait for its goroutine to fully exit so the
	// fake client (rooted via src.opts.Client) is no longer reachable.
	cancel()
	<-done

	// Drop every reference the test still owns to the seeded data, the
	// client, and the source. Each variable is in scope until the end
	// of the function, so the GC will trace from them unless we
	// explicitly nil them out before runtime.GC() runs. ineffassign
	// flags these as dead writes (no read after) — the writes are the
	// whole point of the test, not dead code.
	for i := range objs {
		objs[i] = nil
	}
	objs = nil   //nolint:ineffassign,wastedassign // intentional: drop slice header for GC
	client = nil //nolint:ineffassign,wastedassign // intentional: drop fake client for GC
	src = nil    //nolint:ineffassign,wastedassign // intentional: drop source (holds client) for GC
	runtime.GC()
	runtime.GC() // second pass to clear finalizers triggered by the first

	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	if after.HeapAlloc > budgetBytes {
		t.Fatalf("post-sync heap: %d bytes (budget %d)\n"+
			"this is the smoke check that the LIST path does not cache "+
			"per-secret data: a regression here likely means the Source "+
			"is holding references to entire Secret objects.",
			after.HeapAlloc, budgetBytes)
	}
	t.Logf("post-sync heap: %d KiB (budget %d KiB)", after.HeapAlloc>>10, budgetBytes>>10)
}

// BenchmarkSecretsListPages measures the cost of one full initial sync
// against a fixed-size cluster fixture. Run with:
//
//	go test -bench=BenchmarkSecretsListPages -benchmem ./internal/source/k8s/
//
// allocs/op is the long-term regression watch — a sudden jump indicates
// either an extra per-secret allocation or accidental retention.
func BenchmarkSecretsListPages(b *testing.B) {
	const nSecrets = 500
	pemData := makeCertPEMB(b)
	objs := make([]kruntimeObj, 0, nSecrets)
	for i := 0; i < nSecrets; i++ {
		objs = append(objs, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "tls-" + itoa(i), Namespace: "ns"},
			Type:       corev1.SecretTypeTLS,
			Data:       map[string][]byte{"tls.crt": pemData},
		})
	}
	rules := []SecretTypeRule{{
		Type: "kubernetes.io/tls", KeyRe: regexp.MustCompile(`^tls\.crt$`), Parser: pem.New(),
	}}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		client := fake.NewSimpleClientset(objs...)
		src := New(Options{
			Name: "k", Client: client, ResyncEvery: 10 * time.Minute, ListPageSize: 50,
			SecretRules: rules,
		}, nopLogger())
		sink := &fakeSink{}
		ctx, cancel := context.WithCancel(context.Background())
		go func() { _ = src.Run(ctx, sink) }()
		for {
			sink.mu.Lock()
			n := len(sink.upsert)
			sink.mu.Unlock()
			if n >= nSecrets {
				break
			}
			time.Sleep(time.Millisecond)
		}
		cancel()
	}
}

// itoa is a tiny base-10 formatter that avoids the strconv import dance for
// the benchmark and smoke test.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [12]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(buf[pos:])
}

// makeCertPEMB mirrors makeCertPEM but accepts a *testing.B instead of *testing.T.
func makeCertPEMB(b *testing.B) []byte {
	b.Helper()
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
