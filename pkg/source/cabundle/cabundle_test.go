package cabundle

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
	"sync"
	"testing"
	"time"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

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

func makeCertPEM(t *testing.T) []byte {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-ca"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(180 * 24 * time.Hour),
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

func TestMWCEmitsOnePerEntry(t *testing.T) {
	caA, caB := makeCertPEM(t), makeCertPEM(t)
	mwc := &admissionv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "linkerd-proxy-injector-webhook-config",
			Labels: map[string]string{"app": "linkerd"},
		},
		Webhooks: []admissionv1.MutatingWebhook{
			{Name: "injector.linkerd.io", ClientConfig: admissionv1.WebhookClientConfig{CABundle: caA}},
			{Name: "second.linkerd.io", ClientConfig: admissionv1.WebhookClientConfig{CABundle: caB}},
			// Empty caBundle → silently skipped (fresh webhook, cert-manager not yet injected).
			{Name: "pending.linkerd.io", ClientConfig: admissionv1.WebhookClientConfig{}},
		},
	}
	client := fake.NewSimpleClientset(mwc)
	src := New(Options{
		Name:          "cabundles",
		Client:        client,
		Resources:     Resources{Mutating: true},
		ResyncEvery:   10 * time.Minute,
		ExposedLabels: []string{"app"},
	}, nopLogger())
	sink := &fakeSink{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = src.Run(ctx, sink) }()

	waitFor(t, func() bool {
		sink.mu.Lock()
		defer sink.mu.Unlock()
		return len(sink.upsert) >= 2
	}, "two MWC entries with caBundle")

	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.upsert) != 2 {
		t.Fatalf("want 2 upserts (two non-empty entries, one pending skipped), got %d", len(sink.upsert))
	}
	seen := map[string]bool{}
	for _, b := range sink.upsert {
		if b.Source.Kind != cert.KindKubeCABundle {
			t.Errorf("unexpected source kind %q", b.Source.Kind)
		}
		if b.Source.Location != "MutatingWebhookConfiguration/linkerd-proxy-injector-webhook-config" {
			t.Errorf("unexpected location %q", b.Source.Location)
		}
		if b.Source.Attributes[cert.AttrCABundleLabelPrefix+"app"] != "linkerd" {
			t.Errorf("exposed label missing/wrong: %v", b.Source.Attributes)
		}
		if len(b.Items) != 1 {
			t.Errorf("want 1 item per entry, got %d", len(b.Items))
		}
		seen[b.Source.Key] = true
	}
	if !seen["injector.linkerd.io"] || !seen["second.linkerd.io"] {
		t.Errorf("missing expected entries, got %v", seen)
	}
	if seen["pending.linkerd.io"] {
		t.Errorf("pending entry with empty caBundle should not have been emitted")
	}
}

func TestVWCEmitsAndDeletesOnRemoval(t *testing.T) {
	ca := makeCertPEM(t)
	vwc := &admissionv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "policy-validator"},
		Webhooks: []admissionv1.ValidatingWebhook{
			{Name: "validate.policy.example", ClientConfig: admissionv1.WebhookClientConfig{CABundle: ca}},
		},
	}
	client := fake.NewSimpleClientset(vwc)
	src := New(Options{
		Name:        "cabundles",
		Client:      client,
		Resources:   Resources{Validating: true},
		ResyncEvery: 10 * time.Minute,
	}, nopLogger())
	sink := &fakeSink{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = src.Run(ctx, sink) }()

	waitFor(t, func() bool {
		sink.mu.Lock()
		defer sink.mu.Unlock()
		return len(sink.upsert) >= 1
	}, "VWC upsert")

	// Delete the VWC — the source should fire one Delete for the
	// tracked entry.
	if err := client.AdmissionregistrationV1().ValidatingWebhookConfigurations().
		Delete(ctx, vwc.Name, metav1.DeleteOptions{}); err != nil {
		t.Fatalf("delete vwc: %v", err)
	}
	waitFor(t, func() bool {
		sink.mu.Lock()
		defer sink.mu.Unlock()
		return len(sink.delete) >= 1
	}, "VWC delete event")

	sink.mu.Lock()
	defer sink.mu.Unlock()
	if sink.delete[0].Kind != cert.KindKubeCABundle {
		t.Errorf("unexpected delete kind %q", sink.delete[0].Kind)
	}
	if sink.delete[0].Location != "ValidatingWebhookConfiguration/policy-validator" {
		t.Errorf("unexpected delete location %q", sink.delete[0].Location)
	}
}

func TestEntryRemovalEmitsDelete(t *testing.T) {
	caA, caB := makeCertPEM(t), makeCertPEM(t)
	mwc := &admissionv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "two-entries"},
		Webhooks: []admissionv1.MutatingWebhook{
			{Name: "entry-a", ClientConfig: admissionv1.WebhookClientConfig{CABundle: caA}},
			{Name: "entry-b", ClientConfig: admissionv1.WebhookClientConfig{CABundle: caB}},
		},
	}
	client := fake.NewSimpleClientset(mwc)
	src := New(Options{
		Name:        "cabundles",
		Client:      client,
		Resources:   Resources{Mutating: true},
		ResyncEvery: 10 * time.Minute,
	}, nopLogger())
	sink := &fakeSink{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = src.Run(ctx, sink) }()

	waitFor(t, func() bool {
		sink.mu.Lock()
		defer sink.mu.Unlock()
		return len(sink.upsert) >= 2
	}, "initial two entries")

	// Drop entry-b — the source must emit a Delete for it.
	mwc.Webhooks = mwc.Webhooks[:1]
	if _, err := client.AdmissionregistrationV1().MutatingWebhookConfigurations().
		Update(ctx, mwc, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("update mwc: %v", err)
	}
	waitFor(t, func() bool {
		sink.mu.Lock()
		defer sink.mu.Unlock()
		return len(sink.delete) >= 1
	}, "entry-b delete")

	sink.mu.Lock()
	defer sink.mu.Unlock()
	if sink.delete[0].Key != "entry-b" {
		t.Errorf("want delete for entry-b, got key=%q", sink.delete[0].Key)
	}
}

func TestNameFilterSkipsExcluded(t *testing.T) {
	ca := makeCertPEM(t)
	keep := &admissionv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "team-alpha-webhook"},
		Webhooks: []admissionv1.MutatingWebhook{
			{Name: "e1", ClientConfig: admissionv1.WebhookClientConfig{CABundle: ca}},
		},
	}
	skip := &admissionv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "test-helper-webhook"},
		Webhooks: []admissionv1.MutatingWebhook{
			{Name: "e1", ClientConfig: admissionv1.WebhookClientConfig{CABundle: ca}},
		},
	}
	client := fake.NewSimpleClientset(keep, skip)
	src := New(Options{
		Name:         "cabundles",
		Client:       client,
		Resources:    Resources{Mutating: true},
		ResyncEvery:  10 * time.Minute,
		IncludeNames: []string{"team-*"},
		ExcludeNames: []string{"test-*"},
	}, nopLogger())
	sink := &fakeSink{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = src.Run(ctx, sink) }()

	waitFor(t, func() bool {
		sink.mu.Lock()
		defer sink.mu.Unlock()
		return len(sink.upsert) >= 1
	}, "filtered upsert")

	// Give the informer a moment in case the unwanted one is in flight.
	time.Sleep(100 * time.Millisecond)
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.upsert) != 1 {
		t.Fatalf("want 1 upsert (team-alpha kept, test-helper filtered), got %d", len(sink.upsert))
	}
	if sink.upsert[0].Source.Location != "MutatingWebhookConfiguration/team-alpha-webhook" {
		t.Errorf("wrong upsert location: %v", sink.upsert[0].Source.Location)
	}
}

func TestNoResourcesErrors(t *testing.T) {
	client := fake.NewSimpleClientset()
	src := New(Options{
		Name:      "cabundles",
		Client:    client,
		Resources: Resources{}, // none enabled
	}, nopLogger())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := src.Run(ctx, &fakeSink{}); err == nil {
		t.Fatal("want error when no resources enabled, got nil")
	}
}
