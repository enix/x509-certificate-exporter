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
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextfake "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/fake"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	aggregatorfake "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset/fake"

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

func makeCertPEM(t *testing.T) []byte { return makeCertCN(t, "test-ca") }

func makeCertCN(t *testing.T, cn string) []byte {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
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

func TestAPIServiceEmits(t *testing.T) {
	ca := makeCertPEM(t)
	as := &apiregistrationv1.APIService{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "v1beta1.metrics.k8s.io",
			Labels: map[string]string{"app.kubernetes.io/managed-by": "metrics-server"},
		},
		Spec: apiregistrationv1.APIServiceSpec{
			CABundle: ca,
			Group:    "metrics.k8s.io",
			Version:  "v1beta1",
		},
	}
	src := New(Options{
		Name:             "cabundles",
		Client:           fake.NewSimpleClientset(),
		AggregatorClient: aggregatorfake.NewSimpleClientset(as),
		Resources:        Resources{APIService: true},
		ResyncEvery:      10 * time.Minute,
		ExposedLabels:    []string{"app.kubernetes.io/managed-by"},
	}, nopLogger())
	sink := &fakeSink{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = src.Run(ctx, sink) }()

	waitFor(t, func() bool {
		sink.mu.Lock()
		defer sink.mu.Unlock()
		return len(sink.upsert) >= 1
	}, "APIService upsert")

	sink.mu.Lock()
	defer sink.mu.Unlock()
	b := sink.upsert[0]
	if b.Source.Kind != cert.KindKubeCABundle {
		t.Errorf("kind %q != %q", b.Source.Kind, cert.KindKubeCABundle)
	}
	if b.Source.Location != "APIService/v1beta1.metrics.k8s.io" {
		t.Errorf("location %q", b.Source.Location)
	}
	if b.Source.Key != "" {
		t.Errorf("APIService entry key should be empty, got %q", b.Source.Key)
	}
	if b.Source.Attributes[cert.AttrCABundleLabelPrefix+"app.kubernetes.io/managed-by"] != "metrics-server" {
		t.Errorf("exposed label missing: %v", b.Source.Attributes)
	}
}

func TestAPIServiceEmptyCABundleSkipped(t *testing.T) {
	// `insecureSkipTLSVerify: true` APIServices have no caBundle.
	// The source must skip them silently — no upsert, no error.
	as := &apiregistrationv1.APIService{
		ObjectMeta: metav1.ObjectMeta{Name: "insecure.example.test"},
		Spec: apiregistrationv1.APIServiceSpec{
			InsecureSkipTLSVerify: true,
			Group:                 "example.test",
			Version:               "v1",
		},
	}
	src := New(Options{
		Name:             "cabundles",
		Client:           fake.NewSimpleClientset(),
		AggregatorClient: aggregatorfake.NewSimpleClientset(as),
		Resources:        Resources{APIService: true},
		ResyncEvery:      10 * time.Minute,
	}, nopLogger())
	sink := &fakeSink{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = src.Run(ctx, sink) }()

	time.Sleep(200 * time.Millisecond)
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.upsert) != 0 {
		t.Fatalf("want no upserts, got %d (insecureSkipTLSVerify means no caBundle)", len(sink.upsert))
	}
}

func TestCRDConversionWebhookEmits(t *testing.T) {
	ca := makeCertPEM(t)
	crd := &apiextensionsv1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "tenants.platform.example.com"},
		Spec: apiextensionsv1.CustomResourceDefinitionSpec{
			Group: "platform.example.com",
			Names: apiextensionsv1.CustomResourceDefinitionNames{Plural: "tenants", Kind: "Tenant"},
			Scope: apiextensionsv1.NamespaceScoped,
			Conversion: &apiextensionsv1.CustomResourceConversion{
				Strategy: apiextensionsv1.WebhookConverter,
				Webhook: &apiextensionsv1.WebhookConversion{
					ConversionReviewVersions: []string{"v1"},
					ClientConfig:             &apiextensionsv1.WebhookClientConfig{CABundle: ca},
				},
			},
		},
	}
	src := New(Options{
		Name:                "cabundles",
		Client:              fake.NewSimpleClientset(),
		APIExtensionsClient: apiextfake.NewSimpleClientset(crd),
		Resources:           Resources{CRDConversion: true},
		ResyncEvery:         10 * time.Minute,
	}, nopLogger())
	sink := &fakeSink{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = src.Run(ctx, sink) }()

	waitFor(t, func() bool {
		sink.mu.Lock()
		defer sink.mu.Unlock()
		return len(sink.upsert) >= 1
	}, "CRD upsert")

	sink.mu.Lock()
	defer sink.mu.Unlock()
	b := sink.upsert[0]
	if b.Source.Location != "CustomResourceDefinition/tenants.platform.example.com" {
		t.Errorf("location %q", b.Source.Location)
	}
}

func TestCABundleRotationReplacesUpsert(t *testing.T) {
	// cert-manager-style rotation: a webhook's caBundle is updated
	// to a fresh cert while the resource itself stays. The source
	// must emit a fresh Bundle (same SourceRef, new content) so the
	// registry replaces the previous one. Without this behaviour
	// the metrics would silently report the OLD cert's expiry.
	caV1, caV2 := makeCertCN(t, "ca-v1"), makeCertCN(t, "ca-v2")
	mwc := &admissionv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "rotated"},
		Webhooks: []admissionv1.MutatingWebhook{
			{Name: "wh", ClientConfig: admissionv1.WebhookClientConfig{CABundle: caV1}},
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
		return len(sink.upsert) >= 1
	}, "initial upsert with v1")

	// Verify the first Bundle parsed the v1 cert.
	sink.mu.Lock()
	if len(sink.upsert[0].Items) != 1 || sink.upsert[0].Items[0].Cert.Subject.CommonName != "ca-v1" {
		t.Fatalf("initial Bundle does not carry ca-v1: %+v", sink.upsert[0])
	}
	initialUpserts := len(sink.upsert)
	sink.mu.Unlock()

	// Rotate the caBundle in place.
	mwc.Webhooks[0].ClientConfig.CABundle = caV2
	if _, err := client.AdmissionregistrationV1().MutatingWebhookConfigurations().
		Update(ctx, mwc, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("update mwc: %v", err)
	}

	waitFor(t, func() bool {
		sink.mu.Lock()
		defer sink.mu.Unlock()
		if len(sink.upsert) <= initialUpserts {
			return false
		}
		// Find a Bundle carrying ca-v2 — the registry replaces by
		// SourceRef, but we capture every Upsert in the fakeSink,
		// so the new one is appended at the end.
		latest := sink.upsert[len(sink.upsert)-1]
		return len(latest.Items) == 1 && latest.Items[0].Cert.Subject.CommonName == "ca-v2"
	}, "rotation upsert with ca-v2")

	// No Delete should fire — the SourceRef did not change.
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.delete) != 0 {
		t.Fatalf("rotation must replace, not delete + re-add (got %d deletes)", len(sink.delete))
	}
}

func TestCrossKindSameNameDisambiguated(t *testing.T) {
	// resID is keyed by (kind, name). Two cluster resources of
	// different Kind happening to share a metadata.name must each
	// keep their own tracked set; deleting one must not evict the
	// other.
	ca := makeCertPEM(t)
	const shared = "duplicate-name"
	mwc := &admissionv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: shared},
		Webhooks:   []admissionv1.MutatingWebhook{{Name: "wh", ClientConfig: admissionv1.WebhookClientConfig{CABundle: ca}}},
	}
	as := &apiregistrationv1.APIService{
		ObjectMeta: metav1.ObjectMeta{Name: shared},
		Spec:       apiregistrationv1.APIServiceSpec{CABundle: ca, Group: "x.example", Version: "v1"},
	}
	client := fake.NewSimpleClientset(mwc)
	agg := aggregatorfake.NewSimpleClientset(as)
	src := New(Options{
		Name:             "cabundles",
		Client:           client,
		AggregatorClient: agg,
		Resources:        Resources{Mutating: true, APIService: true},
		ResyncEvery:      10 * time.Minute,
	}, nopLogger())
	sink := &fakeSink{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = src.Run(ctx, sink) }()

	waitFor(t, func() bool {
		sink.mu.Lock()
		defer sink.mu.Unlock()
		return len(sink.upsert) >= 2
	}, "one upsert per Kind")

	// Both kinds present, distinct Locations.
	sink.mu.Lock()
	locs := map[string]bool{}
	for _, b := range sink.upsert {
		locs[b.Source.Location] = true
	}
	sink.mu.Unlock()
	if !locs["MutatingWebhookConfiguration/"+shared] || !locs["APIService/"+shared] {
		t.Fatalf("want both Kinds tracked, got %v", locs)
	}

	// Delete only the MWC — the APIService ref must NOT be evicted.
	if err := client.AdmissionregistrationV1().MutatingWebhookConfigurations().
		Delete(ctx, shared, metav1.DeleteOptions{}); err != nil {
		t.Fatalf("delete mwc: %v", err)
	}
	waitFor(t, func() bool {
		sink.mu.Lock()
		defer sink.mu.Unlock()
		return len(sink.delete) >= 1
	}, "MWC delete event")

	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.delete) != 1 {
		t.Fatalf("want exactly 1 delete (MWC only), got %d", len(sink.delete))
	}
	if sink.delete[0].Location != "MutatingWebhookConfiguration/"+shared {
		t.Fatalf("wrong delete location: %s", sink.delete[0].Location)
	}
}

func TestCRDWithoutConversionSkipped(t *testing.T) {
	// strategy: None — no conversion webhook, no caBundle, no series.
	crd := &apiextensionsv1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "tenants.platform.example.com"},
		Spec: apiextensionsv1.CustomResourceDefinitionSpec{
			Group:      "platform.example.com",
			Names:      apiextensionsv1.CustomResourceDefinitionNames{Plural: "tenants", Kind: "Tenant"},
			Scope:      apiextensionsv1.NamespaceScoped,
			Conversion: &apiextensionsv1.CustomResourceConversion{Strategy: apiextensionsv1.NoneConverter},
		},
	}
	src := New(Options{
		Name:                "cabundles",
		Client:              fake.NewSimpleClientset(),
		APIExtensionsClient: apiextfake.NewSimpleClientset(crd),
		Resources:           Resources{CRDConversion: true},
		ResyncEvery:         10 * time.Minute,
	}, nopLogger())
	sink := &fakeSink{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = src.Run(ctx, sink) }()

	time.Sleep(200 * time.Millisecond)
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.upsert) != 0 {
		t.Fatalf("want no upserts (strategy=None), got %d", len(sink.upsert))
	}
}
