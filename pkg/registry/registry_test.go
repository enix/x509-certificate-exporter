package registry

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/enix/x509-certificate-exporter/v4/pkg/cert"
)

func nopLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func mkCert(t *testing.T, cn string, serial int64) *x509.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"Acme"}},
		Issuer:                pkix.Name{CommonName: "issuer", Organization: []string{"Acme"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	x, _ := x509.ParseCertificate(der)
	return x
}

func bundleFile(c *x509.Certificate, path string) cert.Bundle {
	return cert.Bundle{
		Source: cert.SourceRef{Kind: "file", Location: path, Format: "pem", SourceName: "files"},
		Items:  []cert.Item{{Index: 0, Cert: c, Role: cert.RoleLeaf}},
	}
}

func TestUpsertDelete(t *testing.T) {
	r := New(Config{}, nopLogger())
	c := mkCert(t, "cn", 1)
	b := bundleFile(c, "/etc/x.pem")
	r.Upsert(b)
	if got := testutil.ToFloat64(r.sourceBundles.WithLabelValues("file", "files")); got != 1 {
		t.Fatalf("source bundles = %v want 1", got)
	}
	r.Delete(b.Source)
	if got := testutil.ToFloat64(r.sourceBundles.WithLabelValues("file", "files")); got != 0 {
		t.Fatalf("source bundles = %v want 0 after delete", got)
	}
}

func TestEmitsCertMetrics(t *testing.T) {
	r := New(Config{ExposeRelative: true}, nopLogger())
	r.Upsert(bundleFile(mkCert(t, "leaf", 42), "/etc/leaf.pem"))

	reg := prometheus.NewRegistry()
	if err := reg.Register(r); err != nil {
		t.Fatal(err)
	}
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, mf := range mfs {
		names[*mf.Name] = true
	}
	for _, want := range []string{
		"x509_cert_not_before",
		"x509_cert_not_after",
		"x509_cert_expired",
		"x509_cert_expires_in_seconds",
		"x509_cert_valid_since_seconds",
		"x509_exporter_build_info",
		"x509_scrape_duration_seconds",
	} {
		if !names[want] {
			t.Errorf("missing metric %s", want)
		}
	}
}

func TestCollisionAuto(t *testing.T) {
	r := New(Config{Collision: CollisionAuto}, nopLogger())
	c := mkCert(t, "shared", 1)
	// Bundle-internal collision: a single PEM file containing the exact
	// same certificate twice. Both items have identical labels (same
	// filepath, same serial, same DN), so we expect the discriminator
	// to be activated for both.
	b := cert.Bundle{
		Source: cert.SourceRef{Kind: "file", Location: "/etc/x.pem", SourceName: "files"},
		Items:  []cert.Item{{Index: 0, Cert: c}, {Index: 1, Cert: c}},
	}
	r.Upsert(b)
	reg := prometheus.NewRegistry()
	if err := reg.Register(r); err != nil {
		t.Fatal(err)
	}
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather failed (collision not handled?): %v", err)
	}
	// Both rows should be present with discriminator label.
	found := false
	for _, mf := range mfs {
		if *mf.Name != "x509_cert_not_after" {
			continue
		}
		for _, m := range mf.Metric {
			for _, l := range m.Label {
				if *l.Name == "discriminator" && *l.Value != "" {
					found = true
				}
			}
		}
	}
	if !found {
		t.Fatalf("expected discriminator label on collision in auto mode")
	}
}

func TestCollisionAlways(t *testing.T) {
	r := New(Config{Collision: CollisionAlways}, nopLogger())
	r.Upsert(bundleFile(mkCert(t, "x", 1), "/etc/x.pem"))
	reg := prometheus.NewRegistry()
	_ = reg.Register(r)
	mfs, _ := reg.Gather()
	for _, mf := range mfs {
		if *mf.Name != "x509_cert_not_after" {
			continue
		}
		for _, m := range mf.Metric {
			has := false
			for _, l := range m.Label {
				if *l.Name == "discriminator" {
					has = true
				}
			}
			if !has {
				t.Fatalf("CollisionAlways should always include discriminator")
			}
		}
	}
}

func TestCollisionNeverDedups(t *testing.T) {
	r := New(Config{Collision: CollisionNever}, nopLogger())
	c1 := mkCert(t, "x", 1)
	c2 := mkCert(t, "x", 1)
	c2.NotAfter = c1.NotAfter.Add(-time.Hour) // earlier
	// Bundle-internal collision (same path, same DN, same serial).
	b := cert.Bundle{
		Source: cert.SourceRef{Kind: "file", Location: "/etc/x.pem", SourceName: "files"},
		Items:  []cert.Item{{Index: 0, Cert: c1}, {Index: 1, Cert: c2}},
	}
	r.Upsert(b)
	reg := prometheus.NewRegistry()
	if err := reg.Register(r); err != nil {
		t.Fatal(err)
	}
	if _, err := reg.Gather(); err != nil {
		t.Fatal(err)
	}
	if got := testutil.ToFloat64(r.collisionTotal.WithLabelValues("file")); got < 1 {
		t.Fatalf("collisionTotal = %v want >=1", got)
	}
}

func TestRecordBundleErrorsBumpsCounters(t *testing.T) {
	r := New(Config{}, nopLogger())
	b := cert.Bundle{
		Source: cert.SourceRef{Kind: "file", Location: "/x.pem", SourceName: "files"},
		Errors: []cert.ItemError{
			{Index: -1, Reason: cert.ReasonBadPEM, Err: errors.New("nope")},
			{Index: -1, Reason: cert.ReasonBadPassphrase, Err: errors.New("nope")},
		},
	}
	r.Upsert(b)
	if got := testutil.ToFloat64(r.sourceErrors.WithLabelValues("file", "files", "bad_pem")); got != 1 {
		t.Errorf("bad_pem counter = %v", got)
	}
	if got := testutil.ToFloat64(r.pkcs12PassphraseFailures.WithLabelValues("files")); got != 1 {
		t.Errorf("pkcs12 passphrase counter = %v", got)
	}
}

func TestMarkSourceUp(t *testing.T) {
	r := New(Config{}, nopLogger())
	r.MarkSourceUp("file", "files", true)
	if got := testutil.ToFloat64(r.sourceUp.WithLabelValues("file", "files")); got != 1 {
		t.Fail()
	}
	r.MarkSourceUp("file", "files", false)
	if got := testutil.ToFloat64(r.sourceUp.WithLabelValues("file", "files")); got != 0 {
		t.Fail()
	}
}

func TestObserveAndMark(t *testing.T) {
	r := New(Config{}, nopLogger())
	r.ObserveParse("pem", 5*time.Millisecond)
	r.ObserveKubeRequest("LIST", "secrets", 12*time.Millisecond)
	r.MarkPanic("walker")
	r.MarkInformerScope("k8s", "cluster")
	r.SetInformerQueueDepth("k8s", "secrets", 7)
	r.MarkWatchResync("k8s", "secrets")
	r.MarkSourceError("file", "files", cert.ReasonWalkError)
	if got := testutil.ToFloat64(r.panicTotal.WithLabelValues("walker")); got != 1 {
		t.Fail()
	}
	if got := testutil.ToFloat64(r.informerScope.WithLabelValues("k8s", "cluster")); got != 1 {
		t.Fail()
	}
	if got := testutil.ToFloat64(r.informerScope.WithLabelValues("k8s", "namespace")); got != 0 {
		t.Fail()
	}
	if got := testutil.ToFloat64(r.informerQueueDepth.WithLabelValues("k8s", "secrets")); got != 7 {
		t.Fail()
	}
	if got := testutil.ToFloat64(r.watchResyncs.WithLabelValues("k8s", "secrets")); got != 1 {
		t.Fail()
	}
	if got := testutil.ToFloat64(r.sourceErrors.WithLabelValues("file", "files", "walk_error")); got != 1 {
		t.Fail()
	}
}

func TestSanitiseLabel(t *testing.T) {
	cases := map[string]string{
		"app.kubernetes.io/name": "app_kubernetes_io_name",
		"":                       "_",
		"123":                    "_123",
		"foo-bar":                "foo_bar",
	}
	for in, want := range cases {
		if got := sanitiseLabel(in); got != want {
			t.Errorf("sanitiseLabel(%q) = %q want %q", in, got, want)
		}
	}
}

func TestTrimPath(t *testing.T) {
	if trimPath("/a/b/c", 1) != "/b/c" {
		t.Fail()
	}
	if trimPath("/a/b/c", 0) != "/a/b/c" {
		t.Fail()
	}
	if trimPath("/a/b/c", 5) != "" {
		t.Fail()
	}
	if trimPath("a/b/c", 1) != "b/c" {
		t.Fail()
	}
}

func TestDnFields(t *testing.T) {
	got := dnFields([]string{"cn", "o", "extra"})
	if !equalSlices(got, []string{"O", "CN"}) {
		t.Fatalf("got %v", got)
	}
	if !equalSlices(dnFields(nil), fieldsAll) {
		t.Fatal("nil should expand to all")
	}
}

func equalSlices(a, b []string) bool {
	return strings.Join(a, ",") == strings.Join(b, ",")
}

func TestKubeSecretLabels(t *testing.T) {
	c := mkCert(t, "leaf", 5)
	b := cert.Bundle{
		Source: cert.SourceRef{
			Kind: "kube-secret", Location: "ns/secret-a", Key: "tls.crt",
			SourceName: "kube",
			Attributes: map[string]string{"secret_label/app": "demo"},
		},
		Items: []cert.Item{{Index: 0, Cert: c}},
	}
	r := New(Config{ExposedSecretLabels: []string{"app"}}, nopLogger())
	r.Upsert(b)
	reg := prometheus.NewRegistry()
	_ = reg.Register(r)
	mfs, _ := reg.Gather()
	saw := false
	for _, mf := range mfs {
		if *mf.Name != "x509_cert_not_after" {
			continue
		}
		for _, m := range mf.Metric {
			for _, l := range m.Label {
				if *l.Name == "secret_label_app" && *l.Value == "demo" {
					saw = true
				}
			}
		}
	}
	if !saw {
		t.Fatal("exposed secret label missing")
	}
}
