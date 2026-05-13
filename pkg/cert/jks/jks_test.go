package jks

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/pavlo-v-chernykh/keystore-go/v4"

	"github.com/enix/x509-certificate-exporter/v4/pkg/cert"
)

func makeCert(t *testing.T, cn string, isCA bool) (*x509.Certificate, []byte, *ecdsa.PrivateKey) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  isCA,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	x, _ := x509.ParseCertificate(der)
	return x, der, key
}

// buildTrustStoreJKS writes a JKS truststore holding the given certs
// under predictable aliases. password is store-level.
func buildTrustStoreJKS(t *testing.T, password string, certs ...*x509.Certificate) []byte {
	t.Helper()
	ks := keystore.New()
	for i, c := range certs {
		alias := "trust-" + string(rune('a'+i))
		err := ks.SetTrustedCertificateEntry(alias, keystore.TrustedCertificateEntry{
			CreationTime: time.Now(),
			Certificate: keystore.Certificate{
				Type:    "X.509",
				Content: c.Raw,
			},
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	var buf bytes.Buffer
	if err := ks.Store(&buf, []byte(password)); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// buildKeyStoreJKS writes a JKS keystore containing one
// PrivateKeyEntry whose cert chain is [leaf, intermediate].
func buildKeyStoreJKS(t *testing.T, password string, leaf, inter *x509.Certificate, leafKey *ecdsa.PrivateKey) []byte {
	t.Helper()
	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	ks := keystore.New()
	chain := []keystore.Certificate{
		{Type: "X.509", Content: leaf.Raw},
		{Type: "X.509", Content: inter.Raw},
	}
	err = ks.SetPrivateKeyEntry("leaf", keystore.PrivateKeyEntry{
		CreationTime:     time.Now(),
		PrivateKey:       keyDER,
		CertificateChain: chain,
	}, []byte(password))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := ks.Store(&buf, []byte(password)); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestParseTrustStore(t *testing.T) {
	ca, _, _ := makeCert(t, "Trusted Root", true)
	other, _, _ := makeCert(t, "Trusted Other", true)
	data := buildTrustStoreJKS(t, "changeit", ca, other)
	b := New().Parse(data, cert.SourceRef{Kind: "file"}, cert.ParseOptions{JksPassphrase: "changeit"})
	if len(b.Errors) != 0 {
		t.Fatalf("unexpected errors: %v", b.Errors)
	}
	if len(b.Items) != 2 {
		t.Fatalf("want 2 items, got %d", len(b.Items))
	}
	for _, it := range b.Items {
		if it.Role != cert.RoleCA {
			t.Errorf("truststore CA entry should have RoleCA, got %s", it.Role)
		}
	}
}

func TestParseKeyStoreChain(t *testing.T) {
	leaf, _, leafKey := makeCert(t, "leaf.example.test", false)
	inter, _, _ := makeCert(t, "intermediate", true)
	data := buildKeyStoreJKS(t, "secret", leaf, inter, leafKey)
	b := New().Parse(data, cert.SourceRef{Kind: "file"}, cert.ParseOptions{JksPassphrase: "secret"})
	if len(b.Errors) != 0 {
		t.Fatalf("unexpected errors: %v", b.Errors)
	}
	if len(b.Items) != 2 {
		t.Fatalf("want 2 chain items, got %d", len(b.Items))
	}
	if b.Items[0].Role != cert.RoleLeaf {
		t.Fatalf("first item should be leaf, got %s", b.Items[0].Role)
	}
	if b.Items[1].Role != cert.RoleIntermediate {
		t.Fatalf("second item should be intermediate, got %s", b.Items[1].Role)
	}
	if b.Items[0].Cert.Subject.CommonName != "leaf.example.test" {
		t.Fatalf("leaf CN = %q", b.Items[0].Cert.Subject.CommonName)
	}
}

func TestParseWrongPassphraseReportsBadPassphrase(t *testing.T) {
	ca, _, _ := makeCert(t, "ca", true)
	data := buildTrustStoreJKS(t, "right-pass", ca)
	b := New().Parse(data, cert.SourceRef{Kind: "file"}, cert.ParseOptions{JksPassphrase: "wrong-pass"})
	if !b.HasFatalError() {
		t.Fatalf("wrong passphrase must produce a fatal error")
	}
	if got := b.Errors[0].Reason; got != cert.ReasonBadPassphrase {
		t.Fatalf("reason = %q, want bad_passphrase", got)
	}
}

func TestTryEmptyPassphraseFallback(t *testing.T) {
	ca, _, _ := makeCert(t, "ca", true)
	// Build a keystore protected by an empty password.
	data := buildTrustStoreJKS(t, "", ca)
	// Caller supplies a wrong non-empty password but enables fallback.
	b := New().Parse(data, cert.SourceRef{Kind: "file"}, cert.ParseOptions{
		JksPassphrase: "definitely-wrong",
		JksTryEmpty:   true,
	})
	if len(b.Errors) != 0 {
		t.Fatalf("expected empty-passphrase fallback to succeed: %v", b.Errors)
	}
	if len(b.Items) != 1 {
		t.Fatalf("want 1 item, got %d", len(b.Items))
	}
}

func TestParseGarbageRejectsBeforeKeystoreGo(t *testing.T) {
	b := New().Parse([]byte{0x00, 0x01, 0x02, 0x03}, cert.SourceRef{Kind: "file"}, cert.ParseOptions{})
	if !b.HasFatalError() {
		t.Fatalf("garbage should yield a fatal error")
	}
	if got := b.Errors[0].Reason; got != cert.ReasonBadJKS {
		t.Fatalf("reason = %q, want bad_jks", got)
	}
}

func TestParseEmptyReportsBadJKS(t *testing.T) {
	b := New().Parse(nil, cert.SourceRef{Kind: "file"}, cert.ParseOptions{})
	if !b.HasFatalError() {
		t.Fatalf("empty input should yield a fatal error")
	}
	if got := b.Errors[0].Reason; got != cert.ReasonBadJKS {
		t.Fatalf("reason = %q, want bad_jks", got)
	}
}

func TestParseMisroutedPEMReportsBadJKS(t *testing.T) {
	// A PEM blob fed to the JKS parser should be rejected by the
	// magic-byte pre-filter, never reach keystore-go.
	data := []byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n")
	b := New().Parse(data, cert.SourceRef{Kind: "file"}, cert.ParseOptions{})
	if !b.HasFatalError() {
		t.Fatalf("PEM input should be rejected")
	}
	if got := b.Errors[0].Reason; got != cert.ReasonBadJKS {
		t.Fatalf("reason = %q, want bad_jks", got)
	}
}

func TestFormat(t *testing.T) {
	if New().Format() != "jks" {
		t.Fatalf("Format = %q, want jks", New().Format())
	}
}

func TestEmptyKeystoreReportsNoCertFound(t *testing.T) {
	// A valid JKS with zero entries — Load() succeeds, Aliases()
	// returns empty.
	ks := keystore.New()
	var buf bytes.Buffer
	if err := ks.Store(&buf, []byte("changeit")); err != nil {
		t.Fatal(err)
	}
	b := New().Parse(buf.Bytes(), cert.SourceRef{Kind: "file"}, cert.ParseOptions{JksPassphrase: "changeit"})
	if !b.HasFatalError() {
		t.Fatalf("empty keystore should yield no_certificate_found")
	}
	if got := b.Errors[0].Reason; got != cert.ReasonNoCertificateFound {
		t.Fatalf("reason = %q, want no_certificate_found", got)
	}
}
