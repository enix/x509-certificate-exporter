package pkcs12

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	pk "software.sslmate.com/src/go-pkcs12"

	"github.com/enix/x509-certificate-exporter/v4/pkg/cert"
)

const passphrase = "letmein"

func genCA(t *testing.T, cn string) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	x, _ := x509.ParseCertificate(der)
	return key, x
}

func genLeaf(t *testing.T, cn string, caKey *ecdsa.PrivateKey, caCert *x509.Certificate) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, caCert, &key.PublicKey, caKey)
	x, _ := x509.ParseCertificate(der)
	return key, x
}

func TestParseChain(t *testing.T) {
	caKey, caCert := genCA(t, "rootCA")
	leafKey, leafCert := genLeaf(t, "leaf", caKey, caCert)
	data, err := pk.Modern.Encode(leafKey, leafCert, []*x509.Certificate{caCert}, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	b := New().Parse(data, cert.SourceRef{Kind: "file"}, cert.ParseOptions{Pkcs12Passphrase: passphrase})
	if len(b.Items) != 2 {
		t.Fatalf("want 2 items got %d (errs %v)", len(b.Items), b.Errors)
	}
	if b.Items[0].Role != cert.RoleLeaf {
		t.Fatalf("first should be leaf, got %s", b.Items[0].Role)
	}
	if b.Items[1].Role != cert.RoleIntermediate {
		// CA in a Chain context is classified as intermediate.
		t.Fatalf("second should be intermediate, got %s", b.Items[1].Role)
	}
}

func TestParseTrustStore(t *testing.T) {
	_, ca1 := genCA(t, "ca1")
	_, ca2 := genCA(t, "ca2")
	data, err := pk.Modern.EncodeTrustStore([]*x509.Certificate{ca1, ca2}, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	b := New().Parse(data, cert.SourceRef{Kind: "file"}, cert.ParseOptions{Pkcs12Passphrase: passphrase})
	if len(b.Items) != 2 {
		t.Fatalf("want 2 items got %d", len(b.Items))
	}
	for _, it := range b.Items {
		if it.Role != cert.RoleCA {
			t.Fatalf("trust store entries should be CA, got %s", it.Role)
		}
	}
}

func TestParseBadPassphrase(t *testing.T) {
	caKey, caCert := genCA(t, "rootCA")
	leafKey, leafCert := genLeaf(t, "leaf", caKey, caCert)
	data, _ := pk.Modern.Encode(leafKey, leafCert, []*x509.Certificate{caCert}, passphrase)
	b := New().Parse(data, cert.SourceRef{}, cert.ParseOptions{Pkcs12Passphrase: "wrong"})
	if !b.HasFatalError() || b.Errors[0].Reason != cert.ReasonBadPassphrase {
		t.Fatalf("expected bad_passphrase, got %v", b.Errors)
	}
}

func TestParseTryEmpty(t *testing.T) {
	caKey, caCert := genCA(t, "rootCA")
	leafKey, leafCert := genLeaf(t, "leaf", caKey, caCert)
	// Encode with empty passphrase
	data, err := pk.Passwordless.Encode(leafKey, leafCert, []*x509.Certificate{caCert}, "")
	if err != nil {
		t.Fatal(err)
	}
	b := New().Parse(data, cert.SourceRef{}, cert.ParseOptions{Pkcs12Passphrase: "wrong", Pkcs12TryEmpty: true})
	if b.HasFatalError() {
		t.Fatalf("try-empty fallback should succeed, got %v", b.Errors)
	}
	if len(b.Items) == 0 {
		t.Fatalf("expected at least one item")
	}
}

func TestParseGarbage(t *testing.T) {
	b := New().Parse([]byte("garbage"), cert.SourceRef{}, cert.ParseOptions{Pkcs12Passphrase: passphrase})
	if !b.HasFatalError() || b.Errors[0].Reason != cert.ReasonBadPKCS12 {
		t.Fatalf("expected bad_pkcs12, got %v", b.Errors)
	}
}

func TestFormat(t *testing.T) {
	if New().Format() != "pkcs12" {
		t.Fail()
	}
}
