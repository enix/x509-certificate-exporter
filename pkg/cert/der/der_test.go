package der

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/enix/x509-certificate-exporter/v4/pkg/cert"
)

// genCertDER returns the raw DER bytes of a self-signed cert.
func genCertDER(t *testing.T, cn string, isCA bool) []byte {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  isCA,
		KeyUsage:              x509.KeyUsageCRLSign | x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// genCRLDER returns the raw DER bytes of a CRL signed by an
// ephemeral CA.
func genCRLDER(t *testing.T, issuerCN string, number int64, nextUpdate time.Time) []byte {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: issuerCN},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(48 * time.Hour),
		BasicConstraintsValid: true, IsCA: true,
		KeyUsage: x509.KeyUsageCRLSign,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &key.PublicKey, key)
	caCert, _ := x509.ParseCertificate(caDER)
	thisUpdate := time.Now().Add(-time.Hour)
	if !nextUpdate.After(thisUpdate) {
		thisUpdate = nextUpdate.Add(-time.Hour)
	}
	tpl := &x509.RevocationList{
		Number:     big.NewInt(number),
		ThisUpdate: thisUpdate,
		NextUpdate: nextUpdate,
	}
	der, err := x509.CreateRevocationList(rand.Reader, tpl, caCert, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestParseCert(t *testing.T) {
	derBytes := genCertDER(t, "leaf", false)
	b := New().Parse(derBytes, cert.SourceRef{Kind: "file", Location: "/x.crt"}, cert.ParseOptions{})
	if len(b.Items) != 1 {
		t.Fatalf("want 1 item got %d (errors=%v)", len(b.Items), b.Errors)
	}
	if len(b.RevocationItems) != 0 {
		t.Fatalf("cert input must not produce RevocationItems")
	}
	if len(b.Errors) != 0 {
		t.Fatalf("unexpected errors: %v", b.Errors)
	}
	if b.Items[0].Cert.Subject.CommonName != "leaf" {
		t.Fatalf("CN = %q, want leaf", b.Items[0].Cert.Subject.CommonName)
	}
	if b.Items[0].Role != cert.RoleLeaf {
		t.Fatalf("Role = %s, want leaf", b.Items[0].Role)
	}
}

func TestParseSelfSignedCA(t *testing.T) {
	derBytes := genCertDER(t, "root", true)
	b := New().Parse(derBytes, cert.SourceRef{Kind: "file"}, cert.ParseOptions{})
	if len(b.Items) != 1 {
		t.Fatalf("want 1 item got %d", len(b.Items))
	}
	if b.Items[0].Role != cert.RoleCA {
		t.Fatalf("Role = %s, want ca", b.Items[0].Role)
	}
}

func TestParseIntermediate(t *testing.T) {
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(48 * time.Hour),
		BasicConstraintsValid: true, IsCA: true,
		KeyUsage: x509.KeyUsageCertSign,
	}
	rootDER, _ := x509.CreateCertificate(rand.Reader, rootTpl, rootTpl, &rootKey.PublicKey, rootKey)
	rootCert, _ := x509.ParseCertificate(rootDER)
	intKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	intTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "int"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(48 * time.Hour),
		BasicConstraintsValid: true, IsCA: true,
		KeyUsage: x509.KeyUsageCertSign,
	}
	intDER, _ := x509.CreateCertificate(rand.Reader, intTpl, rootCert, &intKey.PublicKey, rootKey)
	b := New().Parse(intDER, cert.SourceRef{}, cert.ParseOptions{})
	if len(b.Items) != 1 {
		t.Fatalf("want 1 item got %d", len(b.Items))
	}
	if b.Items[0].Role != cert.RoleIntermediate {
		t.Fatalf("CA issued by another should be intermediate, got %s", b.Items[0].Role)
	}
}

func TestParseCRL(t *testing.T) {
	derBytes := genCRLDER(t, "issuer-cn", 42, time.Now().Add(48*time.Hour))
	b := New().Parse(derBytes, cert.SourceRef{Kind: "file", Location: "/x.crl"}, cert.ParseOptions{})
	if len(b.Items) != 0 {
		t.Fatalf("CRL input must not produce cert Items, got %d", len(b.Items))
	}
	if len(b.RevocationItems) != 1 {
		t.Fatalf("want 1 RevocationItem got %d (errors=%v)", len(b.RevocationItems), b.Errors)
	}
	if len(b.Errors) != 0 {
		t.Fatalf("unexpected errors: %v", b.Errors)
	}
	got := b.RevocationItems[0].CRL
	if got.Issuer.CommonName != "issuer-cn" {
		t.Fatalf("issuer CN = %q, want issuer-cn", got.Issuer.CommonName)
	}
	if got.Number.Int64() != 42 {
		t.Fatalf("CRL number = %v, want 42", got.Number)
	}
}

func TestParseGarbage(t *testing.T) {
	b := New().Parse([]byte{0x00, 0x01, 0x02, 0x03}, cert.SourceRef{Kind: "file"}, cert.ParseOptions{})
	if !b.HasFatalError() {
		t.Fatalf("garbage bytes should yield a fatal error")
	}
	if b.Errors[0].Reason != cert.ReasonBadDER {
		t.Fatalf("reason = %q, want bad_der", b.Errors[0].Reason)
	}
	if b.Errors[0].Err == nil {
		t.Fatalf("expected non-nil err on bad_der")
	}
}

func TestParseEmpty(t *testing.T) {
	b := New().Parse(nil, cert.SourceRef{Kind: "file"}, cert.ParseOptions{})
	if !b.HasFatalError() {
		t.Fatalf("empty input should yield a fatal error")
	}
	if b.Errors[0].Reason != cert.ReasonNoCertificateFound {
		t.Fatalf("reason = %q, want no_certificate_found", b.Errors[0].Reason)
	}
}

// TestPEMInputNotRecognised guards against accidental dispatch: a PEM
// blob fed to the DER parser fails fast with bad_der (no cert, no
// CRL, and ParseCertificate's error preserved for the operator).
func TestPEMInputNotRecognised(t *testing.T) {
	pemBytes := []byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n")
	b := New().Parse(pemBytes, cert.SourceRef{Kind: "file"}, cert.ParseOptions{})
	if !b.HasFatalError() {
		t.Fatalf("PEM-wrapped input should not be accepted by the DER parser")
	}
}

// TestTruncatedDERReportsBadDER feeds the first half of a real cert's
// DER: the ASN.1 length prefix is valid but the content is short, so
// ParseCertificate fails with a structured error that the parser
// reports as bad_der.
func TestTruncatedDERReportsBadDER(t *testing.T) {
	derBytes := genCertDER(t, "leaf", false)
	half := derBytes[:len(derBytes)/2]
	b := New().Parse(half, cert.SourceRef{Kind: "file"}, cert.ParseOptions{})
	if !b.HasFatalError() {
		t.Fatalf("truncated DER should yield a fatal error")
	}
	if b.Errors[0].Reason != cert.ReasonBadDER {
		t.Fatalf("reason = %q, want bad_der", b.Errors[0].Reason)
	}
}

func TestFormat(t *testing.T) {
	if New().Format() != "der" {
		t.Fatalf("Format = %q, want der", New().Format())
	}
}
