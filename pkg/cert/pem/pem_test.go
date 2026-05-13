package pem

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	encpem "encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/enix/x509-certificate-exporter/v4/pkg/cert"
)

// gen produces a self-signed cert and its PEM encoding.
func gen(t *testing.T, cn string, isCA bool) (*x509.Certificate, []byte) {
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
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	x, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return x, encpem.EncodeToMemory(&encpem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestParseSingle(t *testing.T) {
	_, pemData := gen(t, "leaf", false)
	b := New().Parse(pemData, cert.SourceRef{Kind: "file", Location: "/x.pem"}, cert.ParseOptions{})
	if len(b.Items) != 1 {
		t.Fatalf("want 1 item got %d", len(b.Items))
	}
	if len(b.Errors) != 0 {
		t.Fatalf("want no errors got %v", b.Errors)
	}
	if b.Items[0].Role != cert.RoleLeaf {
		t.Fatalf("want leaf got %s", b.Items[0].Role)
	}
}

func TestParseMulti(t *testing.T) {
	_, leaf := gen(t, "leaf", false)
	_, ca := gen(t, "rootCA", true)
	combined := append([]byte{}, leaf...)
	combined = append(combined, ca...)
	b := New().Parse(combined, cert.SourceRef{Kind: "file", Location: "/x.pem"}, cert.ParseOptions{})
	if len(b.Items) != 2 {
		t.Fatalf("want 2 items got %d", len(b.Items))
	}
	if b.Items[0].Role != cert.RoleLeaf {
		t.Fatalf("first should be leaf")
	}
	if b.Items[1].Role != cert.RoleCA {
		t.Fatalf("second should be CA, got %s", b.Items[1].Role)
	}
	if b.Items[0].Index != 0 || b.Items[1].Index != 1 {
		t.Fatalf("indices wrong")
	}
}

func TestParseSkipsNonCertBlocks(t *testing.T) {
	_, leaf := gen(t, "leaf", false)
	prefix := encpem.EncodeToMemory(&encpem.Block{Type: "PRIVATE KEY", Bytes: []byte("ignored")})
	combined := append([]byte{}, prefix...)
	combined = append(combined, leaf...)
	b := New().Parse(combined, cert.SourceRef{Kind: "file"}, cert.ParseOptions{})
	if len(b.Items) != 1 || len(b.Errors) != 0 {
		t.Fatalf("non-cert blocks should be silently ignored: items=%d errs=%v", len(b.Items), b.Errors)
	}
}

func TestParseBadCertBlock(t *testing.T) {
	bad := encpem.EncodeToMemory(&encpem.Block{Type: "CERTIFICATE", Bytes: []byte("not asn.1")})
	_, good := gen(t, "leaf", false)
	combined := append([]byte{}, bad...)
	combined = append(combined, good...)
	b := New().Parse(combined, cert.SourceRef{Kind: "file"}, cert.ParseOptions{})
	if len(b.Items) != 1 {
		t.Fatalf("good cert should still parse: got %d items", len(b.Items))
	}
	if len(b.Errors) != 1 || b.Errors[0].Reason != cert.ReasonBadPEM {
		t.Fatalf("expect 1 bad_pem error: %v", b.Errors)
	}
	if b.Errors[0].Index != 0 {
		t.Fatalf("bad block was index 0, got %d", b.Errors[0].Index)
	}
}

func TestParseEmpty(t *testing.T) {
	b := New().Parse([]byte("just garbage no PEM markers"), cert.SourceRef{Kind: "file"}, cert.ParseOptions{})
	if !b.HasFatalError() {
		t.Fatalf("garbage input should yield no_certificate_found: %v", b)
	}
	if b.Errors[0].Reason != cert.ReasonNoCertificateFound {
		t.Fatalf("wrong reason %s", b.Errors[0].Reason)
	}
}

func TestParseOnlyKeyBlock(t *testing.T) {
	keyOnly := encpem.EncodeToMemory(&encpem.Block{Type: "PRIVATE KEY", Bytes: []byte("ignored")})
	b := New().Parse(keyOnly, cert.SourceRef{Kind: "file"}, cert.ParseOptions{})
	if !b.HasFatalError() {
		t.Fatalf("PEM with only non-cert blocks should yield no_certificate_found")
	}
}

func TestFormat(t *testing.T) {
	if New().Format() != "pem" {
		t.Fail()
	}
}

func TestClassifyIntermediate(t *testing.T) {
	// Generate a CA and a child cert signed by it. The child cert is also
	// a CA but issued by another => intermediate.
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true, IsCA: true,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)

	intKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	intTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "int"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true, IsCA: true,
	}
	intDER, _ := x509.CreateCertificate(rand.Reader, intTpl, caCert, &intKey.PublicKey, caKey)
	intCert, _ := x509.ParseCertificate(intDER)
	intPEM := encpem.EncodeToMemory(&encpem.Block{Type: "CERTIFICATE", Bytes: intDER})
	caPEM := encpem.EncodeToMemory(&encpem.Block{Type: "CERTIFICATE", Bytes: caDER})

	b := New().Parse(append(intPEM, caPEM...), cert.SourceRef{}, cert.ParseOptions{})
	if len(b.Items) != 2 {
		t.Fatalf("want 2 items, got %d", len(b.Items))
	}
	if b.Items[0].Role != cert.RoleIntermediate {
		t.Fatalf("first should be intermediate, got %s", b.Items[0].Role)
	}
	if b.Items[1].Role != cert.RoleCA {
		t.Fatalf("self-signed CA should be RoleCA, got %s", b.Items[1].Role)
	}
	_ = intCert
}

func genCRL(t *testing.T, issuerCN string, number int64, nextUpdate time.Time) []byte {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: issuerCN},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true, IsCA: true,
		KeyUsage: x509.KeyUsageCRLSign,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &key.PublicKey, key)
	caCert, _ := x509.ParseCertificate(caDER)
	tpl := &x509.RevocationList{
		Number:     big.NewInt(number),
		ThisUpdate: time.Now().Add(-time.Hour),
		NextUpdate: nextUpdate,
	}
	der, err := x509.CreateRevocationList(rand.Reader, tpl, caCert, key)
	if err != nil {
		t.Fatal(err)
	}
	return encpem.EncodeToMemory(&encpem.Block{Type: "X509 CRL", Bytes: der})
}

func TestParseCRL(t *testing.T) {
	crlPEM := genCRL(t, "issuer-cn", 42, time.Now().Add(48*time.Hour))
	b := New().Parse(crlPEM, cert.SourceRef{Kind: "file"}, cert.ParseOptions{})
	if len(b.Items) != 0 {
		t.Fatalf("CRL-only input should produce no cert items, got %d", len(b.Items))
	}
	if len(b.RevocationItems) != 1 {
		t.Fatalf("want 1 RevocationItem got %d", len(b.RevocationItems))
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

func TestParseCertAndCRLTogether(t *testing.T) {
	_, leaf := gen(t, "leaf", false)
	crl := genCRL(t, "issuer", 1, time.Now().Add(time.Hour))
	combined := append([]byte{}, leaf...)
	combined = append(combined, crl...)
	b := New().Parse(combined, cert.SourceRef{Kind: "file"}, cert.ParseOptions{})
	if len(b.Items) != 1 || len(b.RevocationItems) != 1 {
		t.Fatalf("want 1 cert + 1 crl, got %d certs %d crls", len(b.Items), len(b.RevocationItems))
	}
	if len(b.Errors) != 0 {
		t.Fatalf("unexpected errors: %v", b.Errors)
	}
}

func TestParseBadCRLBlock(t *testing.T) {
	bad := encpem.EncodeToMemory(&encpem.Block{Type: "X509 CRL", Bytes: []byte("not asn.1")})
	b := New().Parse(bad, cert.SourceRef{Kind: "file"}, cert.ParseOptions{})
	if len(b.RevocationItems) != 0 {
		t.Fatalf("bad CRL must not produce a RevocationItem")
	}
	if len(b.Errors) != 1 || b.Errors[0].Reason != cert.ReasonBadCRL {
		t.Fatalf("want one bad_crl error, got %v", b.Errors)
	}
}

func TestParseOnlyCRLAvoidsNoCertFoundFatal(t *testing.T) {
	// A file containing only a valid CRL must NOT be reported as
	// no_certificate_found — that bundle-level fatal would mask the
	// CRL the user explicitly asked us to monitor.
	crlPEM := genCRL(t, "issuer", 1, time.Now().Add(time.Hour))
	b := New().Parse(crlPEM, cert.SourceRef{Kind: "file"}, cert.ParseOptions{})
	if b.HasFatalError() {
		t.Fatalf("CRL-only bundle must not have a fatal error: %v", b.Errors)
	}
}

func TestTrustedCertificateBlock(t *testing.T) {
	_, leafPEM := gen(t, "leaf", false)
	// Replace block type CERTIFICATE -> TRUSTED CERTIFICATE
	block, _ := encpem.Decode(leafPEM)
	tc := encpem.EncodeToMemory(&encpem.Block{Type: "TRUSTED CERTIFICATE", Bytes: block.Bytes})
	b := New().Parse(tc, cert.SourceRef{}, cert.ParseOptions{})
	if len(b.Items) != 1 {
		t.Fatalf("TRUSTED CERTIFICATE blocks should be accepted")
	}
}
