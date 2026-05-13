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

// FuzzParse exercises the DER parser on arbitrary bytes. Contract:
// Parse must never panic, regardless of input. Truncated ASN.1
// prefixes, oversize length headers, OID confusion between cert and
// CRL, near-valid TBS structures — all must surface as Bundle.Errors
// entries, never as a runtime crash.
func FuzzParse(f *testing.F) {
	// A real DER cert and a real DER CRL anchor the corpus so the
	// fuzzer can mutate towards both valid sides of the dispatch.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "seed-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(48 * time.Hour),
		BasicConstraintsValid: true, IsCA: true,
		KeyUsage: x509.KeyUsageCRLSign,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &key.PublicKey, key)
	caCert, _ := x509.ParseCertificate(caDER)
	crlDER, _ := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now().Add(-time.Hour),
		NextUpdate: time.Now().Add(48 * time.Hour),
	}, caCert, key)

	for _, seed := range [][]byte{
		nil,
		{},
		{0x00},
		{0x30, 0x00},                                       // empty SEQUENCE
		{0x30, 0x80, 0x00, 0x00},                           // indefinite-length SEQUENCE
		{0x30, 0x82, 0xff, 0xff},                           // SEQUENCE with bogus 64KB length
		[]byte("not der at all, just plain text"),          // ASCII garbage
		[]byte("-----BEGIN CERTIFICATE-----\n"),            // misrouted PEM
		caDER,
		crlDER,
		caDER[:len(caDER)/2], // truncated cert
		crlDER[:len(crlDER)/2], // truncated CRL
	} {
		f.Add(seed)
	}

	p := New()
	ref := cert.SourceRef{Kind: "fuzz", SourceName: "fuzz"}
	f.Fuzz(func(_ *testing.T, data []byte) {
		_ = p.Parse(data, ref, cert.ParseOptions{})
	})
}
