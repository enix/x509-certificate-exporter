package jks

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"math/big"
	"testing"
	"time"

	"github.com/pavlo-v-chernykh/keystore-go/v4"

	"github.com/enix/x509-certificate-exporter/v4/pkg/cert"
)

func makeCertForFuzz() (*x509.Certificate, []byte, *ecdsa.PrivateKey) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "fuzz-seed"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(48 * time.Hour),
		BasicConstraintsValid: true, IsCA: true,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	c, _ := x509.ParseCertificate(der)
	return c, der, key
}

// FuzzParse exercises the JKS parser on arbitrary bytes. Contract:
// Parse must never panic, regardless of input. Truncated headers,
// magic-byte collisions, oversize lengths, near-valid keystores —
// all must surface as Bundle.Errors entries, never as a runtime
// crash.
func FuzzParse(f *testing.F) {
	// Seed with a real JKS truststore so the fuzzer has a valid
	// starting point to mutate towards interesting edge cases.
	ca, _, _ := makeCertForFuzz()
	ks := keystore.New()
	_ = ks.SetTrustedCertificateEntry("trust", keystore.TrustedCertificateEntry{
		CreationTime: time.Now(),
		Certificate:  keystore.Certificate{Type: "X.509", Content: ca.Raw},
	})
	var buf bytes.Buffer
	_ = ks.Store(&buf, []byte("seed-pw"))
	validJKS := buf.Bytes()

	magicJKSBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(magicJKSBytes, magicJKS)
	magicJCEKSBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(magicJCEKSBytes, magicJCEKS)

	for _, seed := range [][]byte{
		nil,
		{},
		{0x00, 0x00, 0x00},                 // too short for magic
		magicJKSBytes,                       // magic only, no body
		magicJCEKSBytes,                     // JCEKS magic only
		append(magicJKSBytes, 0xff, 0xff),  // magic + 2 garbage bytes
		validJKS,                            // valid JKS
		validJKS[:len(validJKS)/2],          // truncated
		[]byte("-----BEGIN CERTIFICATE-----\n"), // misrouted PEM
	} {
		f.Add(seed)
	}

	p := New()
	ref := cert.SourceRef{Kind: "fuzz", SourceName: "fuzz"}
	f.Fuzz(func(_ *testing.T, data []byte) {
		_ = p.Parse(data, ref, cert.ParseOptions{JksPassphrase: "seed-pw"})
	})
}
