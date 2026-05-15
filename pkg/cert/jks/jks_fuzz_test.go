package jks

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"math/big"
	"testing"
	"time"

	"github.com/pavlo-v-chernykh/keystore-go/v4"

	"github.com/enix/x509-certificate-exporter/v4/pkg/cert"
)

// makeJCEKSTrustStoreForFuzz builds a minimal valid JCEKS truststore so
// the coverage-guided fuzzer has a launching point into the JCEKS
// decoder. Without a valid seed the fuzzer would need to randomly
// satisfy the magic + version + HMAC checks before reaching any of the
// entry-walking code — practically unreachable.
func makeJCEKSTrustStoreForFuzz(ca *x509.Certificate, password string) []byte {
	var buf bytes.Buffer
	put := func(v interface{}) { _ = binary.Write(&buf, binary.BigEndian, v) }
	putUTF := func(s string) { put(uint16(len(s))); buf.WriteString(s) }

	put(uint32(0xCECECECE)) // JCEKS magic
	put(uint32(2))           // version
	put(uint32(1))           // entry count
	put(uint32(2))           // TrustedCertificateEntry
	putUTF("seed")
	put(time.Now().UnixMilli())
	putUTF("X.509")
	put(uint32(len(ca.Raw)))
	buf.Write(ca.Raw)

	h := sha1.New()
	for _, b := range []byte(password) {
		h.Write([]byte{0x00, b})
	}
	h.Write([]byte("Mighty Aphrodite"))
	h.Write(buf.Bytes())
	buf.Write(h.Sum(nil))
	return buf.Bytes()
}

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
	validJCEKS := makeJCEKSTrustStoreForFuzz(ca, "seed-pw")

	magicJKSBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(magicJKSBytes, magicJKS)
	magicJCEKSBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(magicJCEKSBytes, magicJCEKS)

	for _, seed := range [][]byte{
		nil,
		{},
		{0x00, 0x00, 0x00},                       // too short for magic
		magicJKSBytes,                             // JKS magic only, no body
		magicJCEKSBytes,                           // JCEKS magic only, no body
		append(magicJKSBytes, 0xff, 0xff),        // magic + 2 garbage bytes
		validJKS,                                  // valid JKS
		validJKS[:len(validJKS)/2],                // truncated JKS
		validJCEKS,                                // valid JCEKS truststore
		validJCEKS[:len(validJCEKS)/2],            // truncated JCEKS
		validJCEKS[:len(validJCEKS)-1],            // JCEKS with corrupted trailing HMAC
		[]byte("-----BEGIN CERTIFICATE-----\n"),   // misrouted PEM
	} {
		f.Add(seed)
	}

	p := New()
	ref := cert.SourceRef{Kind: "fuzz", SourceName: "fuzz"}
	f.Fuzz(func(_ *testing.T, data []byte) {
		_ = p.Parse(data, ref, cert.ParseOptions{JksPassphrase: "seed-pw"})
	})
}
