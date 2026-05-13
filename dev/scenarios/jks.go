package scenarios

import (
	"bytes"
	"crypto/x509"
	"time"

	"github.com/pavlo-v-chernykh/keystore-go/v4"
)

// EncodeJKSTrustStore builds a JKS truststore holding the given CA certs.
func EncodeJKSTrustStore(cas []*x509.Certificate, passphrase string) ([]byte, error) {
	ks := keystore.New()
	for i, c := range cas {
		alias := string(rune('a' + i))
		err := ks.SetTrustedCertificateEntry(alias, keystore.TrustedCertificateEntry{
			CreationTime: time.Now(),
			Certificate:  keystore.Certificate{Type: "X.509", Content: c.Raw},
		})
		if err != nil {
			return nil, err
		}
	}
	var buf bytes.Buffer
	if err := ks.Store(&buf, []byte(passphrase)); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
