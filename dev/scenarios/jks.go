package scenarios

import (
	"bytes"
	"crypto/sha1"
	"crypto/x509"
	"encoding/binary"
	"fmt"
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

// EncodeJCEKSTrustStore builds a JCEKS truststore holding the given CA
// certs. JCEKS uses magic 0xCECECECE but the entry layout and the
// trailing SHA-1 HMAC (over utf16be(pass) + "Mighty Aphrodite" + payload)
// are identical to JKS for TrustedCertificateEntry. Hand-written because
// keystore-go v4 only writes JKS magic; the exporter's jks parser has a
// native JCEKS decoder that consumes this output.
func EncodeJCEKSTrustStore(cas []*x509.Certificate, passphrase string) ([]byte, error) {
	var buf bytes.Buffer
	put := func(v interface{}) error { return binary.Write(&buf, binary.BigEndian, v) }
	putUTF := func(s string) error {
		if err := put(uint16(len(s))); err != nil {
			return err
		}
		_, err := buf.WriteString(s)
		return err
	}

	if err := put(uint32(0xCECECECE)); err != nil { // JCEKS magic
		return nil, err
	}
	if err := put(uint32(2)); err != nil { // version
		return nil, err
	}
	if err := put(uint32(len(cas))); err != nil {
		return nil, err
	}
	nowMS := time.Now().UnixMilli()
	for i, c := range cas {
		if err := put(uint32(2)); err != nil { // TrustedCertificateEntry
			return nil, err
		}
		if err := putUTF(fmt.Sprintf("ca%d", i+1)); err != nil {
			return nil, err
		}
		if err := put(nowMS); err != nil {
			return nil, err
		}
		if err := putUTF("X.509"); err != nil {
			return nil, err
		}
		if err := put(uint32(len(c.Raw))); err != nil {
			return nil, err
		}
		if _, err := buf.Write(c.Raw); err != nil {
			return nil, err
		}
	}

	h := sha1.New()
	for _, b := range []byte(passphrase) {
		h.Write([]byte{0x00, b})
	}
	h.Write([]byte("Mighty Aphrodite"))
	h.Write(buf.Bytes())
	buf.Write(h.Sum(nil))
	return buf.Bytes(), nil
}
