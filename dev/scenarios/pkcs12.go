package scenarios

import (
	"crypto"
	"crypto/x509"
	"fmt"

	pk "software.sslmate.com/src/go-pkcs12"
)

// EncodePKCS12Chain wraps a leaf + chain into a Modern-encoded PKCS#12 blob
// protected by passphrase.
func EncodePKCS12Chain(leafKey crypto.Signer, certs []*x509.Certificate, passphrase string) ([]byte, error) {
	if len(certs) == 0 {
		return nil, fmt.Errorf("empty cert list")
	}
	leaf := certs[0]
	chain := certs[1:]
	return pk.Modern.Encode(leafKey, leaf, chain, passphrase)
}

// EncodePKCS12Passwordless wraps a leaf + chain into an unencrypted PKCS#12
// blob (no passphrase needed by the exporter when tryEmptyPassphrase is set).
func EncodePKCS12Passwordless(leafKey crypto.Signer, certs []*x509.Certificate) ([]byte, error) {
	if len(certs) == 0 {
		return nil, fmt.Errorf("empty cert list")
	}
	leaf := certs[0]
	chain := certs[1:]
	return pk.Passwordless.Encode(leafKey, leaf, chain, "")
}

// EncodePKCS12TrustStore packages multiple CA certs into a PKCS#12 trust
// store (no private key).
func EncodePKCS12TrustStore(cas []*x509.Certificate, passphrase string) ([]byte, error) {
	return pk.Modern.EncodeTrustStore(cas, passphrase)
}
