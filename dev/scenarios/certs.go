// Cert + keypair generation helpers used by the dev seed and the e2e test.
//
// All certs are self-signed unless built through Chain(), which generates a
// root CA, an intermediate, and a leaf. The exporter doesn't validate trust
// chains — it only parses certs out of the bundle — so the generated chains
// just need to be syntactically valid.
package scenarios

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"
)

type Algo string

const (
	AlgoRSA2048   Algo = "rsa2048"
	AlgoRSA4096   Algo = "rsa4096"
	AlgoECDSAP256 Algo = "ecdsa-p256"
	AlgoECDSAP384 Algo = "ecdsa-p384"
	AlgoEd25519   Algo = "ed25519"
)

func newKey(a Algo) (crypto.Signer, error) {
	switch a {
	case AlgoRSA2048:
		return rsa.GenerateKey(rand.Reader, 2048)
	case AlgoRSA4096:
		return rsa.GenerateKey(rand.Reader, 4096)
	case AlgoECDSAP256:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case AlgoECDSAP384:
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case AlgoEd25519:
		_, k, err := ed25519.GenerateKey(rand.Reader)
		return k, err
	}
	return rsa.GenerateKey(rand.Reader, 2048)
}

func serial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	return n
}

// CertSpec describes a single self-signed cert (also used as a chain rung).
type CertSpec struct {
	CN        string
	O         []string
	OU        []string
	C         []string
	ST        []string
	L         []string
	DNSNames  []string
	NotBefore time.Time
	NotAfter  time.Time
	Algo      Algo
	IsCA      bool
}

// Selfsigned builds a single self-signed cert + its private key.
func Selfsigned(s CertSpec) (cert *x509.Certificate, key crypto.Signer, err error) {
	key, err = newKey(s.Algo)
	if err != nil {
		return nil, nil, err
	}
	tpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject: pkix.Name{
			CommonName:         s.CN,
			Organization:       s.O,
			OrganizationalUnit: s.OU,
			Country:            s.C,
			Province:           s.ST,
			Locality:           s.L,
		},
		NotBefore:             s.NotBefore,
		NotAfter:              s.NotAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              s.DNSNames,
		IsCA:                  s.IsCA,
		BasicConstraintsValid: true,
	}
	if s.IsCA {
		tpl.KeyUsage |= x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		tpl.ExtKeyUsage = nil
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, key.Public(), key)
	if err != nil {
		return nil, nil, err
	}
	cert, err = x509.ParseCertificate(der)
	return cert, key, err
}

// Chain builds a 3-cert hierarchy: root CA → intermediate → leaf, returning
// the leaf private key + each cert in order [leaf, intermediate, root].
func Chain(leafCN string, notBefore, notAfter time.Time, algo Algo) (leafKey crypto.Signer, certs []*x509.Certificate, err error) {
	rootCert, rootKey, err := Selfsigned(CertSpec{
		CN: "Dev Seed Root CA", O: []string{"x509ce-dev"},
		NotBefore: notBefore.Add(-24 * time.Hour),
		NotAfter:  notAfter.Add(24 * time.Hour),
		Algo:      algo, IsCA: true,
	})
	if err != nil {
		return nil, nil, err
	}
	intCert, intKey, err := signed(CertSpec{
		CN: "Dev Seed Intermediate CA", O: []string{"x509ce-dev"},
		NotBefore: notBefore.Add(-12 * time.Hour),
		NotAfter:  notAfter.Add(12 * time.Hour),
		Algo:      algo, IsCA: true,
	}, rootCert, rootKey)
	if err != nil {
		return nil, nil, err
	}
	leafCert, leafKey, err := signed(CertSpec{
		CN: leafCN, O: []string{"x509ce-dev"},
		DNSNames:  []string{leafCN},
		NotBefore: notBefore, NotAfter: notAfter,
		Algo: algo,
	}, intCert, intKey)
	if err != nil {
		return nil, nil, err
	}
	return leafKey, []*x509.Certificate{leafCert, intCert, rootCert}, nil
}

func signed(s CertSpec, parent *x509.Certificate, parentKey crypto.Signer) (*x509.Certificate, crypto.Signer, error) {
	key, err := newKey(s.Algo)
	if err != nil {
		return nil, nil, err
	}
	tpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject: pkix.Name{
			CommonName:         s.CN,
			Organization:       s.O,
			OrganizationalUnit: s.OU,
			Country:            s.C,
			Province:           s.ST,
			Locality:           s.L,
		},
		NotBefore:             s.NotBefore,
		NotAfter:              s.NotAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              s.DNSNames,
		IsCA:                  s.IsCA,
		BasicConstraintsValid: true,
	}
	if s.IsCA {
		tpl.KeyUsage |= x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		tpl.ExtKeyUsage = nil
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, parent, key.Public(), parentKey)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	return cert, key, err
}

// EncodeCertsPEM concatenates DER certs into a single PEM blob.
func EncodeCertsPEM(certs ...*x509.Certificate) []byte {
	var out []byte
	for _, c := range certs {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	return out
}

// EncodeKeyPEM marshals a private key as PEM (PKCS#8 — works for every Algo).
func EncodeKeyPEM(key crypto.Signer) []byte {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}
