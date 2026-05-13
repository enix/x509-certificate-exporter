// CRL fixture generation used by the dev seed and the e2e test.
//
// The exporter doesn't validate CRL signatures — it only parses the
// nextUpdate / thisUpdate / cRLNumber fields out of the PEM block — so
// these fixtures just need to be syntactically valid. Each CRL is signed
// by a fresh self-signed CA generated on the fly.
package scenarios

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"time"
)

// EncodeCRLPEM wraps a CRL in a PEM `X509 CRL` block.
func EncodeCRLPEM(crl *x509.RevocationList) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crl.Raw})
}

// CRLSpec describes one CRL fixture.
type CRLSpec struct {
	IssuerCN   string
	Number     int64
	ThisUpdate time.Time
	NextUpdate time.Time
}

// MakeCRL returns a freshly-issued X.509 CRL signed by an ephemeral CA.
// The CA is discarded; callers care only about the CRL bytes.
func MakeCRL(s CRLSpec) (*x509.RevocationList, error) {
	caCert, caKey, err := Selfsigned(CertSpec{
		CN: s.IssuerCN, O: []string{"x509ce-dev"},
		NotBefore: s.ThisUpdate.Add(-24 * time.Hour),
		NotAfter:  s.NextUpdate.Add(24 * time.Hour),
		Algo:      AlgoECDSAP256, IsCA: true,
	})
	if err != nil {
		return nil, err
	}
	tpl := &x509.RevocationList{
		Number:     big.NewInt(s.Number),
		ThisUpdate: s.ThisUpdate,
		NextUpdate: s.NextUpdate,
	}
	der, err := x509.CreateRevocationList(rand.Reader, tpl, caCert, caKey)
	if err != nil {
		return nil, err
	}
	return x509.ParseRevocationList(der)
}
