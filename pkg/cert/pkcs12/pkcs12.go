// Package pkcs12 implements the PKCS#12 / PFX FormatParser.
//
// Behaviour:
//
//  1. attempt DecodeTrustStore(data, password). On success, every cert is
//     an Item;
//  2. otherwise attempt DecodeChain(data, password). The leaf becomes
//     Item index 0, the chain follows;
//  3. otherwise attempt the legacy Decode(data, password) (one cert);
//  4. otherwise produce a Bundle-level ItemError with reason
//     bad_passphrase if the underlying error is sslmate's
//     ErrIncorrectPassword, else bad_pkcs12.
//
// Passphrases are never logged.
package pkcs12

import (
	"crypto/x509"
	"errors"

	pk "software.sslmate.com/src/go-pkcs12"

	"github.com/enix/x509-certificate-exporter/v4/pkg/cert"
)

// Parser is stateless and safe for concurrent use.
type Parser struct{}

func New() Parser { return Parser{} }

// Format implements cert.FormatParser.
func (Parser) Format() string { return "pkcs12" }

// Parse implements cert.FormatParser. The passphrase is taken from
// opts.Pkcs12Passphrase; if it fails and opts.Pkcs12TryEmpty is true, a
// second attempt is made with "".
func (p Parser) Parse(data []byte, ref cert.SourceRef, opts cert.ParseOptions) cert.Bundle {
	b := cert.Bundle{Source: ref}

	pass := opts.Pkcs12Passphrase
	items, err := decode(data, pass)
	if err != nil && opts.Pkcs12TryEmpty && pass != "" {
		if items2, err2 := decode(data, ""); err2 == nil {
			items = items2
			err = nil
		}
	}
	if err != nil {
		reason := cert.ReasonBadPKCS12
		if errors.Is(err, pk.ErrIncorrectPassword) {
			reason = cert.ReasonBadPassphrase
		}
		b.Errors = append(b.Errors, cert.ItemError{
			Index: -1, Reason: reason, Err: err,
		})
		return b
	}
	if len(items) == 0 {
		b.Errors = append(b.Errors, cert.ItemError{
			Index: -1, Reason: cert.ReasonNoCertificateFound,
		})
		return b
	}
	for i, it := range items {
		b.Items = append(b.Items, cert.Item{
			Index: i,
			Cert:  it.cert,
			Role:  it.role,
		})
	}
	return b
}

type itemWithRole struct {
	cert *x509.Certificate
	role cert.Role
}

func decode(data []byte, pass string) ([]itemWithRole, error) {
	// 1. truststore
	if certs, err := pk.DecodeTrustStore(data, pass); err == nil && len(certs) > 0 {
		out := make([]itemWithRole, 0, len(certs))
		for _, c := range certs {
			out = append(out, itemWithRole{cert: c, role: classifyTrustStore(c)})
		}
		return out, nil
	}
	// 2. chain
	if _, leaf, chain, err := pk.DecodeChain(data, pass); err == nil && leaf != nil {
		out := []itemWithRole{{cert: leaf, role: cert.RoleLeaf}}
		for _, c := range chain {
			out = append(out, itemWithRole{cert: c, role: classifyChain(c)})
		}
		return out, nil
	} else if errors.Is(err, pk.ErrIncorrectPassword) {
		return nil, err
	}
	// 3. legacy single
	_, c, err := pk.Decode(data, pass)
	if err != nil {
		return nil, err
	}
	return []itemWithRole{{cert: c, role: cert.RoleLeaf}}, nil
}

func classifyTrustStore(c *x509.Certificate) cert.Role {
	if c.IsCA {
		return cert.RoleCA
	}
	return cert.RoleUnknown
}

func classifyChain(c *x509.Certificate) cert.Role {
	if c.IsCA {
		return cert.RoleIntermediate
	}
	return cert.RoleUnknown
}
