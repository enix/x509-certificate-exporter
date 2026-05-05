// Package pem implements the PEM FormatParser.
//
// Behaviour:
//   - iterate every PEM block;
//   - keep only "CERTIFICATE" / "TRUSTED CERTIFICATE" blocks;
//   - silently ignore non-cert blocks (private keys, DH params, etc.);
//   - a malformed CERTIFICATE block becomes an ItemError, the bundle keeps
//     processing the next blocks;
//   - a file with zero CERTIFICATE blocks produces a Bundle-level error
//     with Index == -1 and reason "no_certificate_found";
//   - all good certs are exposed as separate Items, no aggregation.
package pem

import (
	"bytes"
	"crypto/x509"
	encpem "encoding/pem"

	"github.com/enix/x509-certificate-exporter/v4/pkg/cert"
)

// Parser is the PEM FormatParser. It has no state and is safe for concurrent
// use. The zero value is usable.
type Parser struct{}

// New returns a Parser. Provided for symmetry with other parsers; the zero
// value works just as well.
func New() Parser { return Parser{} }

// Format implements cert.FormatParser.
func (Parser) Format() string { return cert.FormatPEM }

// Parse implements cert.FormatParser.
func (Parser) Parse(data []byte, ref cert.SourceRef, _ cert.ParseOptions) cert.Bundle {
	b := cert.Bundle{Source: ref}

	rest := data
	idx := 0
	for {
		var block *encpem.Block
		block, rest = encpem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" && block.Type != "TRUSTED CERTIFICATE" {
			// Not a cert: silently ignore (keys, DH params, etc.).
			continue
		}
		x, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			b.Errors = append(b.Errors, cert.ItemError{
				Index:  idx,
				Reason: cert.ReasonBadPEM,
				Err:    err,
			})
			idx++
			continue
		}
		b.Items = append(b.Items, cert.Item{
			Index: idx,
			Cert:  x,
			Role:  classify(x, idx),
		})
		idx++
	}

	if len(b.Items) == 0 && len(b.Errors) == 0 {
		// No PEM blocks at all (or only non-cert blocks). Distinguish
		// "garbage" from "valid PEM with no cert blocks":
		// pem.Decode returned nil from the first call when data has no
		// PEM markers at all; in either case the user-visible signal is
		// the same — no certificate found.
		_ = rest
		b.Errors = append(b.Errors, cert.ItemError{
			Index:  -1,
			Reason: cert.ReasonNoCertificateFound,
		})
	}
	return b
}

// classify makes a best-effort guess at the role of a cert in a chain.
// First cert is assumed to be the leaf unless it is itself a CA; subsequent
// certs are intermediates unless self-signed.
func classify(x *x509.Certificate, idx int) cert.Role {
	if x == nil {
		return cert.RoleUnknown
	}
	if x.IsCA {
		// Self-signed CA: treat as root. Otherwise intermediate.
		if isSelfSigned(x) {
			return cert.RoleCA
		}
		return cert.RoleIntermediate
	}
	if idx == 0 {
		return cert.RoleLeaf
	}
	return cert.RoleUnknown
}

func isSelfSigned(x *x509.Certificate) bool {
	return bytes.Equal(x.RawIssuer, x.RawSubject)
}
