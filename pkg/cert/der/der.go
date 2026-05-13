// Package der implements the DER FormatParser.
//
// DER is the wire format produced by CRL Distribution Points
// (`*.crl` files served over HTTP), by some PKI tooling that writes
// raw cert bytes, and by every PEM block once the base64 envelope is
// stripped — Go's stdlib parsers consume DER directly.
//
// Behaviour:
//   - try parsing the entire input as an X.509 certificate (RFC 5280
//     §4): success → Item with classify-derived Role;
//   - fallback: try parsing the entire input as a CRL (RFC 5280 §5):
//     success → RevocationItem;
//   - both failed: a single Bundle-level ItemError with reason
//     `bad_der` carrying the certificate parser's error (the more
//     common failure mode and the more informative message for a
//     misrouted DER blob).
//
// The wire format has no self-framing, so concatenated DER is NOT
// supported — one DER object per input byte string. Users with
// multiple objects should ship them as PEM (one block each).
package der

import (
	"bytes"
	"crypto/x509"

	"github.com/enix/x509-certificate-exporter/v4/pkg/cert"
)

// Parser is the DER FormatParser. It has no state and is safe for
// concurrent use. The zero value is usable.
type Parser struct{}

// New returns a Parser. Provided for symmetry with other parsers; the
// zero value works just as well.
func New() Parser { return Parser{} }

// Format implements cert.FormatParser.
func (Parser) Format() string { return cert.FormatDER }

// Parse implements cert.FormatParser.
func (Parser) Parse(data []byte, ref cert.SourceRef, _ cert.ParseOptions) cert.Bundle {
	b := cert.Bundle{Source: ref}
	if len(data) == 0 {
		b.Errors = append(b.Errors, cert.ItemError{
			Index:  -1,
			Reason: cert.ReasonNoCertificateFound,
		})
		return b
	}
	if x, err := x509.ParseCertificate(data); err == nil {
		b.Items = append(b.Items, cert.Item{
			Index: 0,
			Cert:  x,
			Role:  classify(x),
		})
		return b
	} else {
		certErr := err
		if crl, crlErr := x509.ParseRevocationList(data); crlErr == nil {
			b.RevocationItems = append(b.RevocationItems, cert.RevocationItem{
				Index: 0,
				CRL:   crl,
			})
			return b
		}
		// Neither parse succeeded — report the certificate-side error
		// since DER blobs misrouted to this parser are far more often
		// malformed certs than malformed CRLs.
		b.Errors = append(b.Errors, cert.ItemError{
			Index:  -1,
			Reason: cert.ReasonBadDER,
			Err:    certErr,
		})
	}
	return b
}

// classify mirrors the PEM parser's heuristic but with a single Item
// — no chain context — so we can only distinguish leaf, self-signed
// CA, and "CA issued by another" (intermediate).
func classify(x *x509.Certificate) cert.Role {
	if x == nil {
		return cert.RoleUnknown
	}
	if x.IsCA {
		if bytes.Equal(x.RawIssuer, x.RawSubject) {
			return cert.RoleCA
		}
		return cert.RoleIntermediate
	}
	return cert.RoleLeaf
}
