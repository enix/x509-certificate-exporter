// Package jks implements the JKS / JCEKS FormatParser.
//
// JKS (Java KeyStore, magic `0xFEEDFEED`) and JCEKS (Java Cryptography
// Extension KeyStore, magic `0xCECECECE`) are the two pre-PKCS#12 Java
// keystore formats still in widespread use in legacy Spring Boot
// configurations, Apache Tomcat / ActiveMQ / Kafka deployments, and
// many vendor appliances. Both store either:
//
//   - TrustedCertificateEntries (truststore mode) — every entry is a
//     standalone CA / trust anchor we surface as an Item;
//   - PrivateKeyEntries (keystore mode) — each entry pairs an encrypted
//     private key with a cert chain. We only read the chain.
//
// Behaviour:
//
//   - leading magic bytes determine the variant; mismatching bytes
//     surface as `bad_jks`;
//   - the passphrase is applied store-level for integrity check (and
//     for JCEKS entry decryption when needed). A wrong passphrase
//     surfaces as `bad_passphrase`;
//   - JksTryEmpty retries with "" exactly like the PKCS#12 parser;
//   - an otherwise valid keystore with zero certs (truly empty) surfaces
//     as `no_certificate_found`.
//
// Passphrases are never logged. Private keys are never decoded.
package jks

import (
	"bytes"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/pavlo-v-chernykh/keystore-go/v4"

	"github.com/enix/x509-certificate-exporter/v4/pkg/cert"
)

// Magic numbers as written by sun.security.provider.JavaKeyStore /
// com.sun.crypto.provider.JceKeyStore. The first 4 bytes of the wire
// format. Anything else is rejected with `bad_jks` before keystore-go
// gets a chance to emit its own less-specific error.
const (
	magicJKS   uint32 = 0xFEEDFEED
	magicJCEKS uint32 = 0xCECECECE
)

// Parser is stateless and safe for concurrent use.
type Parser struct{}

// New returns a Parser. Provided for symmetry with other parsers.
func New() Parser { return Parser{} }

// Format implements cert.FormatParser.
func (Parser) Format() string { return cert.FormatJKS }

// Parse implements cert.FormatParser. The passphrase is taken from
// opts.JksPassphrase; if it fails and opts.JksTryEmpty is true, a
// second attempt is made with "".
func (Parser) Parse(data []byte, ref cert.SourceRef, opts cert.ParseOptions) cert.Bundle {
	b := cert.Bundle{Source: ref}

	if !looksLikeJKS(data) {
		b.Errors = append(b.Errors, cert.ItemError{
			Index:  -1,
			Reason: cert.ReasonBadJKS,
			Err:    fmt.Errorf("magic bytes do not match JKS (0xFEEDFEED) or JCEKS (0xCECECECE)"),
		})
		return b
	}

	pass := opts.JksPassphrase
	items, err := decode(data, pass)
	if err != nil && opts.JksTryEmpty && pass != "" {
		if items2, err2 := decode(data, ""); err2 == nil {
			items = items2
			err = nil
		}
	}
	if err != nil {
		reason := cert.ReasonBadJKS
		if isPasswordErr(err) {
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

// looksLikeJKS rejects anything that is not at least 4 bytes starting
// with one of the known magic numbers. This pre-filter is cheap and
// produces a sharper error message than letting keystore-go fail
// somewhere inside its TLV scanner.
func looksLikeJKS(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	m := binary.BigEndian.Uint32(data[:4])
	return m == magicJKS || m == magicJCEKS
}

type itemWithRole struct {
	cert *x509.Certificate
	role cert.Role
}

func decode(data []byte, pass string) ([]itemWithRole, error) {
	ks := keystore.New()
	if err := ks.Load(bytes.NewReader(data), []byte(pass)); err != nil {
		return nil, err
	}
	var out []itemWithRole
	for _, alias := range ks.Aliases() {
		switch {
		case ks.IsTrustedCertificateEntry(alias):
			e, err := ks.GetTrustedCertificateEntry(alias)
			if err != nil {
				return nil, fmt.Errorf("truststore entry %q: %w", alias, err)
			}
			c, err := x509.ParseCertificate(e.Certificate.Content)
			if err != nil {
				return nil, fmt.Errorf("truststore entry %q parse: %w", alias, err)
			}
			out = append(out, itemWithRole{cert: c, role: classifyTrustStore(c)})
		case ks.IsPrivateKeyEntry(alias):
			// Read the chain only — never touch the private key.
			// GetPrivateKeyEntryCertificateChain reads ONLY the cert
			// chain attached to a PrivateKeyEntry, with no key
			// decryption attempt — the right primitive for an
			// expiry-monitoring exporter that has no business
			// decoding production private keys.
			chain, err := ks.GetPrivateKeyEntryCertificateChain(alias)
			if err != nil {
				return nil, fmt.Errorf("keystore entry %q chain: %w", alias, err)
			}
			for i, cc := range chain {
				c, err := x509.ParseCertificate(cc.Content)
				if err != nil {
					return nil, fmt.Errorf("keystore entry %q chain[%d]: %w", alias, i, err)
				}
				role := cert.RoleLeaf
				if i > 0 {
					role = classifyChain(c)
				}
				out = append(out, itemWithRole{cert: c, role: role})
			}
		}
	}
	return out, nil
}

// isPasswordErr distinguishes a wrong-passphrase outcome from other
// failure modes. keystore-go does not export a sentinel for the
// HMAC-based store-integrity check, so we match on the substring
// "invalid digest" surfaced by Load(). Since the magic-byte pre-filter
// above already rules out non-JKS / non-JCEKS inputs, a digest
// mismatch at this stage overwhelmingly indicates a wrong password
// (the alternative is store corruption, which is rare in practice and
// surfaces with the same operator action: investigate the file).
func isPasswordErr(err error) bool {
	return err != nil && strings.Contains(err.Error(), "invalid digest")
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
