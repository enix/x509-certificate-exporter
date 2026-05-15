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
	"crypto/hmac"
	"crypto/sha1"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
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

// decode dispatches to the appropriate format-specific decoder based on
// the leading magic bytes. JKS is handled by keystore-go (proven, fuzzed
// upstream); JCEKS is parsed natively because keystore-go v4 hard-codes
// the JKS magic in its Load() and rejects JCEKS payloads outright.
func decode(data []byte, pass string) ([]itemWithRole, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("keystore too short")
	}
	switch binary.BigEndian.Uint32(data[:4]) {
	case magicJKS:
		return decodeJKS(data, pass)
	case magicJCEKS:
		return decodeJCEKS(data, pass)
	default:
		return nil, fmt.Errorf("unrecognised magic")
	}
}

func decodeJKS(data []byte, pass string) ([]itemWithRole, error) {
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

// JCEKS entry types (RFC-equivalent: see com.sun.crypto.provider.JceKeyStore).
// Type 3 (SecretKeyEntry) wraps a Java SealedObject and cannot be skipped
// without implementing Java ObjectStream deserialization — we reject the
// whole store rather than misalign on subsequent entries.
const (
	jceksEntryPrivateKey       = uint32(1)
	jceksEntryTrustedCert      = uint32(2)
	jceksEntrySecretKey        = uint32(3)
	jceksTrailingHMACLength    = 20 // SHA-1
	jceksMightyAphrodite       = "Mighty Aphrodite"
)

// errJCEKSBadDigest mirrors the substring keystore-go surfaces for a wrong
// JKS passphrase, so isPasswordErr classifies both paths identically.
var errJCEKSBadDigest = errors.New("invalid digest")

// decodeJCEKS parses a JCEKS keystore natively. The wire format is byte-
// identical to JKS for our purposes — same `version=2` header, same
// TrustedCertificateEntry (type=2) and PrivateKeyEntry (type=1) layout,
// same trailing SHA-1 HMAC over `utf16be(pass)+"Mighty Aphrodite"+payload`.
// The only meaningful difference is the leading magic (0xCECECECE) and an
// additional entry kind (SecretKeyEntry, type=3) which we refuse rather
// than try to skip past — its length isn't encoded directly, it ends inside
// a serialized Java SealedObject.
//
// Private-key blobs are skipped (length-prefixed) without any decryption
// attempt, matching the JKS path: the exporter only ever reads cert chains.
func decodeJCEKS(data []byte, pass string) ([]itemWithRole, error) {
	if len(data) < 12+jceksTrailingHMACLength {
		return nil, fmt.Errorf("keystore too short")
	}
	payload := data[:len(data)-jceksTrailingHMACLength]
	storedMAC := data[len(data)-jceksTrailingHMACLength:]

	// Verify HMAC before trusting any bytes we're about to interpret.
	if !hmac.Equal(jceksHMAC(pass, payload), storedMAC) {
		return nil, errJCEKSBadDigest
	}

	r := bytes.NewReader(payload)
	skip := func(uint32) error { return nil }
	var magic, version, count uint32
	for _, dst := range []*uint32{&magic, &version, &count} {
		if err := binary.Read(r, binary.BigEndian, dst); err != nil {
			return nil, fmt.Errorf("header: %w", err)
		}
	}
	if magic != magicJCEKS {
		return nil, fmt.Errorf("unexpected magic 0x%X after pre-filter", magic)
	}
	if version != 2 {
		return nil, fmt.Errorf("unsupported JCEKS version %d", version)
	}

	skip = func(n uint32) error {
		_, err := r.Seek(int64(n), io.SeekCurrent)
		return err
	}

	var out []itemWithRole
	for i := uint32(0); i < count; i++ {
		var entryType uint32
		if err := binary.Read(r, binary.BigEndian, &entryType); err != nil {
			return nil, fmt.Errorf("entry %d: %w", i, err)
		}
		if _, err := readJavaUTF(r); err != nil { // alias
			return nil, fmt.Errorf("entry %d alias: %w", i, err)
		}
		var ts int64
		if err := binary.Read(r, binary.BigEndian, &ts); err != nil {
			return nil, fmt.Errorf("entry %d ts: %w", i, err)
		}
		switch entryType {
		case jceksEntryTrustedCert:
			c, err := readJCEKSCert(r)
			if err != nil {
				return nil, fmt.Errorf("entry %d trusted cert: %w", i, err)
			}
			out = append(out, itemWithRole{cert: c, role: classifyTrustStore(c)})
		case jceksEntryPrivateKey:
			var keyLen uint32
			if err := binary.Read(r, binary.BigEndian, &keyLen); err != nil {
				return nil, fmt.Errorf("entry %d key length: %w", i, err)
			}
			if err := skip(keyLen); err != nil {
				return nil, fmt.Errorf("entry %d skip key: %w", i, err)
			}
			var chainLen uint32
			if err := binary.Read(r, binary.BigEndian, &chainLen); err != nil {
				return nil, fmt.Errorf("entry %d chain length: %w", i, err)
			}
			for j := uint32(0); j < chainLen; j++ {
				c, err := readJCEKSCert(r)
				if err != nil {
					return nil, fmt.Errorf("entry %d chain[%d]: %w", i, j, err)
				}
				role := cert.RoleLeaf
				if j > 0 {
					role = classifyChain(c)
				}
				out = append(out, itemWithRole{cert: c, role: role})
			}
		case jceksEntrySecretKey:
			return nil, fmt.Errorf("entry %d: JCEKS SecretKey entries are not supported (Java SealedObject deserialization required to locate subsequent entries)", i)
		default:
			return nil, fmt.Errorf("entry %d: unknown entry type %d", i, entryType)
		}
	}
	return out, nil
}

// readJCEKSCert reads a single X.509 cert: "X.509" UTF tag + uint32 length + DER.
func readJCEKSCert(r *bytes.Reader) (*x509.Certificate, error) {
	certType, err := readJavaUTF(r)
	if err != nil {
		return nil, fmt.Errorf("cert type: %w", err)
	}
	if certType != "X.509" {
		return nil, fmt.Errorf("unsupported cert type %q", certType)
	}
	var certLen uint32
	if err := binary.Read(r, binary.BigEndian, &certLen); err != nil {
		return nil, fmt.Errorf("cert length: %w", err)
	}
	der := make([]byte, certLen)
	if _, err := io.ReadFull(r, der); err != nil {
		return nil, fmt.Errorf("cert body: %w", err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("cert parse: %w", err)
	}
	return c, nil
}

// readJavaUTF reads a Java DataOutputStream.writeUTF()-encoded string:
// uint16 length + UTF-8-ish bytes (technically Java's modified UTF-8, but
// JKS/JCEKS aliases and the literal "X.509" never hit the modified
// encoding's quirks because they are pure ASCII).
func readJavaUTF(r *bytes.Reader) (string, error) {
	var n uint16
	if err := binary.Read(r, binary.BigEndian, &n); err != nil {
		return "", err
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", err
	}
	return string(buf), nil
}

// jceksHMAC computes SHA1( utf16be(pass) || "Mighty Aphrodite" || payload ).
// Matches the algorithm shared by JKS and JCEKS (com.sun.crypto.provider.
// JceKeyStore.getPreKeyedHash). Each input byte is widened to UTF-16BE by
// prepending 0x00 — strictly correct for ASCII passphrases, which mirrors
// keystore-go's behaviour and the universe of passphrases configured in
// real Java apps.
func jceksHMAC(pass string, payload []byte) []byte {
	h := sha1.New()
	for _, b := range []byte(pass) {
		h.Write([]byte{0x00, b})
	}
	h.Write([]byte(jceksMightyAphrodite))
	h.Write(payload)
	return h.Sum(nil)
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
