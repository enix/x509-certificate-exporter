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
//   - both variants share one wire layout, read the way the JDK reads
//     it: the store-integrity digest is the 20 bytes that follow the
//     last entry, and anything after it is ignored;
//   - the passphrase only keys that digest — private keys are skipped,
//     never decrypted. A digest mismatch surfaces as `bad_passphrase`, a
//     malformed layout as `bad_jks`;
//   - JksTryEmpty retries with "" exactly like the PKCS#12 parser;
//   - an otherwise valid keystore with zero certs (truly empty) surfaces
//     as `no_certificate_found`.
//
// Every length the input declares is checked against the bytes actually
// left before anything is allocated, so allocations stay proportional to
// the input size whatever the store claims. Certificates are only parsed
// once the digest matches.
//
// Passphrases are never logged. Private keys are never decoded.
package jks

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // JKS/JCEKS wire format mandates SHA-1
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"

	"github.com/enix/x509-certificate-exporter/v4/pkg/cert"
)

// Magic numbers as written by sun.security.provider.JavaKeyStore /
// com.sun.crypto.provider.JceKeyStore. The first 4 bytes of the wire
// format. Anything else is rejected with `bad_jks` before the store is
// walked.
const (
	magicJKS   uint32 = 0xFEEDFEED
	magicJCEKS uint32 = 0xCECECECE
)

// Entry tags. A SecretKeyEntry (JCEKS only) wraps a Java SealedObject
// whose length isn't encoded, so it can't be stepped over: the whole
// store is refused rather than misaligned on the entries after it.
const (
	entryPrivateKey  = uint32(1)
	entryTrustedCert = uint32(2)
	entrySecretKey   = uint32(3)
	digestLength     = 20 // SHA-1
	digestWhitener   = "Mighty Aphrodite"
)

// errBadDigest reports a store-integrity digest mismatch. The layout
// has been walked successfully by then, so the passphrase is wrong.
var errBadDigest = errors.New("invalid digest")

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

	items, err := decode(data, opts.JksPassphrase, opts.JksTryEmpty)
	if err != nil {
		reason := cert.ReasonBadJKS
		if errors.Is(err, errBadDigest) {
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
// produces a sharper error message than a failed header read.
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

// decode walks the store layout, checks the integrity digest against
// pass (then "" when tryEmpty), and only then parses the certificates.
func decode(data []byte, pass string, tryEmpty bool) ([]itemWithRole, error) {
	s, err := walk(data)
	if err != nil {
		return nil, err
	}
	if !s.digestMatches(pass) && (!tryEmpty || pass == "" || !s.digestMatches("")) {
		return nil, errBadDigest
	}
	return s.items()
}

// store is a walked keystore: its layout fits in the input, but neither
// the digest nor the certificates have been checked yet.
type store struct {
	magic   uint32
	entries []entry
	signed  []byte // magic through the last entry: what the digest covers
	digest  []byte
}

// entry is one TrustedCertificateEntry (a single cert) or one
// PrivateKeyEntry chain (leaf first). certs holds the raw DER.
type entry struct {
	alias   string
	trusted bool
	certs   [][]byte
}

// walk reads the header and every entry, then locates the digest.
// Only lengths and offsets are interpreted; no certificate is parsed.
func walk(data []byte) (*store, error) {
	r := bytes.NewReader(data)
	var magic, version, count uint32
	for _, dst := range []*uint32{&magic, &version, &count} {
		if err := binary.Read(r, binary.BigEndian, dst); err != nil {
			return nil, fmt.Errorf("header: %w", err)
		}
	}
	switch {
	case magic == magicJKS && (version == 1 || version == 2):
	case magic == magicJCEKS && version == 2:
	default:
		return nil, fmt.Errorf("unsupported keystore version %d (magic 0x%X)", version, magic)
	}

	s := &store{magic: magic}
	for i := uint32(0); i < count; i++ {
		e, err := walkEntry(r, magic, version)
		if err != nil {
			return nil, fmt.Errorf("entry %d: %w", i, err)
		}
		s.entries = append(s.entries, e)
	}

	end := len(data) - r.Len()
	if r.Len() < digestLength {
		return nil, fmt.Errorf("digest: %w", io.ErrUnexpectedEOF)
	}
	s.signed = data[:end]
	s.digest = data[end : end+digestLength]
	return s, nil
}

func walkEntry(r *bytes.Reader, magic, version uint32) (entry, error) {
	var e entry
	var tag uint32
	if err := binary.Read(r, binary.BigEndian, &tag); err != nil {
		return e, fmt.Errorf("tag: %w", err)
	}
	alias, err := readJavaUTF(r)
	if err != nil {
		return e, fmt.Errorf("alias: %w", err)
	}
	e.alias = alias
	if err := skip(r, 8); err != nil {
		return e, fmt.Errorf("creation time: %w", err)
	}

	switch {
	case tag == entryTrustedCert:
		e.trusted = true
		der, err := readCert(r, version)
		if err != nil {
			return e, fmt.Errorf("trusted cert: %w", err)
		}
		e.certs = [][]byte{der}
	case tag == entryPrivateKey:
		var keyLen uint32
		if err := binary.Read(r, binary.BigEndian, &keyLen); err != nil {
			return e, fmt.Errorf("key length: %w", err)
		}
		if err := skip(r, keyLen); err != nil {
			return e, fmt.Errorf("skip key: %w", err)
		}
		var chainLen uint32
		if err := binary.Read(r, binary.BigEndian, &chainLen); err != nil {
			return e, fmt.Errorf("chain length: %w", err)
		}
		for j := uint32(0); j < chainLen; j++ {
			der, err := readCert(r, version)
			if err != nil {
				return e, fmt.Errorf("chain[%d]: %w", j, err)
			}
			e.certs = append(e.certs, der)
		}
	case tag == entrySecretKey && magic == magicJCEKS:
		return e, errors.New("JCEKS SecretKey entries are not supported (Java SealedObject deserialization required to locate subsequent entries)")
	default:
		return e, fmt.Errorf("unknown entry type %d", tag)
	}
	return e, nil
}

// readCert reads one certificate: a type string (version 2 only — the
// body is parsed as X.509 whatever it says) then a uint32-length DER
// body.
func readCert(r *bytes.Reader, version uint32) ([]byte, error) {
	if version == 2 {
		if _, err := readJavaUTF(r); err != nil {
			return nil, fmt.Errorf("cert type: %w", err)
		}
	}
	var n uint32
	if err := binary.Read(r, binary.BigEndian, &n); err != nil {
		return nil, fmt.Errorf("cert length: %w", err)
	}
	der, err := readBytes(r, n)
	if err != nil {
		return nil, fmt.Errorf("cert body: %w", err)
	}
	return der, nil
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
	b, err := readBytes(r, uint32(n))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// readBytes copies the next n bytes. n comes from the input, so it is
// checked against what is left before allocating: a short store can't
// claim a huge field.
func readBytes(r *bytes.Reader, n uint32) ([]byte, error) {
	if int64(n) > int64(r.Len()) {
		return nil, fmt.Errorf("length %d exceeds %d remaining bytes", n, r.Len())
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, err
	}
	return b, nil
}

// skip advances past n bytes under the same bound as readBytes —
// bytes.Reader.Seek would otherwise move past the end silently and only
// fail on the next read, with a misleading error.
func skip(r *bytes.Reader, n uint32) error {
	if int64(n) > int64(r.Len()) {
		return io.ErrUnexpectedEOF
	}
	_, err := r.Seek(int64(n), io.SeekCurrent)
	return err
}

// digestMatches checks the store-integrity digest,
// SHA1( utf16be(pass) || "Mighty Aphrodite" || signed ), the algorithm
// shared by JKS and JCEKS (JavaKeyStore / JceKeyStore getPreKeyedHash).
// Each passphrase byte is widened to UTF-16BE by prepending 0x00 —
// exact for ASCII passphrases, which is what real Java apps configure.
func (s *store) digestMatches(pass string) bool {
	h := sha1.New() //nolint:gosec // protocol-mandated: JKS/JCEKS integrity uses SHA-1
	for _, b := range []byte(pass) {
		h.Write([]byte{0x00, b})
	}
	h.Write([]byte(digestWhitener))
	h.Write(s.signed)
	return hmac.Equal(h.Sum(nil), s.digest)
}

// items parses the walked certificates. JKS entries are keyed by alias
// (a later duplicate replaces an earlier one) and come out in alias
// order; JCEKS entries come out in file order. Item order feeds the
// series discriminator, so it must not depend on anything but the store.
func (s *store) items() ([]itemWithRole, error) {
	entries := s.entries
	if s.magic == magicJKS {
		entries = byAlias(entries)
	}
	var out []itemWithRole
	for _, e := range entries {
		for i, der := range e.certs {
			c, err := x509.ParseCertificate(der)
			if err != nil {
				return nil, fmt.Errorf("entry %q cert[%d]: %w", e.alias, i, err)
			}
			role := cert.RoleLeaf
			switch {
			case e.trusted:
				role = classifyTrustStore(c)
			case i > 0:
				role = classifyChain(c)
			}
			out = append(out, itemWithRole{cert: c, role: role})
		}
	}
	return out, nil
}

// byAlias keeps the last entry of each alias and sorts them by alias.
func byAlias(entries []entry) []entry {
	last := make(map[string]int, len(entries))
	for i, e := range entries {
		last[e.alias] = i
	}
	out := make([]entry, 0, len(last))
	for i, e := range entries {
		if last[e.alias] == i {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(a, b int) bool { return out[a].alias < out[b].alias })
	return out
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
