package jks

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"fmt"
	"math"
	"math/big"
	"runtime"
	"testing"
	"time"

	"github.com/pavlo-v-chernykh/keystore-go/v4"

	"github.com/enix/x509-certificate-exporter/v4/pkg/cert"
)

// rawStore hand-writes keystore bytes so a test controls every field,
// including the malformed ones no producer would write.
type rawStore struct{ bytes.Buffer }

func (s *rawStore) u16(v uint16) *rawStore { _ = binary.Write(s, binary.BigEndian, v); return s }
func (s *rawStore) u32(v uint32) *rawStore { _ = binary.Write(s, binary.BigEndian, v); return s }
func (s *rawStore) i64(v int64) *rawStore  { _ = binary.Write(s, binary.BigEndian, v); return s }
func (s *rawStore) raw(b []byte) *rawStore { _, _ = s.Write(b); return s }
func (s *rawStore) utf(v string) *rawStore { return s.u16(uint16(len(v))).raw([]byte(v)) }

// trusted appends a version-2 TrustedCertificateEntry.
func (s *rawStore) trusted(alias string, der []byte) *rawStore {
	return s.u32(entryTrustedCert).utf(alias).i64(0).utf("X.509").u32(uint32(len(der))).raw(der)
}

// allocated reports the bytes allocated while f runs.
func allocated(f func()) uint64 {
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	f()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

func parseWith(data []byte, pass string) cert.Bundle {
	return New().Parse(data, cert.SourceRef{Kind: "file"}, cert.ParseOptions{JksPassphrase: pass})
}

func makeCert(t *testing.T, cn string, isCA bool) (*x509.Certificate, []byte, *ecdsa.PrivateKey) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  isCA,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	x, _ := x509.ParseCertificate(der)
	return x, der, key
}

// buildTrustStoreJKS writes a JKS truststore holding the given certs
// under predictable aliases. password is store-level.
func buildTrustStoreJKS(t *testing.T, password string, certs ...*x509.Certificate) []byte {
	t.Helper()
	ks := keystore.New()
	for i, c := range certs {
		alias := "trust-" + string(rune('a'+i))
		err := ks.SetTrustedCertificateEntry(alias, keystore.TrustedCertificateEntry{
			CreationTime: time.Now(),
			Certificate: keystore.Certificate{
				Type:    "X.509",
				Content: c.Raw,
			},
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	var buf bytes.Buffer
	if err := ks.Store(&buf, []byte(password)); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// buildKeyStoreJKS writes a JKS keystore containing one
// PrivateKeyEntry whose cert chain is [leaf, intermediate].
func buildKeyStoreJKS(t *testing.T, password string, leaf, inter *x509.Certificate, leafKey *ecdsa.PrivateKey) []byte {
	t.Helper()
	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	ks := keystore.New()
	chain := []keystore.Certificate{
		{Type: "X.509", Content: leaf.Raw},
		{Type: "X.509", Content: inter.Raw},
	}
	err = ks.SetPrivateKeyEntry("leaf", keystore.PrivateKeyEntry{
		CreationTime:     time.Now(),
		PrivateKey:       keyDER,
		CertificateChain: chain,
	}, []byte(password))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := ks.Store(&buf, []byte(password)); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestParseTrustStore(t *testing.T) {
	ca, _, _ := makeCert(t, "Trusted Root", true)
	other, _, _ := makeCert(t, "Trusted Other", true)
	data := buildTrustStoreJKS(t, "changeit", ca, other)
	b := New().Parse(data, cert.SourceRef{Kind: "file"}, cert.ParseOptions{JksPassphrase: "changeit"})
	if len(b.Errors) != 0 {
		t.Fatalf("unexpected errors: %v", b.Errors)
	}
	if len(b.Items) != 2 {
		t.Fatalf("want 2 items, got %d", len(b.Items))
	}
	for _, it := range b.Items {
		if it.Role != cert.RoleCA {
			t.Errorf("truststore CA entry should have RoleCA, got %s", it.Role)
		}
	}
}

func TestParseTrustStoreAliasOrderDeterministic(t *testing.T) {
	// JKS items come out in alias order whatever order the entries sit
	// in the file, so item order (and therefore Prometheus series
	// ordering) is stable across exporter restarts and store rewrites.
	// buildTrustStoreJKS assigns trust-a, trust-b, … in cert order, and
	// keystore-go writes entries in randomized map order: every build is
	// a different file order with the same sorted-alias CN sequence.
	cas := make([]*x509.Certificate, 6)
	wantCN := make([]string, 6)
	for i := range cas {
		cn := "Anchor-" + string(rune('A'+i))
		c, _, _ := makeCert(t, cn, true)
		cas[i] = c
		wantCN[i] = cn
	}

	// Many iterations: an order leak would surface as a flaky mismatch
	// on at least one of them.
	for iter := 0; iter < 20; iter++ {
		data := buildTrustStoreJKS(t, "changeit", cas...)
		b := New().Parse(data, cert.SourceRef{Kind: "file"}, cert.ParseOptions{JksPassphrase: "changeit"})
		if len(b.Items) != len(wantCN) {
			t.Fatalf("iter %d: want %d items, got %d", iter, len(wantCN), len(b.Items))
		}
		for i, want := range wantCN {
			if got := b.Items[i].Cert.Subject.CommonName; got != want {
				t.Fatalf("iter %d: item %d CN = %q, want %q (alias order not deterministic)", iter, i, got, want)
			}
		}
	}
}

func TestParseKeyStoreChain(t *testing.T) {
	leaf, _, leafKey := makeCert(t, "leaf.example.test", false)
	inter, _, _ := makeCert(t, "intermediate", true)
	data := buildKeyStoreJKS(t, "secret", leaf, inter, leafKey)
	b := New().Parse(data, cert.SourceRef{Kind: "file"}, cert.ParseOptions{JksPassphrase: "secret"})
	if len(b.Errors) != 0 {
		t.Fatalf("unexpected errors: %v", b.Errors)
	}
	if len(b.Items) != 2 {
		t.Fatalf("want 2 chain items, got %d", len(b.Items))
	}
	if b.Items[0].Role != cert.RoleLeaf {
		t.Fatalf("first item should be leaf, got %s", b.Items[0].Role)
	}
	if b.Items[1].Role != cert.RoleIntermediate {
		t.Fatalf("second item should be intermediate, got %s", b.Items[1].Role)
	}
	if b.Items[0].Cert.Subject.CommonName != "leaf.example.test" {
		t.Fatalf("leaf CN = %q", b.Items[0].Cert.Subject.CommonName)
	}
}

func TestParseWrongPassphraseReportsBadPassphrase(t *testing.T) {
	ca, _, _ := makeCert(t, "ca", true)
	data := buildTrustStoreJKS(t, "right-pass", ca)
	b := New().Parse(data, cert.SourceRef{Kind: "file"}, cert.ParseOptions{JksPassphrase: "wrong-pass"})
	if !b.HasFatalError() {
		t.Fatalf("wrong passphrase must produce a fatal error")
	}
	if got := b.Errors[0].Reason; got != cert.ReasonBadPassphrase {
		t.Fatalf("reason = %q, want bad_passphrase", got)
	}
}

func TestTryEmptyPassphraseFallback(t *testing.T) {
	ca, _, _ := makeCert(t, "ca", true)
	// Build a keystore protected by an empty password.
	data := buildTrustStoreJKS(t, "", ca)
	// Caller supplies a wrong non-empty password but enables fallback.
	b := New().Parse(data, cert.SourceRef{Kind: "file"}, cert.ParseOptions{
		JksPassphrase: "definitely-wrong",
		JksTryEmpty:   true,
	})
	if len(b.Errors) != 0 {
		t.Fatalf("expected empty-passphrase fallback to succeed: %v", b.Errors)
	}
	if len(b.Items) != 1 {
		t.Fatalf("want 1 item, got %d", len(b.Items))
	}
}

func TestParseGarbageReportsBadJKS(t *testing.T) {
	b := New().Parse([]byte{0x00, 0x01, 0x02, 0x03}, cert.SourceRef{Kind: "file"}, cert.ParseOptions{})
	if !b.HasFatalError() {
		t.Fatalf("garbage should yield a fatal error")
	}
	if got := b.Errors[0].Reason; got != cert.ReasonBadJKS {
		t.Fatalf("reason = %q, want bad_jks", got)
	}
}

func TestParseEmptyReportsBadJKS(t *testing.T) {
	b := New().Parse(nil, cert.SourceRef{Kind: "file"}, cert.ParseOptions{})
	if !b.HasFatalError() {
		t.Fatalf("empty input should yield a fatal error")
	}
	if got := b.Errors[0].Reason; got != cert.ReasonBadJKS {
		t.Fatalf("reason = %q, want bad_jks", got)
	}
}

func TestParseMisroutedPEMReportsBadJKS(t *testing.T) {
	// A PEM blob fed to the JKS parser should be rejected by the
	// magic-byte pre-filter, never reach the store walker.
	data := []byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n")
	b := New().Parse(data, cert.SourceRef{Kind: "file"}, cert.ParseOptions{})
	if !b.HasFatalError() {
		t.Fatalf("PEM input should be rejected")
	}
	if got := b.Errors[0].Reason; got != cert.ReasonBadJKS {
		t.Fatalf("reason = %q, want bad_jks", got)
	}
}

func TestFormat(t *testing.T) {
	if New().Format() != "jks" {
		t.Fatalf("Format = %q, want jks", New().Format())
	}
}

func TestEmptyKeystoreReportsNoCertFound(t *testing.T) {
	// A valid JKS with zero entries: the layout and the digest check
	// out, there's just nothing to emit.
	ks := keystore.New()
	var buf bytes.Buffer
	if err := ks.Store(&buf, []byte("changeit")); err != nil {
		t.Fatal(err)
	}
	b := New().Parse(buf.Bytes(), cert.SourceRef{Kind: "file"}, cert.ParseOptions{JksPassphrase: "changeit"})
	if !b.HasFatalError() {
		t.Fatalf("empty keystore should yield no_certificate_found")
	}
	if got := b.Errors[0].Reason; got != cert.ReasonNoCertificateFound {
		t.Fatalf("reason = %q, want no_certificate_found", got)
	}
}

func TestParseJKSVersion1(t *testing.T) {
	// Version-1 stores carry no certificate type string.
	_, der, _ := makeCert(t, "V1 Anchor", true)
	s := new(rawStore).u32(magicJKS).u32(1).u32(1).
		u32(entryTrustedCert).utf("v1").i64(0).u32(uint32(len(der))).raw(der)
	b := parseWith(withDigest("changeit", s.Bytes()), "changeit")
	if len(b.Errors) != 0 {
		t.Fatalf("unexpected errors: %v", b.Errors)
	}
	if len(b.Items) != 1 || b.Items[0].Cert.Subject.CommonName != "V1 Anchor" || b.Items[0].Role != cert.RoleCA {
		t.Fatalf("want the V1 Anchor CA, got %d items", len(b.Items))
	}
}

func TestParseJKSDuplicateAliasKeepsLast(t *testing.T) {
	_, first, _ := makeCert(t, "First", true)
	_, second, _ := makeCert(t, "Second", true)
	s := new(rawStore).u32(magicJKS).u32(2).u32(2).trusted("dup", first).trusted("dup", second)
	b := parseWith(withDigest("changeit", s.Bytes()), "changeit")
	if len(b.Errors) != 0 {
		t.Fatalf("unexpected errors: %v", b.Errors)
	}
	if len(b.Items) != 1 || b.Items[0].Cert.Subject.CommonName != "Second" {
		t.Fatalf("want only the later entry, got %d items", len(b.Items))
	}
}

func TestParseTruncatedJKSReportsBadJKS(t *testing.T) {
	// A store cut short is malformed, not protected by another passphrase.
	ca, _, _ := makeCert(t, "ca", true)
	data := buildTrustStoreJKS(t, "changeit", ca)
	b := parseWith(data[:len(data)/2], "changeit")
	if !b.HasFatalError() || b.Errors[0].Reason != cert.ReasonBadJKS {
		t.Fatalf("want bad_jks, got %v", b.Errors)
	}
}

func TestParseIgnoresBytesAfterDigest(t *testing.T) {
	// The digest is the 20 bytes after the last entry; bytes past it
	// don't invalidate the store.
	ca, _, _ := makeCert(t, "ca", true)
	for name, data := range map[string][]byte{
		"jks":   buildTrustStoreJKS(t, "changeit", ca),
		"jceks": buildJCEKSTrustStore(t, "changeit", ca),
	} {
		b := parseWith(append(data, "trailing\n"...), "changeit")
		if len(b.Errors) != 0 || len(b.Items) != 1 {
			t.Errorf("%s: want 1 item and no error, got %d items, errors %v", name, len(b.Items), b.Errors)
		}
	}
}

// TestParseBoundsDeclaredLengths feeds stores whose length and count
// fields claim far more than the input holds. No digest is needed to
// reach these fields — the layout is walked before the digest is
// checked — so the bound must hold on unauthenticated input: parsing
// fails as bad_jks without allocating anything near the claim.
func TestParseBoundsDeclaredLengths(t *testing.T) {
	const budget = 1 << 20 // every store below is under 64 bytes
	for _, magic := range []uint32{magicJKS, magicJCEKS} {
		head := func(count uint32) *rawStore { return new(rawStore).u32(magic).u32(2).u32(count) }
		for _, tc := range []struct {
			name string
			data []byte
		}{
			// 38 bytes declaring a 16 MiB certificate.
			{"cert length", head(1).u32(entryTrustedCert).utf("a").i64(0).utf("X.509").u32(16 << 20).Bytes()},
			{"max cert length", head(1).u32(entryTrustedCert).utf("a").i64(0).utf("X.509").u32(math.MaxUint32).Bytes()},
			{"key length", head(1).u32(entryPrivateKey).utf("a").i64(0).u32(math.MaxUint32).Bytes()},
			{"chain length", head(1).u32(entryPrivateKey).utf("a").i64(0).u32(0).u32(math.MaxUint32).Bytes()},
			{"alias length", head(1).u32(entryTrustedCert).u16(math.MaxUint16).Bytes()},
			{"entry count", head(math.MaxUint32).Bytes()},
		} {
			t.Run(fmt.Sprintf("%08X/%s", magic, tc.name), func(t *testing.T) {
				var b cert.Bundle
				n := allocated(func() {
					b = New().Parse(tc.data, cert.SourceRef{Kind: "file"}, cert.ParseOptions{JksPassphrase: "changeit", JksTryEmpty: true})
				})
				if !b.HasFatalError() || b.Errors[0].Reason != cert.ReasonBadJKS {
					t.Fatalf("want bad_jks, got %v", b.Errors)
				}
				if n > budget {
					t.Fatalf("parsing %d bytes allocated %d bytes", len(tc.data), n)
				}
			})
		}
	}
}
