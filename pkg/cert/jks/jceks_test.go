package jks

import (
	"bytes"
	"crypto/sha1"
	"crypto/x509"
	"encoding/binary"
	"testing"
	"time"

	"github.com/enix/x509-certificate-exporter/v4/pkg/cert"
)

// buildJCEKSTrustStore writes a JCEKS truststore by hand. The wire format
// matches OpenJDK's com.sun.crypto.provider.JceKeyStore: only the leading
// magic differs from JKS, and the trailing HMAC algorithm is identical.
//
// Kept self-contained (no library dependency for the encoder) precisely so
// it cannot mask bugs in the decoder under test.
func buildJCEKSTrustStore(t *testing.T, password string, certs ...*x509.Certificate) []byte {
	t.Helper()
	var buf bytes.Buffer
	put := func(v interface{}) {
		if err := binary.Write(&buf, binary.BigEndian, v); err != nil {
			t.Fatal(err)
		}
	}
	putUTF := func(s string) {
		put(uint16(len(s)))
		buf.WriteString(s)
	}

	put(uint32(0xCECECECE)) // JCEKS magic
	put(uint32(2))           // version
	put(uint32(len(certs)))
	nowMS := time.Now().UnixMilli()
	for i, c := range certs {
		put(uint32(2)) // TrustedCertificateEntry
		putUTF("ca" + string(rune('a'+i)))
		put(nowMS)
		putUTF("X.509")
		put(uint32(len(c.Raw)))
		buf.Write(c.Raw)
	}

	h := sha1.New()
	for _, b := range []byte(password) {
		h.Write([]byte{0x00, b})
	}
	h.Write([]byte("Mighty Aphrodite"))
	h.Write(buf.Bytes())
	buf.Write(h.Sum(nil))
	return buf.Bytes()
}

// buildJCEKSWithSecretKey returns a JCEKS payload that announces one
// SecretKeyEntry. The body is intentionally truncated — the test only
// verifies the parser rejects the entry type before reading body bytes.
func buildJCEKSWithSecretKey(t *testing.T, password string) []byte {
	t.Helper()
	var buf bytes.Buffer
	put := func(v interface{}) {
		if err := binary.Write(&buf, binary.BigEndian, v); err != nil {
			t.Fatal(err)
		}
	}
	putUTF := func(s string) {
		put(uint16(len(s)))
		buf.WriteString(s)
	}
	put(uint32(0xCECECECE))
	put(uint32(2))
	put(uint32(1))
	put(uint32(3)) // SecretKeyEntry
	putUTF("secret-1")
	put(time.Now().UnixMilli())
	// No body — decoder must refuse before reading further.

	h := sha1.New()
	for _, b := range []byte(password) {
		h.Write([]byte{0x00, b})
	}
	h.Write([]byte("Mighty Aphrodite"))
	h.Write(buf.Bytes())
	buf.Write(h.Sum(nil))
	return buf.Bytes()
}

// jceksMAC appends the trailing SHA-1 HMAC for a hand-built JCEKS
// payload. Factored out so malformed payloads (wrong version,
// oversized lengths) can still carry a *valid* digest and therefore
// exercise the post-HMAC parsing paths instead of dying at the digest
// check — which is exactly the attacker model the bounds guards defend
// against (forged keystore + tryEmptyPassphrase makes the HMAC pass).
func jceksMAC(password string, payload []byte) []byte {
	h := sha1.New()
	for _, b := range []byte(password) {
		h.Write([]byte{0x00, b})
	}
	h.Write([]byte("Mighty Aphrodite"))
	h.Write(payload)
	return append(payload, h.Sum(nil)...)
}

// buildJCEKSKeyStore writes a JCEKS keystore with one PrivateKeyEntry
// (type=1): a length-prefixed opaque key blob followed by a cert chain.
// The decoder must skip the key bytes (no decryption) and emit the
// chain with leaf/intermediate roles.
func buildJCEKSKeyStore(t *testing.T, password string, keyBlob []byte, chain ...*x509.Certificate) []byte {
	t.Helper()
	var buf bytes.Buffer
	put := func(v interface{}) {
		if err := binary.Write(&buf, binary.BigEndian, v); err != nil {
			t.Fatal(err)
		}
	}
	putUTF := func(s string) {
		put(uint16(len(s)))
		buf.WriteString(s)
	}
	put(uint32(0xCECECECE))
	put(uint32(2))
	put(uint32(1)) // one entry
	put(uint32(1)) // PrivateKeyEntry
	putUTF("key-1")
	put(time.Now().UnixMilli())
	put(uint32(len(keyBlob)))
	buf.Write(keyBlob)
	put(uint32(len(chain)))
	for _, c := range chain {
		putUTF("X.509")
		put(uint32(len(c.Raw)))
		buf.Write(c.Raw)
	}
	return jceksMAC(password, buf.Bytes())
}

func TestParseJCEKSKeyStoreChain(t *testing.T) {
	leaf, _, _ := makeCert(t, "JCEKS Leaf", false)
	inter, _, _ := makeCert(t, "JCEKS Inter", true)
	// The key blob is opaque to the decoder — it must skip exactly
	// len(keyBlob) bytes and never attempt to decode it.
	data := buildJCEKSKeyStore(t, "changeit", []byte("opaque-encrypted-private-key"), leaf, inter)

	b := New().Parse(data, cert.SourceRef{Kind: "file"}, cert.ParseOptions{JksPassphrase: "changeit"})
	if len(b.Errors) != 0 {
		t.Fatalf("unexpected errors: %v", b.Errors)
	}
	if len(b.Items) != 2 {
		t.Fatalf("want 2 chain items, got %d", len(b.Items))
	}
	if b.Items[0].Role != cert.RoleLeaf {
		t.Errorf("item 0 role = %s, want leaf", b.Items[0].Role)
	}
	if b.Items[1].Role != cert.RoleIntermediate {
		t.Errorf("item 1 role = %s, want intermediate", b.Items[1].Role)
	}
	if got := b.Items[0].Cert.Subject.CommonName; got != "JCEKS Leaf" {
		t.Errorf("leaf CN = %q", got)
	}
}

func TestParseJCEKSOversizedCertLenRejected(t *testing.T) {
	// A truststore entry that claims a 4 GiB cert body. The HMAC is
	// recomputed over the malformed payload so the decoder reaches the
	// length read; without the remaining-bytes bound this would
	// make([]byte, ~4e9) and OOM the process. We assert a graceful
	// fatal error instead.
	var buf bytes.Buffer
	put := func(v interface{}) {
		if err := binary.Write(&buf, binary.BigEndian, v); err != nil {
			t.Fatal(err)
		}
	}
	putUTF := func(s string) {
		put(uint16(len(s)))
		buf.WriteString(s)
	}
	put(uint32(0xCECECECE))
	put(uint32(2))
	put(uint32(1))
	put(uint32(2)) // TrustedCertificateEntry
	putUTF("ca")
	put(time.Now().UnixMilli())
	putUTF("X.509")
	put(uint32(0xFFFFFFF0)) // ~4 GiB cert length, only a few bytes follow
	buf.Write([]byte{0x01, 0x02, 0x03})
	data := jceksMAC("changeit", buf.Bytes())

	b := New().Parse(data, cert.SourceRef{Kind: "file"}, cert.ParseOptions{JksPassphrase: "changeit"})
	if !b.HasFatalError() {
		t.Fatalf("oversized cert length must produce a fatal error, not OOM")
	}
	if got := b.Errors[0].Reason; got != cert.ReasonBadJKS {
		t.Fatalf("reason = %q, want bad_jks", got)
	}
}

func TestParseJCEKSOversizedKeyLenRejected(t *testing.T) {
	// PrivateKeyEntry that claims a key blob larger than the remaining
	// payload. bytes.Reader.Seek would silently move past EOF; the
	// bounded skip must reject it up front.
	var buf bytes.Buffer
	put := func(v interface{}) {
		if err := binary.Write(&buf, binary.BigEndian, v); err != nil {
			t.Fatal(err)
		}
	}
	putUTF := func(s string) {
		put(uint16(len(s)))
		buf.WriteString(s)
	}
	put(uint32(0xCECECECE))
	put(uint32(2))
	put(uint32(1))
	put(uint32(1)) // PrivateKeyEntry
	putUTF("key-1")
	put(time.Now().UnixMilli())
	put(uint32(0xFFFFFFF0)) // key length far past EOF
	buf.Write([]byte{0x01, 0x02})
	data := jceksMAC("changeit", buf.Bytes())

	b := New().Parse(data, cert.SourceRef{Kind: "file"}, cert.ParseOptions{JksPassphrase: "changeit"})
	if !b.HasFatalError() {
		t.Fatalf("oversized key length must produce a fatal error")
	}
	if got := b.Errors[0].Reason; got != cert.ReasonBadJKS {
		t.Fatalf("reason = %q, want bad_jks", got)
	}
}

func TestParseJCEKSUnsupportedVersionRejected(t *testing.T) {
	// Version != 2, HMAC recomputed so the version check (not the
	// digest check) is what rejects the store.
	var buf bytes.Buffer
	put := func(v interface{}) {
		if err := binary.Write(&buf, binary.BigEndian, v); err != nil {
			t.Fatal(err)
		}
	}
	put(uint32(0xCECECECE))
	put(uint32(99)) // unsupported version
	put(uint32(0))  // zero entries
	data := jceksMAC("changeit", buf.Bytes())

	b := New().Parse(data, cert.SourceRef{Kind: "file"}, cert.ParseOptions{JksPassphrase: "changeit"})
	if !b.HasFatalError() {
		t.Fatalf("unsupported version must produce a fatal error")
	}
	if got := b.Errors[0].Reason; got != cert.ReasonBadJKS {
		t.Fatalf("reason = %q, want bad_jks", got)
	}
}

func TestParseJCEKSTrustStore(t *testing.T) {
	ca1, _, _ := makeCert(t, "JCEKS Trust One", true)
	ca2, _, _ := makeCert(t, "JCEKS Trust Two", true)
	data := buildJCEKSTrustStore(t, "changeit", ca1, ca2)

	b := New().Parse(data, cert.SourceRef{Kind: "file"}, cert.ParseOptions{JksPassphrase: "changeit"})
	if len(b.Errors) != 0 {
		t.Fatalf("unexpected errors: %v", b.Errors)
	}
	if len(b.Items) != 2 {
		t.Fatalf("want 2 items, got %d", len(b.Items))
	}
	for i, want := range []string{"JCEKS Trust One", "JCEKS Trust Two"} {
		if got := b.Items[i].Cert.Subject.CommonName; got != want {
			t.Errorf("item %d CN = %q, want %q", i, got, want)
		}
		if b.Items[i].Role != cert.RoleCA {
			t.Errorf("item %d role = %s, want ca", i, b.Items[i].Role)
		}
	}
}

func TestParseJCEKSWrongPassphraseReportsBadPassphrase(t *testing.T) {
	ca, _, _ := makeCert(t, "JCEKS PW", true)
	data := buildJCEKSTrustStore(t, "right-pass", ca)
	b := New().Parse(data, cert.SourceRef{Kind: "file"}, cert.ParseOptions{JksPassphrase: "wrong-pass"})
	if !b.HasFatalError() {
		t.Fatalf("wrong passphrase must produce a fatal error")
	}
	if got := b.Errors[0].Reason; got != cert.ReasonBadPassphrase {
		t.Fatalf("reason = %q, want bad_passphrase", got)
	}
}

func TestParseJCEKSTryEmptyFallback(t *testing.T) {
	ca, _, _ := makeCert(t, "JCEKS Empty", true)
	data := buildJCEKSTrustStore(t, "", ca)
	b := New().Parse(data, cert.SourceRef{Kind: "file"}, cert.ParseOptions{
		JksPassphrase: "definitely-wrong",
		JksTryEmpty:   true,
	})
	if len(b.Errors) != 0 {
		t.Fatalf("expected fallback to succeed: %v", b.Errors)
	}
	if len(b.Items) != 1 {
		t.Fatalf("want 1 item, got %d", len(b.Items))
	}
}

func TestParseJCEKSRejectsSecretKeyEntry(t *testing.T) {
	// JCEKS SecretKey entries wrap a serialized Java SealedObject whose
	// length isn't directly encoded, so the parser cannot skip them and
	// keep its position aligned. The store is refused with a clear error.
	data := buildJCEKSWithSecretKey(t, "changeit")
	b := New().Parse(data, cert.SourceRef{Kind: "file"}, cert.ParseOptions{JksPassphrase: "changeit"})
	if !b.HasFatalError() {
		t.Fatalf("SecretKey entry must produce a fatal error")
	}
	if got := b.Errors[0].Reason; got != cert.ReasonBadJKS {
		t.Fatalf("reason = %q, want bad_jks", got)
	}
}
