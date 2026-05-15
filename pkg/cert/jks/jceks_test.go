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
	put(int64(time.Now().UnixMilli()))
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
