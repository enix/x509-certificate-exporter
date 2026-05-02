package pkcs12

import (
	"testing"

	"github.com/enix/x509-certificate-exporter/v4/pkg/cert"
)

// FuzzParse exercises the PKCS#12 parser on arbitrary bytes paired with
// arbitrary passphrases. Contract: Parse must never panic — corrupt ASN.1,
// wrong-length salt, malformed MAC, etc. must surface as Bundle.Errors,
// never as a runtime crash.
//
// PKCS#12 is a notoriously baroque format (PKCS#12 → PFX → PKCS#7 →
// PKCS#8 → ASN.1 DER), so the parser delegates to software.sslmate.com's
// implementation. This fuzzer enforces our invariant that even when that
// library returns an error or unexpected state, our wrapper stays sane.
func FuzzParse(f *testing.F) {
	for _, data := range [][]byte{
		nil,
		{0x30}, // bare ASN.1 SEQUENCE tag
		{0x30, 0x00},
		[]byte("not pkcs12"),
	} {
		for _, pass := range []string{"", "letmein"} {
			f.Add(data, pass)
		}
	}

	p := New()
	ref := cert.SourceRef{Kind: "fuzz", SourceName: "fuzz"}
	f.Fuzz(func(_ *testing.T, data []byte, pass string) {
		_ = p.Parse(data, ref, cert.ParseOptions{Pkcs12Passphrase: pass})
		_ = p.Parse(data, ref, cert.ParseOptions{Pkcs12Passphrase: pass, Pkcs12TryEmpty: true})
	})
}
