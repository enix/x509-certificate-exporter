package pem

import (
	"testing"

	"github.com/enix/x509-certificate-exporter/v4/pkg/cert"
)

// FuzzParse exercises the PEM parser on arbitrary bytes. Contract: Parse
// must never panic, regardless of input. Truncated headers, garbage
// inside CERTIFICATE blocks, mixed block types — all must surface as
// Bundle.Errors entries, never as a runtime crash.
func FuzzParse(f *testing.F) {
	for _, seed := range [][]byte{
		nil,
		[]byte("garbage"),
		[]byte("-----BEGIN CERTIFICATE-----\n"),
		[]byte("-----BEGIN CERTIFICATE-----\nQUFB\n-----END CERTIFICATE-----\n"),
		[]byte("-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n"),
		[]byte("-----BEGIN TRUSTED CERTIFICATE-----\nQUFB\n-----END TRUSTED CERTIFICATE-----\n"),
		[]byte("-----BEGIN PRIVATE KEY-----\nQUFB\n-----END PRIVATE KEY-----\n"),
	} {
		f.Add(seed)
	}

	p := New()
	ref := cert.SourceRef{Kind: "fuzz", SourceName: "fuzz"}
	f.Fuzz(func(_ *testing.T, data []byte) {
		_ = p.Parse(data, ref, cert.ParseOptions{})
	})
}
