package scenarios

import (
	"testing"

	"github.com/enix/x509-certificate-exporter/v4/pkg/cert/pem"
	"github.com/enix/x509-certificate-exporter/v4/pkg/cert/pkcs12"
	"github.com/enix/x509-certificate-exporter/v4/pkg/cert"
)

// TestAllParseWithExporter is a self-test: every Data blob in every scenario
// is round-tripped through the exporter's parsers, and the result is checked
// against the scenario's stated Expect entries. If this passes, the e2e
// suite is asserting against a faithful in-process model of what the
// exporter will emit.
func TestAllParseWithExporter(t *testing.T) {
	pemP := pem.New()
	p12P := pkcs12.New()

	for _, sc := range All() {
		sc := sc
		t.Run(sc.Namespace+"/"+sc.Name, func(t *testing.T) {
			expectByKey := map[string][]ExpectCert{}
			for _, e := range sc.Expect {
				expectByKey[e.Key] = append(expectByKey[e.Key], e)
			}
			for key, blob := range sc.Data {
				exps, ok := expectByKey[key]
				if !ok {
					continue // sibling key (e.g. tls.key, passphrase)
				}
				ref := cert.SourceRef{Kind: "kube-secret", Key: key}
				var b cert.Bundle
				switch {
				case isPKCS12Key(key):
					pp := PKCS12Passphrase
					if other, ok := sc.Data[PKCS12PassphraseKey]; ok {
						pp = string(other)
					}
					tryEmpty := key == "keystore-empty.p12"
					b = p12P.Parse(blob, ref, cert.ParseOptions{Pkcs12Passphrase: pp, Pkcs12TryEmpty: tryEmpty})
				default:
					b = pemP.Parse(blob, ref, cert.ParseOptions{})
				}
				validateBundle(t, sc, key, exps, b)
			}
		})
	}
}

func isPKCS12Key(k string) bool {
	return k == "keystore.p12" || k == "keystore-empty.p12" || k == "truststore.p12"
}

func validateBundle(t *testing.T, sc Scenario, key string, exps []ExpectCert, b cert.Bundle) {
	t.Helper()
	wantErr := ""
	for _, e := range exps {
		if e.ParseError != "" {
			wantErr = string(e.ParseError)
			break
		}
	}
	if wantErr != "" {
		if len(b.Errors) == 0 {
			t.Fatalf("%s key=%s: expected parse error %q, got none (items=%d)", sc.Name, key, wantErr, len(b.Items))
		}
		found := false
		for _, e := range b.Errors {
			if string(e.Reason) == wantErr {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("%s key=%s: expected reason %q, got %v", sc.Name, key, wantErr, b.Errors)
		}
		return
	}
	if len(b.Items) != len(exps) {
		t.Fatalf("%s key=%s: want %d items, got %d (errs %v)", sc.Name, key, len(exps), len(b.Items), b.Errors)
	}
	for i, exp := range exps {
		if exp.SubjectCN != "" && b.Items[i].Cert.Subject.CommonName != exp.SubjectCN {
			t.Fatalf("%s key=%s item %d: want CN %q, got %q",
				sc.Name, key, i, exp.SubjectCN, b.Items[i].Cert.Subject.CommonName)
		}
	}
}
