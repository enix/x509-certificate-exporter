package k8s

import (
	"context"
	"regexp"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/enix/x509-certificate-exporter/v4/pkg/cert"
)

// recordingParser captures the ParseOptions it receives so the test can
// assert that PassphraseSecretRef resolution actually populated
// Pkcs12Passphrase before the parser was invoked.
type recordingParser struct {
	mu   sync.Mutex
	opts []cert.ParseOptions
}

func (p *recordingParser) Format() string { return cert.FormatPKCS12 }

func (p *recordingParser) Parse(_ []byte, ref cert.SourceRef, opts cert.ParseOptions) cert.Bundle {
	p.mu.Lock()
	p.opts = append(p.opts, opts)
	p.mu.Unlock()
	// Always succeed so the source emits something the test can wait on.
	return cert.Bundle{Source: ref}
}

func (p *recordingParser) snapshot() []cert.ParseOptions {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]cert.ParseOptions{}, p.opts...)
}

func TestPassphraseSecretRefSameNamespace(t *testing.T) {
	// Two Secrets in the same namespace: the cert one (matched by rule)
	// and the passphrase one (referenced by rule.PassphraseSecretRef).
	certSec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "tls", Namespace: "ns"},
		Type:       corev1.SecretType("kubernetes.io/tls"),
		Data:       map[string][]byte{"keystore.p12": []byte("not-actually-parsed")},
	}
	ppSec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "tls-pass", Namespace: "ns"},
		Data:       map[string][]byte{"pp": []byte("letmein")},
	}
	client := fake.NewSimpleClientset(certSec, ppSec)

	parser := &recordingParser{}
	src := New(Options{
		Name: "k", Client: client, ResyncEvery: 10 * time.Minute,
		SecretRules: []SecretTypeRule{{
			Type:  "kubernetes.io/tls",
			KeyRe: regexp.MustCompile(`^keystore\.p12$`),
			// Empty Namespace → falls back to the cert Secret's own ns.
			PassphraseSecretRef: &PassphraseSecretRef{Name: "tls-pass", Key: "pp"},
			Parser:              parser,
		}},
	}, nopLogger())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sink := &fakeSink{}
	go func() { _ = src.Run(ctx, sink) }()

	waitFor(t, func() bool { return len(parser.snapshot()) >= 1 }, "parser called")

	got := parser.snapshot()[0]
	if got.Pkcs12Passphrase != "letmein" {
		t.Fatalf("Pkcs12Passphrase = %q, want %q", got.Pkcs12Passphrase, "letmein")
	}
}

func TestPassphraseSecretRefExplicitNamespace(t *testing.T) {
	// Explicit Namespace on the ref takes precedence over the cert
	// Secret's own namespace.
	certSec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "tls", Namespace: "app-ns"},
		Type:       corev1.SecretType("kubernetes.io/tls"),
		Data:       map[string][]byte{"keystore.p12": []byte("blob")},
	}
	ppSec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "vault", Namespace: "kube-system"},
		Data:       map[string][]byte{"pp": []byte("cross-ns-pass\n")},
	}
	client := fake.NewSimpleClientset(certSec, ppSec)

	parser := &recordingParser{}
	src := New(Options{
		Name: "k", Client: client, ResyncEvery: 10 * time.Minute,
		SecretRules: []SecretTypeRule{{
			Type:  "kubernetes.io/tls",
			KeyRe: regexp.MustCompile(`^keystore\.p12$`),
			PassphraseSecretRef: &PassphraseSecretRef{
				Namespace: "kube-system", Name: "vault", Key: "pp",
			},
			Parser: parser,
		}},
	}, nopLogger())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sink := &fakeSink{}
	go func() { _ = src.Run(ctx, sink) }()

	waitFor(t, func() bool { return len(parser.snapshot()) >= 1 }, "parser called")

	// Trailing newline trimmed (same convention as PassphraseKey path).
	if got := parser.snapshot()[0].Pkcs12Passphrase; got != "cross-ns-pass" {
		t.Fatalf("Pkcs12Passphrase = %q, want %q", got, "cross-ns-pass")
	}
}

func TestPassphraseSecretRefMissingSecretLogsAndContinues(t *testing.T) {
	// Cert Secret is matched; the passphrase Secret does NOT exist. The
	// source must log and call the parser anyway (with empty Pkcs12Passphrase
	// — so a sane PKCS#12 parser will surface bad_passphrase, but that's
	// the parser's job, not the source's). No panic, no hang.
	certSec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "tls", Namespace: "ns"},
		Type:       corev1.SecretType("kubernetes.io/tls"),
		Data:       map[string][]byte{"keystore.p12": []byte("blob")},
	}
	client := fake.NewSimpleClientset(certSec)

	parser := &recordingParser{}
	src := New(Options{
		Name: "k", Client: client, ResyncEvery: 10 * time.Minute,
		SecretRules: []SecretTypeRule{{
			Type:                "kubernetes.io/tls",
			KeyRe:               regexp.MustCompile(`^keystore\.p12$`),
			PassphraseSecretRef: &PassphraseSecretRef{Name: "missing", Key: "pp"},
			Parser:              parser,
		}},
	}, nopLogger())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sink := &fakeSink{}
	go func() { _ = src.Run(ctx, sink) }()

	waitFor(t, func() bool { return len(parser.snapshot()) >= 1 }, "parser called")

	if got := parser.snapshot()[0].Pkcs12Passphrase; got != "" {
		t.Fatalf("Pkcs12Passphrase = %q, want empty (missing ref)", got)
	}
}

func TestPassphraseSecretRefMissingKeyLogsAndContinues(t *testing.T) {
	certSec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "tls", Namespace: "ns"},
		Type:       corev1.SecretType("kubernetes.io/tls"),
		Data:       map[string][]byte{"keystore.p12": []byte("blob")},
	}
	ppSec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "pp", Namespace: "ns"},
		// "other" key exists but the ref points at "missing"
		Data: map[string][]byte{"other": []byte("xxx")},
	}
	client := fake.NewSimpleClientset(certSec, ppSec)

	parser := &recordingParser{}
	src := New(Options{
		Name: "k", Client: client, ResyncEvery: 10 * time.Minute,
		SecretRules: []SecretTypeRule{{
			Type:                "kubernetes.io/tls",
			KeyRe:               regexp.MustCompile(`^keystore\.p12$`),
			PassphraseSecretRef: &PassphraseSecretRef{Name: "pp", Key: "missing"},
			Parser:              parser,
		}},
	}, nopLogger())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sink := &fakeSink{}
	go func() { _ = src.Run(ctx, sink) }()

	waitFor(t, func() bool { return len(parser.snapshot()) >= 1 }, "parser called")

	if got := parser.snapshot()[0].Pkcs12Passphrase; got != "" {
		t.Fatalf("Pkcs12Passphrase = %q, want empty (key missing)", got)
	}
}
