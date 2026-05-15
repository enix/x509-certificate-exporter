package k8s

import (
	"regexp"
	"sync"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/enix/x509-certificate-exporter/v4/pkg/cert"
)

// recordingParser captures the ParseOptions it receives so the test can
// assert that {,Jks}PassphraseSecretRef resolution actually populated
// the right Passphrase field before the parser was invoked.
type recordingParser struct {
	mu     sync.Mutex
	opts   []cert.ParseOptions
	format string // defaults to pkcs12; set to jks to drive the JKS rule path
}

func (p *recordingParser) Format() string {
	if p.format != "" {
		return p.format
	}
	return cert.FormatPKCS12
}

func (p *recordingParser) Parse(_ []byte, ref cert.SourceRef, opts cert.ParseOptions) cert.Bundle {
	p.mu.Lock()
	p.opts = append(p.opts, opts)
	p.mu.Unlock()
	return cert.Bundle{Source: ref}
}

func (p *recordingParser) lastOpts(t *testing.T) cert.ParseOptions {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.opts) == 0 {
		t.Fatal("parser was not called")
	}
	return p.opts[len(p.opts)-1]
}

// newSource builds a minimal Source whose only purpose is to drive
// onSecret directly. Bypasses Run() to avoid the LIST+WATCH event loop
// — these tests target the rule→passphrase resolution logic and the
// surrounding plumbing is exercised by TestSecretsWatchEmits etc.
func newSource(t *testing.T, rule SecretTypeRule, objs ...runtime.Object) *Source {
	t.Helper()
	return &Source{
		opts:     Options{Name: "k", Client: fake.NewSimpleClientset(objs...), SecretRules: []SecretTypeRule{rule}},
		log:      nopLogger().With("source_kind", "kubernetes"),
		tracked:  map[string]struct{}{},
		nsLabels: map[string]map[string]string{},
	}
}

func TestPassphraseSecretRefSameNamespace(t *testing.T) {
	certSec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "tls", Namespace: "ns"},
		Type:       corev1.SecretType("kubernetes.io/tls"),
		Data:       map[string][]byte{"keystore.p12": []byte("blob")},
	}
	ppSec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "tls-pass", Namespace: "ns"},
		Data:       map[string][]byte{"pp": []byte("letmein")},
	}
	parser := &recordingParser{}
	rule := SecretTypeRule{
		Type:                "kubernetes.io/tls",
		KeyRe:               regexp.MustCompile(`^keystore\.p12$`),
		PassphraseSecretRef: &PassphraseSecretRef{Name: "tls-pass", Key: "pp"}, // empty NS → fallback
		Parser:              parser,
	}
	src := newSource(t, rule, certSec, ppSec)
	src.onSecret(&fakeSink{}, certSec, false)

	if got := parser.lastOpts(t).Pkcs12Passphrase; got != "letmein" {
		t.Fatalf("Pkcs12Passphrase = %q, want %q", got, "letmein")
	}
}

func TestPassphraseSecretRefExplicitNamespace(t *testing.T) {
	certSec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "tls", Namespace: "app-ns"},
		Type:       corev1.SecretType("kubernetes.io/tls"),
		Data:       map[string][]byte{"keystore.p12": []byte("blob")},
	}
	ppSec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "vault", Namespace: "kube-system"},
		Data:       map[string][]byte{"pp": []byte("cross-ns-pass\n")}, // trailing newline trimmed
	}
	parser := &recordingParser{}
	rule := SecretTypeRule{
		Type:                "kubernetes.io/tls",
		KeyRe:               regexp.MustCompile(`^keystore\.p12$`),
		PassphraseSecretRef: &PassphraseSecretRef{Namespace: "kube-system", Name: "vault", Key: "pp"},
		Parser:              parser,
	}
	src := newSource(t, rule, certSec, ppSec)
	src.onSecret(&fakeSink{}, certSec, false)

	if got := parser.lastOpts(t).Pkcs12Passphrase; got != "cross-ns-pass" {
		t.Fatalf("Pkcs12Passphrase = %q, want %q", got, "cross-ns-pass")
	}
}

func TestPassphraseSecretRefMissingSecretLogsAndContinues(t *testing.T) {
	// The passphrase Secret does not exist. Source must log and call the
	// parser anyway (with empty Pkcs12Passphrase) — a sane PKCS#12 parser
	// will surface bad_passphrase, but that's the parser's job.
	certSec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "tls", Namespace: "ns"},
		Type:       corev1.SecretType("kubernetes.io/tls"),
		Data:       map[string][]byte{"keystore.p12": []byte("blob")},
	}
	parser := &recordingParser{}
	rule := SecretTypeRule{
		Type:                "kubernetes.io/tls",
		KeyRe:               regexp.MustCompile(`^keystore\.p12$`),
		PassphraseSecretRef: &PassphraseSecretRef{Name: "missing", Key: "pp"},
		Parser:              parser,
	}
	src := newSource(t, rule, certSec)
	src.onSecret(&fakeSink{}, certSec, false)

	if got := parser.lastOpts(t).Pkcs12Passphrase; got != "" {
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
		Data:       map[string][]byte{"other": []byte("xxx")}, // wrong key
	}
	parser := &recordingParser{}
	rule := SecretTypeRule{
		Type:                "kubernetes.io/tls",
		KeyRe:               regexp.MustCompile(`^keystore\.p12$`),
		PassphraseSecretRef: &PassphraseSecretRef{Name: "pp", Key: "missing"},
		Parser:              parser,
	}
	src := newSource(t, rule, certSec, ppSec)
	src.onSecret(&fakeSink{}, certSec, false)

	if got := parser.lastOpts(t).Pkcs12Passphrase; got != "" {
		t.Fatalf("Pkcs12Passphrase = %q, want empty (key missing)", got)
	}
}

func TestJksPassphraseSecretRefSameNamespace(t *testing.T) {
	// Parity check: JksPassphraseSecretRef populates ParseOptions.JksPassphrase,
	// never Pkcs12Passphrase. The parser advertises format jks but routing
	// here is by rule (not by parser.Format()), so this is mostly cosmetic.
	certSec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "tls", Namespace: "ns"},
		Type:       corev1.SecretType("Opaque"),
		Data:       map[string][]byte{"truststore.jks": []byte("blob")},
	}
	ppSec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "jks-pp", Namespace: "ns"},
		Data:       map[string][]byte{"pp": []byte("letmein")},
	}
	parser := &recordingParser{format: cert.FormatJKS}
	rule := SecretTypeRule{
		Type:                   "Opaque",
		KeyRe:                  regexp.MustCompile(`^truststore\.jks$`),
		JksPassphraseSecretRef: &PassphraseSecretRef{Name: "jks-pp", Key: "pp"},
		Parser:                 parser,
	}
	src := newSource(t, rule, certSec, ppSec)
	src.onSecret(&fakeSink{}, certSec, false)

	got := parser.lastOpts(t)
	if got.JksPassphrase != "letmein" {
		t.Fatalf("JksPassphrase = %q, want %q", got.JksPassphrase, "letmein")
	}
	if got.Pkcs12Passphrase != "" {
		t.Fatalf("Pkcs12Passphrase leaked into JKS path: %q", got.Pkcs12Passphrase)
	}
}

func TestJksPassphraseSecretRefExplicitNamespace(t *testing.T) {
	certSec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "ks", Namespace: "app-ns"},
		Type:       corev1.SecretType("Opaque"),
		Data:       map[string][]byte{"truststore.jks": []byte("blob")},
	}
	ppSec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "vault", Namespace: "kube-system"},
		Data:       map[string][]byte{"pp": []byte("cross-ns-jks")},
	}
	parser := &recordingParser{format: cert.FormatJKS}
	rule := SecretTypeRule{
		Type:                   "Opaque",
		KeyRe:                  regexp.MustCompile(`^truststore\.jks$`),
		JksPassphraseSecretRef: &PassphraseSecretRef{Namespace: "kube-system", Name: "vault", Key: "pp"},
		Parser:                 parser,
	}
	src := newSource(t, rule, certSec, ppSec)
	src.onSecret(&fakeSink{}, certSec, false)

	if got := parser.lastOpts(t).JksPassphrase; got != "cross-ns-jks" {
		t.Fatalf("JksPassphrase = %q, want %q", got, "cross-ns-jks")
	}
}
