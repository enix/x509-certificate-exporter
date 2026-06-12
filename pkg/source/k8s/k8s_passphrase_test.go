package k8s

import (
	"context"
	"regexp"
	"strings"
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

func (p *recordingParser) assertNotCalled(t *testing.T) {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.opts) > 0 {
		t.Fatalf("parser was called %d time(s), expected none", len(p.opts))
	}
}

type recordingRecorder struct {
	mu    sync.Mutex
	calls [][3]string // source_name, resource, reason
}

func (r *recordingRecorder) MarkTransportError(sourceName, resource, reason string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, [3]string{sourceName, resource, reason})
}

func TestRecordTransportErrIsNilSafe(t *testing.T) {
	// No Recorder configured (the library-consumer-without-metrics path):
	// every call site must no-op without panicking.
	src := &Source{opts: Options{Name: "kube"}}
	src.recordTransportErr("secrets", "watch_flapped") // must not panic
}

func TestRecordTransportErrForwardsWithSourceName(t *testing.T) {
	rec := &recordingRecorder{}
	src := &Source{opts: Options{Name: "kube", Recorder: rec}}
	src.recordTransportErr("secrets", "watch_flapped")
	src.recordTransportErr("configmaps", "list_failed")
	if len(rec.calls) != 2 {
		t.Fatalf("want 2 calls, got %d", len(rec.calls))
	}
	if rec.calls[0] != [3]string{"kube", "secrets", "watch_flapped"} {
		t.Errorf("call[0] = %v", rec.calls[0])
	}
	if rec.calls[1] != [3]string{"kube", "configmaps", "list_failed"} {
		t.Errorf("call[1] = %v", rec.calls[1])
	}
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
	src.onSecret(context.Background(), &fakeSink{}, certSec, false)

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
	src.onSecret(context.Background(), &fakeSink{}, certSec, false)

	if got := parser.lastOpts(t).Pkcs12Passphrase; got != "cross-ns-pass" {
		t.Fatalf("Pkcs12Passphrase = %q, want %q", got, "cross-ns-pass")
	}
}

func TestPassphraseSecretRefMissingSecretSkipsParseWhenTryEmptyFalse(t *testing.T) {
	// The passphrase Secret does not exist and tryEmptyPassphrase is false
	// (default). The source must NOT call the parser — it emits a
	// bad_passphrase bundle error directly rather than silently falling
	// through to an empty-passphrase attempt.
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
	sink := &fakeSink{}
	src.onSecret(context.Background(), sink, certSec, false)

	parser.assertNotCalled(t)
}

func TestPassphraseSecretRefMissingSecretContinuesWhenTryEmptyTrue(t *testing.T) {
	// Same setup, but tryEmptyPassphrase: true — source must still call the
	// parser (with empty passphrase) so the parser can decide the outcome.
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
		ParseOpts:           cert.ParseOptions{Pkcs12TryEmpty: true},
		Parser:              parser,
	}
	src := newSource(t, rule, certSec)
	src.onSecret(context.Background(), &fakeSink{}, certSec, false)

	if got := parser.lastOpts(t).Pkcs12Passphrase; got != "" {
		t.Fatalf("Pkcs12Passphrase = %q, want empty", got)
	}
}

func TestPassphraseSecretRefMissingKeySkipsParseWhenTryEmptyFalse(t *testing.T) {
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
	src.onSecret(context.Background(), &fakeSink{}, certSec, false)

	parser.assertNotCalled(t)
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
	src.onSecret(context.Background(), &fakeSink{}, certSec, false)

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
	src.onSecret(context.Background(), &fakeSink{}, certSec, false)

	if got := parser.lastOpts(t).JksPassphrase; got != "cross-ns-jks" {
		t.Fatalf("JksPassphrase = %q, want %q", got, "cross-ns-jks")
	}
}

// soleUpsert returns the single Bundle a fakeSink received, failing if
// the count isn't exactly one. The fail-fast tests use it to inspect
// the bad_passphrase bundle the source emits instead of calling the
// parser.
func soleUpsert(t *testing.T, sink *fakeSink) cert.Bundle {
	t.Helper()
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.upsert) != 1 {
		t.Fatalf("want exactly 1 upsert, got %d", len(sink.upsert))
	}
	return sink.upsert[0]
}

// TestPassphraseFailFastEmitsBadPassphraseBundle pins the output of the
// skip-parse path: one bundle carrying a bundle-level (Index -1)
// bad_passphrase error whose Err names the concrete cause. The earlier
// tests asserted only "parser not called", leaving the emitted metric
// and its reason invisible to the suite.
func TestPassphraseFailFastEmitsBadPassphraseBundle(t *testing.T) {
	certSec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "tls", Namespace: "ns"},
		Type:       corev1.SecretType("kubernetes.io/tls"),
		Data:       map[string][]byte{"keystore.p12": []byte("blob")},
	}
	parser := &recordingParser{}
	rule := SecretTypeRule{
		Type:          "kubernetes.io/tls",
		KeyRe:         regexp.MustCompile(`^keystore\.p12$`),
		PassphraseKey: "missing-key", // not present in the cert Secret
		Parser:        parser,
	}
	src := newSource(t, rule, certSec)
	sink := &fakeSink{}
	src.onSecret(context.Background(), sink, certSec, false)

	parser.assertNotCalled(t)
	b := soleUpsert(t, sink)
	if len(b.Errors) != 1 {
		t.Fatalf("want 1 bundle error, got %d (%v)", len(b.Errors), b.Errors)
	}
	e := b.Errors[0]
	if e.Index != -1 {
		t.Errorf("Index = %d, want -1 (bundle-level)", e.Index)
	}
	if e.Reason != cert.ReasonBadPassphrase {
		t.Errorf("Reason = %q, want bad_passphrase", e.Reason)
	}
	if e.Err == nil || !strings.Contains(e.Err.Error(), "missing-key") {
		t.Errorf("Err = %v, want it to name the missing key", e.Err)
	}
}

// TestPassphraseTwoSourcesOneSucceedsStillParses covers the
// passphraseObtained accumulation: when two passphrase sources are
// configured and at least one yields a value, the parser must be
// called — a regression to "fail if any source fails" would skip it.
func TestPassphraseTwoSourcesOneSucceedsStillParses(t *testing.T) {
	certSec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "tls", Namespace: "ns"},
		Type:       corev1.SecretType("kubernetes.io/tls"),
		Data: map[string][]byte{
			"keystore.p12":    []byte("blob"),
			"inline-pass-key": []byte("from-inline"),
		},
	}
	parser := &recordingParser{}
	rule := SecretTypeRule{
		Type:                "kubernetes.io/tls",
		KeyRe:               regexp.MustCompile(`^keystore\.p12$`),
		PassphraseKey:       "inline-pass-key",                         // present → succeeds
		PassphraseSecretRef: &PassphraseSecretRef{Name: "absent", Key: "pp"}, // fails
		Parser:              parser,
	}
	src := newSource(t, rule, certSec)
	src.onSecret(context.Background(), &fakeSink{}, certSec, false)

	// The inline key won; the failed ref must not have overwritten it.
	if got := parser.lastOpts(t).Pkcs12Passphrase; got != "from-inline" {
		t.Fatalf("Pkcs12Passphrase = %q, want %q (sticky obtained value)", got, "from-inline")
	}
}

// TestPassphraseTwoSourcesBothFailEmitsLastCause verifies that when
// every configured source fails, the emitted bundle error carries the
// last failure's cause (the SecretRef lookup here).
func TestPassphraseTwoSourcesBothFailEmitsLastCause(t *testing.T) {
	certSec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "tls", Namespace: "ns"},
		Type:       corev1.SecretType("kubernetes.io/tls"),
		Data:       map[string][]byte{"keystore.p12": []byte("blob")},
	}
	parser := &recordingParser{}
	rule := SecretTypeRule{
		Type:                "kubernetes.io/tls",
		KeyRe:               regexp.MustCompile(`^keystore\.p12$`),
		PassphraseKey:       "missing-key",                              // fails first
		PassphraseSecretRef: &PassphraseSecretRef{Name: "absent", Key: "pp"}, // fails last
		Parser:              parser,
	}
	src := newSource(t, rule, certSec)
	sink := &fakeSink{}
	src.onSecret(context.Background(), sink, certSec, false)

	parser.assertNotCalled(t)
	b := soleUpsert(t, sink)
	if len(b.Errors) != 1 || b.Errors[0].Err == nil {
		t.Fatalf("want 1 bundle error with a cause, got %v", b.Errors)
	}
	if got := b.Errors[0].Err.Error(); !strings.Contains(got, "absent") {
		t.Errorf("Err = %q, want last cause (SecretRef lookup of 'absent')", got)
	}
}

// TestJksTryEmptyDrivesFailFast pins the format switch in onSecret:
// for a JKS rule the skip-parse decision must read JksTryEmpty, not
// Pkcs12TryEmpty. The two cases below would both break if the switch
// arms were swapped.
func TestJksTryEmptyDrivesFailFast(t *testing.T) {
	mkCertSec := func() *corev1.Secret {
		return &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "ks", Namespace: "ns"},
			Type:       corev1.SecretType("Opaque"),
			Data:       map[string][]byte{"truststore.jks": []byte("blob")},
		}
	}

	t.Run("JksTryEmpty=true parses despite missing key", func(t *testing.T) {
		parser := &recordingParser{format: cert.FormatJKS}
		rule := SecretTypeRule{
			Type:             "Opaque",
			KeyRe:            regexp.MustCompile(`^truststore\.jks$`),
			JksPassphraseKey: "missing",
			// Pkcs12TryEmpty deliberately false: if the switch read it
			// instead of JksTryEmpty, this would wrongly skip the parser.
			ParseOpts: cert.ParseOptions{JksTryEmpty: true},
			Parser:    parser,
		}
		src := newSource(t, rule, mkCertSec())
		src.onSecret(context.Background(), &fakeSink{}, mkCertSec(), false)
		if got := parser.lastOpts(t).JksPassphrase; got != "" {
			t.Fatalf("JksPassphrase = %q, want empty", got)
		}
	})

	t.Run("JksTryEmpty=false skips parse even if Pkcs12TryEmpty=true", func(t *testing.T) {
		parser := &recordingParser{format: cert.FormatJKS}
		rule := SecretTypeRule{
			Type:             "Opaque",
			KeyRe:            regexp.MustCompile(`^truststore\.jks$`),
			JksPassphraseKey: "missing",
			// Trap: Pkcs12TryEmpty true must be ignored for a JKS rule.
			ParseOpts: cert.ParseOptions{Pkcs12TryEmpty: true, JksTryEmpty: false},
			Parser:    parser,
		}
		src := newSource(t, rule, mkCertSec())
		sink := &fakeSink{}
		src.onSecret(context.Background(), sink, mkCertSec(), false)
		parser.assertNotCalled(t)
		if b := soleUpsert(t, sink); b.Errors[0].Reason != cert.ReasonBadPassphrase {
			t.Fatalf("reason = %q, want bad_passphrase", b.Errors[0].Reason)
		}
	})
}

// TestPassphraseKeyTrimsOnlyCRLF verifies the secret-sourced passphrase
// is trimmed of trailing CR/LF only — interior and significant spaces
// must survive (a passphrase legitimately containing spaces).
func TestPassphraseKeyTrimsOnlyCRLF(t *testing.T) {
	certSec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "tls", Namespace: "ns"},
		Type:       corev1.SecretType("kubernetes.io/tls"),
		Data: map[string][]byte{
			"keystore.p12": []byte("blob"),
			"pp":           []byte("  pass with spaces  \r\n"),
		},
	}
	parser := &recordingParser{}
	rule := SecretTypeRule{
		Type:          "kubernetes.io/tls",
		KeyRe:         regexp.MustCompile(`^keystore\.p12$`),
		PassphraseKey: "pp",
		Parser:        parser,
	}
	src := newSource(t, rule, certSec)
	src.onSecret(context.Background(), &fakeSink{}, certSec, false)

	if got := parser.lastOpts(t).Pkcs12Passphrase; got != "  pass with spaces  " {
		t.Fatalf("Pkcs12Passphrase = %q, want CR/LF trimmed but spaces kept", got)
	}
}
