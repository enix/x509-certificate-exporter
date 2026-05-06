// Package scenarios is the single source of truth for what the dev cluster
// holds and what the e2e suite expects to find on /metrics.
//
// The seed (dev/seed) reads All() and creates the corresponding Kubernetes
// objects. The e2e test (test/e2e) reads All() and asserts each Expect entry
// against scraped Prometheus metrics. Keeping both consumers tied to the
// same data structure means coverage and assertions move together.
//
// Scenarios are deterministic at build time within a single process: All()
// is computed once and cached. Re-running All() in a different process (the
// seed and the test do run separately) produces freshly generated keys/serials
// — that's fine because the assertions key off (namespace, name, key, CN),
// none of which depend on per-byte cert content.
package scenarios

import (
	"crypto/x509"
	"sync"
	"time"
)

const (
	// Common passphrase for all encrypted PKCS#12 fixtures. The dev seed
	// stores it as a sibling key in the same Secret; the chart's
	// secretTypes.pkcs12.passphraseKey points to that key.
	PKCS12Passphrase    = "letmein"
	PKCS12PassphraseKey = "keystore-passphrase"
)

// Lifecycle classifies the temporal state of an expected cert.
type Lifecycle int

const (
	LifecycleValid       Lifecycle = iota // 0 ≤ now-NotBefore, NotAfter > now
	LifecycleExpired                      // NotAfter < now → x509_cert_expired==1
	LifecycleNotYetValid                  // NotBefore > now → x509_cert_expired==0 and not_before > now
)

// ParseError mirrors cert.Reason* strings used by the exporter for
// per-bundle error metrics. Empty string means "no error expected".
type ParseError string

const (
	ErrNone           ParseError = ""
	ErrBadPEM         ParseError = "bad_pem"
	ErrBadPKCS12      ParseError = "bad_pkcs12"
	ErrBadPassphrase  ParseError = "bad_passphrase"
	ErrNoCertificates ParseError = "no_certificate_found"
)

// ExpectCert is one expected cert series — i.e. one row in the scraped
// metric output for the parent Scenario.
type ExpectCert struct {
	Key       string    // matches the secret_key / configmap_key label
	SubjectCN string    // matches the subject_CN label
	Lifecycle Lifecycle // valid / expired / not yet valid
	NotBefore time.Time // for sanity checks (informational)
	NotAfter  time.Time // for sanity checks (informational)

	// ParseError, when non-empty, means this entry is a parse failure
	// (no x509_cert_not_after series to assert; instead we expect the
	// exporter's x509_source_errors_total{reason=ParseError} to grow).
	ParseError ParseError

	// ExposedLabels are the user-configured object labels expected to
	// appear on the emitted series as Prometheus labels named
	// `secret_label_<key>` (or `configmap_label_<key>`). The map's keys
	// are the bare label names (matching what was configured via
	// `exposeSecretLabels` / `exposeConfigMapLabels` — no prefix); the
	// map's values are the expected values. Empty / nil means
	// "don't assert".
	ExposedLabels map[string]string
}

// Scenario is one Kubernetes object the seed will materialise.
type Scenario struct {
	Namespace string
	Name      string

	// Kind: "Secret" or "ConfigMap".
	Kind string

	// SecretType applies only to Kind=="Secret"; e.g. "kubernetes.io/tls"
	// or "Opaque".
	SecretType string

	// Data: keys → bytes (the seed copies these into the object's Data).
	Data map[string][]byte

	// Labels applied to the object itself.
	Labels map[string]string

	// NamespaceLabels applied to the namespace when the seed first creates
	// it. Multiple scenarios in the same namespace may set this; the seed
	// merges. The expected use case is gating the exporter via include/
	// exclude namespace labels.
	NamespaceLabels map[string]string

	// Watched is true if the exporter is configured to discover this
	// object. Watched=false scenarios verify the negative case: the
	// object is present but never appears in x509_cert_* series.
	Watched bool

	// Expect holds the per-cert-row attestations for the e2e test.
	// Empty when Watched=false.
	Expect []ExpectCert
}

var (
	once   sync.Once
	cached []Scenario
)

// All returns the full scenario list, computed once per process.
func All() []Scenario {
	once.Do(build)
	return cached
}

func build() {
	now := time.Now().UTC().Truncate(time.Second)
	in := now.Add
	day := 24 * time.Hour

	var sc []Scenario

	// ─── kubernetes.io/tls — lifecycles ─────────────────────────────────
	sc = append(sc, mkTLSLeaf("x509ce-fresh", "valid-1y", "valid-1y.example.test",
		in(-time.Hour), in(365*day), AlgoRSA2048, LifecycleValid))
	sc = append(sc, mkTLSLeaf("x509ce-fresh", "valid-90d", "valid-90d.example.test",
		in(-time.Hour), in(90*day), AlgoECDSAP256, LifecycleValid))
	sc = append(sc, mkTLSLeaf("x509ce-warn", "soon-7d", "soon-7d.example.test",
		in(-30*day), in(7*day), AlgoRSA2048, LifecycleValid))
	sc = append(sc, mkTLSLeaf("x509ce-warn", "soon-1d", "soon-1d.example.test",
		in(-90*day), in(36*time.Hour), AlgoRSA2048, LifecycleValid))
	sc = append(sc, mkTLSLeaf("x509ce-expired", "expired-1d", "expired-1d.example.test",
		in(-365*day), in(-time.Hour), AlgoRSA2048, LifecycleExpired))
	sc = append(sc, mkTLSLeaf("x509ce-expired", "expired-30d", "expired-30d.example.test",
		in(-365*day), in(-30*day), AlgoRSA2048, LifecycleExpired))
	sc = append(sc, mkTLSLeaf("x509ce-future", "not-yet-valid", "not-yet-valid.example.test",
		in(7*day), in(180*day), AlgoRSA2048, LifecycleNotYetValid))

	// ─── kubernetes.io/tls — key algorithms ─────────────────────────────
	sc = append(sc, mkTLSLeaf("x509ce-algos", "rsa-4096", "rsa-4096.example.test",
		in(-time.Hour), in(180*day), AlgoRSA4096, LifecycleValid))
	sc = append(sc, mkTLSLeaf("x509ce-algos", "ecdsa-p384", "ecdsa-p384.example.test",
		in(-time.Hour), in(180*day), AlgoECDSAP384, LifecycleValid))
	sc = append(sc, mkTLSLeaf("x509ce-algos", "ed25519", "ed25519.example.test",
		in(-time.Hour), in(180*day), AlgoEd25519, LifecycleValid))

	// ─── kubernetes.io/tls — full chain in tls.crt ──────────────────────
	sc = append(sc, mkTLSChain("x509ce-fresh", "full-chain", "leaf.chain.example.test",
		in(-time.Hour), in(180*day), AlgoECDSAP256))

	// ─── kubernetes.io/tls — full DN + exposed labels ───────────────────
	leafCert, leafKey, err := Selfsigned(CertSpec{
		CN: "rich-dn.example.test",
		O:  []string{"Enix"}, OU: []string{"Platform", "SRE"},
		C: []string{"FR"}, ST: []string{"Île-de-France"}, L: []string{"Paris"},
		DNSNames:  []string{"rich-dn.example.test"},
		NotBefore: in(-time.Hour), NotAfter: in(180 * day),
		Algo: AlgoECDSAP256,
	})
	must(err)
	sc = append(sc, Scenario{
		Namespace: "x509ce-labels", Name: "rich-dn",
		Kind: "Secret", SecretType: "kubernetes.io/tls",
		Data: map[string][]byte{
			"tls.crt": EncodeCertsPEM(leafCert),
			"tls.key": EncodeKeyPEM(leafKey),
		},
		Labels: map[string]string{
			"app.kubernetes.io/name": "rich-dn-app",
			"environment":            "production",
			"team":                   "platform",
		},
		Watched: true,
		Expect: []ExpectCert{{
			Key: "tls.crt", SubjectCN: "rich-dn.example.test", Lifecycle: LifecycleValid,
			NotBefore: in(-time.Hour), NotAfter: in(180 * day),
			// `environment` and `team` are listed in dev/values.yaml's
			// exposeSecretLabels and applied to this Secret above. The
			// e2e suite asserts the resulting `secret_label_environment`
			// and `secret_label_team` Prometheus labels carry these
			// exact values — guards against drift between the writer
			// (Kubernetes source) and reader (registry label builder)
			// sides of the prefix contract.
			ExposedLabels: map[string]string{
				"environment": "production",
				"team":        "platform",
			},
		}},
	})

	// ─── Opaque — PEM with custom data key ──────────────────────────────
	cert1, _, err := Selfsigned(CertSpec{
		CN: "opaque-pem.example.test", DNSNames: []string{"opaque-pem.example.test"},
		NotBefore: in(-time.Hour), NotAfter: in(120 * day), Algo: AlgoRSA2048,
	})
	must(err)
	sc = append(sc, Scenario{
		Namespace: "x509ce-opaque-pem", Name: "single-cert",
		Kind: "Secret", SecretType: "Opaque",
		Data:    map[string][]byte{"cert.pem": EncodeCertsPEM(cert1)},
		Watched: true,
		Expect: []ExpectCert{{
			Key: "cert.pem", SubjectCN: "opaque-pem.example.test", Lifecycle: LifecycleValid,
		}},
	})

	// ─── Opaque — PKCS#12 with passphrase (passphraseKey) ───────────────
	leafKey2, chain2, err := Chain("pkcs12-encrypted.example.test",
		in(-time.Hour), in(180*day), AlgoECDSAP256)
	must(err)
	p12Encrypted, err := EncodePKCS12Chain(leafKey2, chain2, PKCS12Passphrase)
	must(err)
	sc = append(sc, Scenario{
		Namespace: "x509ce-pkcs12", Name: "encrypted",
		Kind: "Secret", SecretType: "Opaque",
		Data: map[string][]byte{
			"keystore.p12":      p12Encrypted,
			PKCS12PassphraseKey: []byte(PKCS12Passphrase),
		},
		Watched: true,
		Expect: []ExpectCert{
			{Key: "keystore.p12", SubjectCN: "pkcs12-encrypted.example.test", Lifecycle: LifecycleValid},
			{Key: "keystore.p12", SubjectCN: "Dev Seed Intermediate CA", Lifecycle: LifecycleValid},
			{Key: "keystore.p12", SubjectCN: "Dev Seed Root CA", Lifecycle: LifecycleValid},
		},
	})

	// ─── Opaque — PKCS#12 passwordless ──────────────────────────────────
	leafKey3, chain3, err := Chain("pkcs12-empty.example.test",
		in(-time.Hour), in(120*day), AlgoRSA2048)
	must(err)
	p12Empty, err := EncodePKCS12Passwordless(leafKey3, chain3)
	must(err)
	sc = append(sc, Scenario{
		Namespace: "x509ce-pkcs12", Name: "passwordless",
		Kind: "Secret", SecretType: "Opaque",
		Data:    map[string][]byte{"keystore-empty.p12": p12Empty},
		Watched: true,
		Expect: []ExpectCert{
			{Key: "keystore-empty.p12", SubjectCN: "pkcs12-empty.example.test", Lifecycle: LifecycleValid},
			{Key: "keystore-empty.p12", SubjectCN: "Dev Seed Intermediate CA", Lifecycle: LifecycleValid},
			{Key: "keystore-empty.p12", SubjectCN: "Dev Seed Root CA", Lifecycle: LifecycleValid},
		},
	})

	// ─── Opaque — PKCS#12 truststore (multiple CAs) ─────────────────────
	caCert1, _, err := Selfsigned(CertSpec{
		CN: "Trust Anchor One", O: []string{"x509ce-dev"},
		NotBefore: in(-time.Hour), NotAfter: in(720 * day),
		Algo: AlgoECDSAP256, IsCA: true,
	})
	must(err)
	caCert2, _, err := Selfsigned(CertSpec{
		CN: "Trust Anchor Two", O: []string{"x509ce-dev"},
		NotBefore: in(-time.Hour), NotAfter: in(720 * day),
		Algo: AlgoRSA2048, IsCA: true,
	})
	must(err)
	p12Truststore, err := EncodePKCS12TrustStore([]*x509.Certificate{caCert1, caCert2}, PKCS12Passphrase)
	must(err)
	sc = append(sc, Scenario{
		Namespace: "x509ce-pkcs12", Name: "truststore",
		Kind: "Secret", SecretType: "Opaque",
		Data: map[string][]byte{
			"truststore.p12":    p12Truststore,
			PKCS12PassphraseKey: []byte(PKCS12Passphrase),
		},
		Watched: true,
		Expect: []ExpectCert{
			{Key: "truststore.p12", SubjectCN: "Trust Anchor One", Lifecycle: LifecycleValid},
			{Key: "truststore.p12", SubjectCN: "Trust Anchor Two", Lifecycle: LifecycleValid},
		},
	})

	// ─── ConfigMap — PEM ────────────────────────────────────────────────
	cmCert, _, err := Selfsigned(CertSpec{
		CN: "configmap.example.test", DNSNames: []string{"configmap.example.test"},
		NotBefore: in(-time.Hour), NotAfter: in(180 * day), Algo: AlgoECDSAP256,
	})
	must(err)
	sc = append(sc, Scenario{
		Namespace: "x509ce-configmaps", Name: "tls-bundle",
		Kind: "ConfigMap",
		Data: map[string][]byte{
			"tls.crt": EncodeCertsPEM(cmCert),
		},
		Labels: map[string]string{
			"app.kubernetes.io/name": "tls-bundle-app",
			"environment":            "production",
			"team":                   "platform",
		},
		Watched: true,
		Expect: []ExpectCert{
			{
				Key: "tls.crt", SubjectCN: "configmap.example.test", Lifecycle: LifecycleValid,
				// `environment` and `team` are listed in dev/values.yaml's
				// exposeConfigMapLabels and applied to this ConfigMap above.
				// Asserts the chart's configMaps.exposeLabels feature
				// reaches the registry's `configmap_label_*` series.
				ExposedLabels: map[string]string{
					"environment": "production",
					"team":        "platform",
				},
			},
		},
	})

	// ─── Errors — corrupt PEM, corrupt PKCS#12, wrong passphrase ────────
	// Valid base64 of bytes that do not parse as a certificate → bad_pem
	// (with Index>=0 so x509_cert_error gets a series). The matching
	// `tls.key` is intentionally a real key for an unrelated cert: the
	// kube-apiserver will warn about the cert being malformed (which
	// is the whole point of this fixture and its expected ParseError
	// assertion) but won't add a separate, unrelated warning about
	// missing PEM data on the key.
	_, badPEMKey, err := Selfsigned(CertSpec{
		CN:        "bad-pem-companion-key",
		NotBefore: in(-time.Hour),
		NotAfter:  in(day),
		Algo:      AlgoRSA2048,
	})
	must(err)
	sc = append(sc, Scenario{
		Namespace: "x509ce-errors", Name: "bad-pem",
		Kind: "Secret", SecretType: "kubernetes.io/tls",
		Data: map[string][]byte{
			"tls.crt": []byte("-----BEGIN CERTIFICATE-----\nQUFBQUFBQUFBQUFBQUFBQQ==\n-----END CERTIFICATE-----\n"),
			"tls.key": EncodeKeyPEM(badPEMKey),
		},
		Watched: true,
		Expect:  []ExpectCert{{Key: "tls.crt", ParseError: ErrBadPEM}},
	})

	sc = append(sc, Scenario{
		Namespace: "x509ce-errors", Name: "bad-pkcs12",
		Kind: "Secret", SecretType: "Opaque",
		Data: map[string][]byte{
			"keystore.p12":      []byte("garbage-not-pkcs12"),
			PKCS12PassphraseKey: []byte(PKCS12Passphrase),
		},
		Watched: true,
		Expect:  []ExpectCert{{Key: "keystore.p12", ParseError: ErrBadPKCS12}},
	})

	leafKey4, chain4, err := Chain("pkcs12-wrongpw.example.test",
		in(-time.Hour), in(180*day), AlgoRSA2048)
	must(err)
	p12WrongPw, err := EncodePKCS12Chain(leafKey4, chain4, PKCS12Passphrase)
	must(err)
	sc = append(sc, Scenario{
		Namespace: "x509ce-errors", Name: "wrong-passphrase",
		Kind: "Secret", SecretType: "Opaque",
		Data: map[string][]byte{
			"keystore.p12":      p12WrongPw,
			PKCS12PassphraseKey: []byte("not-the-right-password"),
		},
		Watched: true,
		Expect:  []ExpectCert{{Key: "keystore.p12", ParseError: ErrBadPassphrase}},
	})

	// ─── Negative — namespace excluded by label ─────────────────────────
	hiddenCert, hiddenKey, err := Selfsigned(CertSpec{
		CN: "hidden.example.test", DNSNames: []string{"hidden.example.test"},
		NotBefore: in(-time.Hour), NotAfter: in(180 * day), Algo: AlgoRSA2048,
	})
	must(err)
	sc = append(sc, Scenario{
		Namespace: "x509ce-ignored", Name: "hidden-by-ns-label",
		Kind: "Secret", SecretType: "kubernetes.io/tls",
		Data: map[string][]byte{
			"tls.crt": EncodeCertsPEM(hiddenCert),
			"tls.key": EncodeKeyPEM(hiddenKey),
		},
		NamespaceLabels: map[string]string{
			"x509ce-test/ignore": "true",
		},
		Watched: false,
	})

	// ─── Negative — namespace excluded by name ─────────────────────────
	hiddenByName, hiddenByNameKey, err := Selfsigned(CertSpec{
		CN: "hidden-by-name.example.test", DNSNames: []string{"hidden-by-name.example.test"},
		NotBefore: in(-time.Hour), NotAfter: in(180 * day), Algo: AlgoRSA2048,
	})
	must(err)
	sc = append(sc, Scenario{
		Namespace: "x509ce-excl-name", Name: "hidden-by-ns-name",
		Kind: "Secret", SecretType: "kubernetes.io/tls",
		Data: map[string][]byte{
			"tls.crt": EncodeCertsPEM(hiddenByName),
			"tls.key": EncodeKeyPEM(hiddenByNameKey),
		},
		Watched: false,
	})

	// ─── Negative — secret of a watched type but no matching key ───────
	// Opaque type IS in `secretTypes` (with several known keys). This
	// fixture's keys deliberately match NONE of them. The exporter
	// should silently ignore it: no x509_cert_* series, no
	// x509_source_errors_total — it's not an error, just not relevant.
	sc = append(sc, Scenario{
		Namespace: "x509ce-fresh", Name: "no-matching-key",
		Kind: "Secret", SecretType: "Opaque",
		Data: map[string][]byte{
			"some-random-data": []byte("not a cert, not even base64"),
			"another-key":      []byte("still not a cert"),
		},
		Watched: false,
	})

	// ─── Negative — secret excluded by label (server-side selector) ────
	hiddenSecCert, hiddenSecKey, err := Selfsigned(CertSpec{
		CN: "hidden-secret-label.example.test", DNSNames: []string{"hidden-secret-label.example.test"},
		NotBefore: in(-time.Hour), NotAfter: in(180 * day), Algo: AlgoRSA2048,
	})
	must(err)
	sc = append(sc, Scenario{
		Namespace: "x509ce-fresh", Name: "labelled-out",
		Kind: "Secret", SecretType: "kubernetes.io/tls",
		Data: map[string][]byte{
			"tls.crt": EncodeCertsPEM(hiddenSecCert),
			"tls.key": EncodeKeyPEM(hiddenSecKey),
		},
		Labels: map[string]string{
			"x509ce-test/ignore": "true",
		},
		Watched: false,
	})

	cached = sc
}

// mkTLSLeaf returns a kubernetes.io/tls Secret holding a single self-signed
// leaf cert + matching key in tls.crt / tls.key.
func mkTLSLeaf(ns, name, cn string, notBefore, notAfter time.Time, algo Algo, lc Lifecycle) Scenario {
	cert, key, err := Selfsigned(CertSpec{
		CN: cn, DNSNames: []string{cn},
		NotBefore: notBefore, NotAfter: notAfter, Algo: algo,
	})
	must(err)
	return Scenario{
		Namespace: ns, Name: name,
		Kind: "Secret", SecretType: "kubernetes.io/tls",
		Data: map[string][]byte{
			"tls.crt": EncodeCertsPEM(cert),
			"tls.key": EncodeKeyPEM(key),
		},
		Watched: true,
		Expect: []ExpectCert{{
			Key: "tls.crt", SubjectCN: cn, Lifecycle: lc,
			NotBefore: notBefore, NotAfter: notAfter,
		}},
	}
}

// mkTLSChain returns a kubernetes.io/tls Secret whose tls.crt holds a
// concatenated leaf+intermediate+root chain.
func mkTLSChain(ns, name, leafCN string, notBefore, notAfter time.Time, algo Algo) Scenario {
	leafKey, certs, err := Chain(leafCN, notBefore, notAfter, algo)
	must(err)
	return Scenario{
		Namespace: ns, Name: name,
		Kind: "Secret", SecretType: "kubernetes.io/tls",
		Data: map[string][]byte{
			"tls.crt": EncodeCertsPEM(certs...),
			"tls.key": EncodeKeyPEM(leafKey),
		},
		Watched: true,
		Expect: []ExpectCert{
			{Key: "tls.crt", SubjectCN: leafCN, Lifecycle: LifecycleValid, NotBefore: notBefore, NotAfter: notAfter},
			{Key: "tls.crt", SubjectCN: "Dev Seed Intermediate CA", Lifecycle: LifecycleValid},
			{Key: "tls.crt", SubjectCN: "Dev Seed Root CA", Lifecycle: LifecycleValid},
		},
	}
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
