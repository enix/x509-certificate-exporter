// Package secauth generates a self-contained PKI bundle plus an
// exporter-toolkit `web.config.file` for the e2e secauth release, where
// the chart enforces TLS + mTLS + basic_auth simultaneously.
//
// The seeder calls Generate() once per run, materialises the server-side
// half (server cert/key, CA bundle, webconfig.yaml) as a Kubernetes
// Secret consumed by the chart, and serialises the client-side half
// (CA, client cert/key, plaintext password) to a JSON file the e2e
// test reads on the host.
//
// Validity window is intentionally small (1h) and starts five minutes
// in the past to absorb any clock skew between the host running `tilt`
// and the k3d node running the exporter pod.
package secauth

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"

	"github.com/enix/x509-certificate-exporter/v4/dev/scenarios"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
)

// Username and Password are constants so the e2e values.yaml and the test
// can reference the same credentials without round-tripping a runtime
// secret. Plaintext password is fine in this context — the whole bundle
// is regenerated every seed run and only ever lives on the host running
// `task test:e2e` and inside the throwaway k3d node.
const (
	Username = "e2e"
	Password = "test-password"
)

// Bundle holds the full PKI material for one secauth release.
type Bundle struct {
	CACertPEM     []byte
	ServerCertPEM []byte
	ServerKeyPEM  []byte
	ClientCertPEM []byte
	ClientKeyPEM  []byte
	WebConfigYAML []byte
}

// SecretData returns the keys/values to put in the chart-mounted Secret.
// Only `webconfig.yaml` is consumed by the chart (it explicitly mounts
// just that key); the cert / key / CA material is embedded inline in
// the YAML via exporter-toolkit's `cert:` / `key:` / `client_ca:`
// fields, so a single Secret with a single key is all the chart needs.
func (b *Bundle) SecretData() map[string][]byte {
	return map[string][]byte{
		"webconfig.yaml": b.WebConfigYAML,
	}
}

// TestBundle is the JSON-serialisable subset the e2e test needs to
// construct a TLS+basic-auth client. The server-side material is
// deliberately omitted — the exporter pod is the sole consumer of those.
type TestBundle struct {
	CACertPEM     string `json:"ca_cert_pem"`
	ClientCertPEM string `json:"client_cert_pem"`
	ClientKeyPEM  string `json:"client_key_pem"`
	Username      string `json:"username"`
	Password      string `json:"password"`
}

// Generate produces a fresh bundle. `serverDNS` are the SANs the server
// cert must carry — typically `127.0.0.1` and the in-cluster Service
// FQDN, so the host-side port-forward and any in-cluster scrape both
// succeed.
func Generate(serverDNS []string) (*Bundle, error) {
	notBefore := time.Now().Add(-5 * time.Minute)
	notAfter := time.Now().Add(1 * time.Hour)

	caCert, caKey, err := scenarios.Selfsigned(scenarios.CertSpec{
		CN:        "x509ce-secauth-e2e-ca",
		O:         []string{"x509ce-e2e"},
		NotBefore: notBefore,
		NotAfter:  notAfter,
		Algo:      scenarios.AlgoECDSAP256,
		IsCA:      true,
	})
	if err != nil {
		return nil, fmt.Errorf("ca: %w", err)
	}

	serverCert, serverKey, err := signLeaf(leafSpec{
		cn:          "x509ce-secauth-server",
		dnsNames:    serverDNS,
		notBefore:   notBefore,
		notAfter:    notAfter,
		extKeyUsage: x509.ExtKeyUsageServerAuth,
	}, caCert, caKey)
	if err != nil {
		return nil, fmt.Errorf("server cert: %w", err)
	}

	clientCert, clientKey, err := signLeaf(leafSpec{
		cn:          "x509ce-secauth-client",
		notBefore:   notBefore,
		notAfter:    notAfter,
		extKeyUsage: x509.ExtKeyUsageClientAuth,
	}, caCert, caKey)
	if err != nil {
		return nil, fmt.Errorf("client cert: %w", err)
	}

	bcryptHash, err := bcrypt.GenerateFromPassword([]byte(Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("bcrypt: %w", err)
	}

	caPEM := scenarios.EncodeCertsPEM(caCert)
	serverCertPEM := scenarios.EncodeCertsPEM(serverCert)
	serverKeyPEM := scenarios.EncodeKeyPEM(serverKey)

	webconfig, err := buildWebConfigYAML(serverCertPEM, serverKeyPEM, caPEM, Username, string(bcryptHash))
	if err != nil {
		return nil, fmt.Errorf("webconfig yaml: %w", err)
	}

	return &Bundle{
		CACertPEM:     caPEM,
		ServerCertPEM: serverCertPEM,
		ServerKeyPEM:  serverKeyPEM,
		ClientCertPEM: scenarios.EncodeCertsPEM(clientCert),
		ClientKeyPEM:  scenarios.EncodeKeyPEM(clientKey),
		WebConfigYAML: webconfig,
	}, nil
}

// WriteTestBundle serialises the client-side material to path as JSON,
// 0600 perms (it carries a private key). Idempotent.
func (b *Bundle) WriteTestBundle(path string) error {
	tb := TestBundle{
		CACertPEM:     string(b.CACertPEM),
		ClientCertPEM: string(b.ClientCertPEM),
		ClientKeyPEM:  string(b.ClientKeyPEM),
		Username:      Username,
		Password:      Password,
	}
	buf, err := json.MarshalIndent(tb, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, buf, 0o600)
}

type leafSpec struct {
	cn          string
	dnsNames    []string
	notBefore   time.Time
	notAfter    time.Time
	extKeyUsage x509.ExtKeyUsage
}

func signLeaf(s leafSpec, parent *x509.Certificate, parentKey crypto.Signer) (*x509.Certificate, crypto.Signer, error) {
	// Need a fresh leaf key with the same algorithm family the rest of the
	// scenarios package settles on; we go through scenarios.CertSpec for
	// key generation only, then build our own template so we can pin the
	// extended key usage (ServerAuth vs ClientAuth) — scenarios.signed
	// would always set ServerAuth.
	_, key, err := scenarios.Selfsigned(scenarios.CertSpec{
		CN:        s.cn + "-keygen-discard",
		NotBefore: s.notBefore,
		NotAfter:  s.notAfter,
		Algo:      scenarios.AlgoECDSAP256,
	})
	if err != nil {
		return nil, nil, err
	}
	tpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject: pkix.Name{
			CommonName:   s.cn,
			Organization: []string{"x509ce-e2e"},
		},
		NotBefore:             s.notBefore,
		NotAfter:              s.notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{s.extKeyUsage},
		DNSNames:              s.dnsNames,
		IPAddresses:           parseIPs(s.dnsNames),
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, parent, key.Public(), parentKey)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	return cert, key, err
}

// serial returns a 128-bit random serial number.
func serial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	return n
}

// parseIPs picks the IP-shaped entries out of dnsNames and converts them
// to net.IP-encoded SANs. x509 needs IPs in IPAddresses, not DNSNames,
// or it won't accept them when the client connects to a literal IP
// (`127.0.0.1`).
func parseIPs(names []string) []net.IP {
	var ips []net.IP
	for _, n := range names {
		if ip := net.ParseIP(n); ip != nil {
			ips = append(ips, ip)
		}
	}
	return ips
}

// buildWebConfigYAML renders the exporter-toolkit web.config.file content
// with server TLS, mTLS client verification, and basic_auth stitched
// into a single config. Cert / key / CA material is inlined via the
// `cert:` / `key:` / `client_ca:` fields (exporter-toolkit accepts
// those as alternatives to `*_file:`) so we can ship the whole bundle
// in the single key the chart's webConfiguration mount exposes.
func buildWebConfigYAML(serverCertPEM, serverKeyPEM, caCertPEM []byte, user, bcryptHash string) ([]byte, error) {
	cfg := map[string]any{
		"tls_server_config": map[string]any{
			"cert":             string(serverCertPEM),
			"key":              string(serverKeyPEM),
			"client_auth_type": "RequireAndVerifyClientCert",
			"client_ca":        string(caCertPEM),
		},
		"basic_auth_users": map[string]string{
			user: bcryptHash,
		},
	}
	return yaml.Marshal(cfg)
}

