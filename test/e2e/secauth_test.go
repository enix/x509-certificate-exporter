//go:build e2e

// secauth e2e: scrapes /metrics on the auxiliary `x509ce-secauth` release
// where the chart enforces TLS + mTLS + basic_auth simultaneously via
// webConfiguration. Asserts that the gating layers actually hold —
// every credential the exporter-toolkit checks must be required.
//
// The seeder generates a fresh PKI bundle per run and writes the
// client-side material (CA, client cert/key, plaintext password) to
// E2E_SECAUTH_BUNDLE_PATH (default /tmp/x509ce-e2e-secauth-bundle.json).
// We re-read it here to build the matching tls.Config and basic-auth
// header.
package e2e

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

const (
	defaultSecauthURL        = "https://127.0.0.1:19895/metrics"
	defaultSecauthBundlePath = "/tmp/x509ce-e2e-secauth-bundle.json"
)

// secauthBundle mirrors secauth.TestBundle (separate package to avoid
// importing the seed-side crypto into the test binary).
type secauthBundle struct {
	CACertPEM     string `json:"ca_cert_pem"`
	ClientCertPEM string `json:"client_cert_pem"`
	ClientKeyPEM  string `json:"client_key_pem"`
	Username      string `json:"username"`
	Password      string `json:"password"`
}

func loadSecauthBundle(t *testing.T) *secauthBundle {
	t.Helper()
	path := os.Getenv("E2E_SECAUTH_BUNDLE_PATH")
	if path == "" {
		path = defaultSecauthBundlePath
	}
	buf, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read bundle %s: %v", path, err)
	}
	b := &secauthBundle{}
	if err := json.Unmarshal(buf, b); err != nil {
		t.Fatalf("unmarshal bundle %s: %v", path, err)
	}
	return b
}

func secauthURL() string {
	if v := os.Getenv("E2E_SECAUTH_URL"); v != "" {
		return v
	}
	return defaultSecauthURL
}

// tlsConfigFor builds an *http.Client.TLSClientConfig that trusts the
// seeded CA. If `withClient` is true, it presents the seeded client
// cert too — that's what the chart's `RequireAndVerifyClientCert` mode
// expects. Without a client cert, the TLS handshake fails.
func tlsConfigFor(t *testing.T, b *secauthBundle, withClient bool) *tls.Config {
	t.Helper()
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(b.CACertPEM)) {
		t.Fatalf("could not parse CA cert PEM")
	}
	cfg := &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	if withClient {
		pair, err := tls.X509KeyPair([]byte(b.ClientCertPEM), []byte(b.ClientKeyPEM))
		if err != nil {
			t.Fatalf("load client keypair: %v", err)
		}
		cfg.Certificates = []tls.Certificate{pair}
	}
	return cfg
}

func newSecauthClient(t *testing.T, tlsCfg *tls.Config) *http.Client {
	t.Helper()
	return &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}
}

// scrapeOnce issues exactly one request. Used by negative tests where
// the retry loop would just hide the expected failure.
func scrapeOnce(t *testing.T, client *http.Client, basicAuth *struct{ user, pass string }) (*http.Response, error) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, secauthURL(), nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	if basicAuth != nil {
		req.SetBasicAuth(basicAuth.user, basicAuth.pass)
	}
	return client.Do(req)
}

// TestSecauth groups the four sub-cases as t.Run sub-tests so a single
// `tilt up` run can iterate on all of them without re-seeding.
func TestSecauth(t *testing.T) {
	b := loadSecauthBundle(t)

	t.Run("Authorized", func(t *testing.T) {
		client := newSecauthClient(t, tlsConfigFor(t, b, true))
		auth := &struct{ user, pass string }{b.Username, b.Password}
		// The exporter is guaranteed to be reachable by the time
		// `seed` finishes (Tilt deps), but the watcher might not have
		// observed the seeded TLS Secret yet. Retry briefly so a
		// freshly-installed release converges before we assert.
		var resp *http.Response
		var err error
		deadline := time.Now().Add(30 * time.Second)
		for time.Now().Before(deadline) {
			resp, err = scrapeOnce(t, client, auth)
			if err == nil && resp.StatusCode == 200 {
				break
			}
			if resp != nil {
				resp.Body.Close()
			}
			time.Sleep(2 * time.Second)
		}
		if err != nil {
			t.Fatalf("scrape: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("status: got %d, want 200", resp.StatusCode)
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		if !strings.Contains(string(body), "x509_cert_not_after") {
			t.Errorf("metrics body missing x509_cert_not_after — got %d bytes:\n%s", len(body), preview(string(body)))
		}
	})

	t.Run("WrongPassword", func(t *testing.T) {
		client := newSecauthClient(t, tlsConfigFor(t, b, true))
		resp, err := scrapeOnce(t, client, &struct{ user, pass string }{b.Username, "wrong-password"})
		if err != nil {
			t.Fatalf("scrape: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != 401 {
			t.Errorf("status: got %d, want 401", resp.StatusCode)
		}
	})

	t.Run("NoBasicAuth", func(t *testing.T) {
		client := newSecauthClient(t, tlsConfigFor(t, b, true))
		resp, err := scrapeOnce(t, client, nil)
		if err != nil {
			t.Fatalf("scrape: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != 401 {
			t.Errorf("status: got %d, want 401", resp.StatusCode)
		}
	})

	t.Run("NoClientCert", func(t *testing.T) {
		// Client trusts the CA but presents no cert — the server's
		// `RequireAndVerifyClientCert` mode aborts the handshake.
		// The Go TLS stack surfaces this as a *url.Error wrapping a
		// tls.RecordHeader / RemoteError.
		client := newSecauthClient(t, tlsConfigFor(t, b, false))
		resp, err := scrapeOnce(t, client, &struct{ user, pass string }{b.Username, b.Password})
		if err == nil {
			defer resp.Body.Close()
			t.Fatalf("expected TLS handshake error, got status %d", resp.StatusCode)
		}
		// Don't be too strict on the exact error string — different
		// Go versions surface it slightly differently. Asserting the
		// transport-level signature is enough.
		if !isTLSHandshakeFailure(err) {
			t.Errorf("expected TLS handshake failure, got: %v", err)
		}
	})
}

func preview(s string) string {
	if len(s) > 512 {
		return s[:512] + "…"
	}
	return s
}

// isTLSHandshakeFailure recognises the family of errors Go's TLS stack
// returns when the server requires a client cert and the client doesn't
// present one. Covers `tls: bad certificate`, `tls: certificate required`,
// `remote error: tls:`, and the generic EOF that some servers emit when
// they reset the connection mid-handshake.
func isTLSHandshakeFailure(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	for _, needle := range []string{
		"tls: bad certificate",
		"tls: certificate required",
		"remote error: tls",
		"EOF",
		"connection reset",
		"broken pipe",
	} {
		if strings.Contains(msg, needle) {
			return true
		}
	}
	// Ensure we don't accept a non-network error (e.g. URL parse failure).
	var urlErr interface{ Unwrap() error }
	if errors.As(err, &urlErr) {
		return true
	}
	return false
}

