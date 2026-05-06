//go:build e2e

// rbacproxy e2e: scrapes /metrics on the auxiliary `x509ce-rbacproxy`
// release where the chart fronts the exporter with kube-rbac-proxy.
// Asserts that the proxy's Bearer-token gating actually rejects what
// it should reject — a regression in the chart's wiring (e.g. typo on
// `rbacProxy.enable` vs `rbacProxy.enabled`) would make `NoToken`
// return 200 instead of 401.
//
// `dev/seed/auxiliary.go` pre-creates two ServiceAccounts in the
// `x509ce-rbacproxy` namespace (one bound to a ClusterRole that allows
// GET /metrics, one not). We fetch a Bearer token for each via the
// TokenRequest API and assert the matching response code.
package e2e

import (
	"context"
	"crypto/tls"
	"net/http"
	"os"
	"testing"
	"time"

	authv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	defaultRbacproxyURL     = "https://127.0.0.1:19896/metrics"
	rbacproxyNamespace      = "x509ce-rbacproxy"
	rbacproxyAuthorizedSA   = "e2e-scraper-authorized"
	rbacproxyUnauthorizedSA = "e2e-scraper-unauthorized"
)

func rbacproxyURL() string {
	if v := os.Getenv("E2E_RBACPROXY_URL"); v != "" {
		return v
	}
	return defaultRbacproxyURL
}

func k8sClient(t *testing.T) *kubernetes.Clientset {
	t.Helper()
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		clientcmd.NewDefaultClientConfigLoadingRules(),
		&clientcmd.ConfigOverrides{},
	).ClientConfig()
	if err != nil {
		t.Fatalf("kubeconfig: %v", err)
	}
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	return cs
}

// requestToken issues a TokenRequest for the named ServiceAccount and
// returns the resulting Bearer token. Lifetime is intentionally short —
// the test will use it within seconds.
func requestToken(t *testing.T, cs *kubernetes.Clientset, ns, sa string) string {
	t.Helper()
	ttl := int64(600)
	tr := &authv1.TokenRequest{
		Spec: authv1.TokenRequestSpec{ExpirationSeconds: &ttl},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	got, err := cs.CoreV1().ServiceAccounts(ns).CreateToken(ctx, sa, tr, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("token request for %s/%s: %v", ns, sa, err)
	}
	return got.Status.Token
}

// newRbacproxyClient configures InsecureSkipVerify because kube-rbac-proxy
// generates a self-signed serving cert at startup — we don't have a
// principled way to learn it from outside the pod, and the e2e cluster
// is a sandbox. The cert verification path is exercised by the secauth
// test instead.
func newRbacproxyClient() *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec // sandbox e2e, see comment
				MinVersion:         tls.VersionTLS12,
			},
		},
	}
}

func scrapeRbacproxy(t *testing.T, client *http.Client, bearer string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, rbacproxyURL(), nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("scrape: %v", err)
	}
	return resp
}

// TestRbacproxy groups the three sub-cases. Tokens are fetched once
// per parent test (TokenRequest is fast but adds latency).
func TestRbacproxy(t *testing.T) {
	cs := k8sClient(t)
	authorizedToken := requestToken(t, cs, rbacproxyNamespace, rbacproxyAuthorizedSA)
	unauthorizedToken := requestToken(t, cs, rbacproxyNamespace, rbacproxyUnauthorizedSA)
	client := newRbacproxyClient()

	t.Run("Authorized", func(t *testing.T) {
		// Same converge-then-assert pattern as secauth: the exporter
		// pod may still be coming up when the test starts.
		var resp *http.Response
		deadline := time.Now().Add(30 * time.Second)
		for time.Now().Before(deadline) {
			resp = scrapeRbacproxy(t, client, authorizedToken)
			if resp.StatusCode == 200 {
				break
			}
			resp.Body.Close()
			time.Sleep(2 * time.Second)
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("status: got %d, want 200", resp.StatusCode)
		}
	})

	t.Run("NoToken", func(t *testing.T) {
		resp := scrapeRbacproxy(t, client, "")
		defer resp.Body.Close()
		if resp.StatusCode != 401 {
			t.Errorf("status: got %d, want 401", resp.StatusCode)
		}
	})

	t.Run("Forbidden", func(t *testing.T) {
		resp := scrapeRbacproxy(t, client, unauthorizedToken)
		defer resp.Body.Close()
		if resp.StatusCode != 403 {
			t.Errorf("status: got %d, want 403", resp.StatusCode)
		}
	})
}
