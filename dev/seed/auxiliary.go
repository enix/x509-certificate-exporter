// Auxiliary seeding for the e2e-only secauth and rbacproxy releases.
//
// The main x509-certificate-exporter release (handled by the scenarios
// package) lives in namespace `x509ce-e2e` and exercises the cert
// metric pipeline over plain HTTP. The two auxiliary releases prove the
// chart's auth-gating layers work without re-asserting metric content,
// each in its own namespace:
//
//   - `x509ce-secauth` runs the chart with webConfiguration enforcing
//     TLS + mTLS + basic_auth. We materialise the matching server-side
//     PKI as a Secret consumed by the chart, plus a single TLS Secret
//     so /metrics returns at least one series. The client-side bundle
//     (CA + client cert/key + plaintext password) is written to a JSON
//     file the e2e test reads on the host.
//
//   - `x509ce-rbacproxy` runs the chart with rbacProxy.enabled. We
//     pre-create two ServiceAccounts (one bound to a ClusterRole that
//     allows GET /metrics, one not) so the test can fetch their bearer
//     tokens at runtime and assert 200/401/403 responses.
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/enix/x509-certificate-exporter/v4/dev/scenarios"
	"github.com/enix/x509-certificate-exporter/v4/dev/scenarios/secauth"
)

const (
	secauthNamespace   = "x509ce-secauth"
	secauthSecret      = "x509ce-secauth-webconfig"
	secauthTLSSecret   = "x509ce-secauth-leaf"
	secauthBundlePath  = "/tmp/x509ce-e2e-secauth-bundle.json"

	rbacproxyNamespace      = "x509ce-rbacproxy"
	rbacproxyTLSSecret      = "x509ce-rbacproxy-leaf"
	rbacproxyAuthorizedSA   = "e2e-scraper-authorized"
	rbacproxyUnauthorizedSA = "e2e-scraper-unauthorized"
	rbacproxyClusterRole    = "x509ce-e2e-metrics-reader"
)

// seedAuxiliary applies everything needed by the secauth and rbacproxy
// e2e releases. Idempotent — safe to re-run.
func seedAuxiliary(ctx context.Context, cs *kubernetes.Clientset) {
	if err := seedSecauth(ctx, cs); err != nil {
		log.Fatalf("secauth: %v", err)
	}
	if err := seedRbacproxy(ctx, cs); err != nil {
		log.Fatalf("rbacproxy: %v", err)
	}
}

func seedSecauth(ctx context.Context, cs *kubernetes.Clientset) error {
	if err := ensureNamespace(ctx, cs, secauthNamespace, nil); err != nil {
		return err
	}

	// SAN list covers the host-side port-forward target plus the chart's
	// in-cluster Service FQDN — anyone scraping over either route should
	// get a valid TLS handshake.
	bundle, err := secauth.Generate([]string{
		"127.0.0.1",
		"localhost",
		fmt.Sprintf("x509-certificate-exporter.%s.svc", secauthNamespace),
		fmt.Sprintf("x509-certificate-exporter.%s.svc.cluster.local", secauthNamespace),
	})
	if err != nil {
		return fmt.Errorf("generate bundle: %w", err)
	}

	if err := upsertOpaqueSecret(ctx, cs, secauthNamespace, secauthSecret, bundle.SecretData()); err != nil {
		return fmt.Errorf("upsert webconfig secret: %w", err)
	}

	if err := bundle.WriteTestBundle(secauthBundlePath); err != nil {
		return fmt.Errorf("write test bundle: %w", err)
	}

	// One TLS Secret so the exporter has at least one cert to surface
	// when the test successfully scrapes through the auth gate. The
	// content is irrelevant — we only assert that we got *some* series.
	if err := upsertSelfsignedTLSSecret(ctx, cs, secauthNamespace, secauthTLSSecret); err != nil {
		return fmt.Errorf("upsert tls secret: %w", err)
	}

	fmt.Printf("[seed] secauth — Secret %s/%s + Secret %s/%s + bundle %s\n",
		secauthNamespace, secauthSecret, secauthNamespace, secauthTLSSecret, secauthBundlePath)
	return nil
}

func seedRbacproxy(ctx context.Context, cs *kubernetes.Clientset) error {
	if err := ensureNamespace(ctx, cs, rbacproxyNamespace, nil); err != nil {
		return err
	}

	for _, name := range []string{rbacproxyAuthorizedSA, rbacproxyUnauthorizedSA} {
		if err := upsertServiceAccount(ctx, cs, rbacproxyNamespace, name); err != nil {
			return fmt.Errorf("upsert sa %s: %w", name, err)
		}
	}

	if err := upsertMetricsReaderClusterRole(ctx, cs); err != nil {
		return fmt.Errorf("upsert clusterrole: %w", err)
	}
	if err := upsertMetricsReaderBinding(ctx, cs); err != nil {
		return fmt.Errorf("upsert clusterrolebinding: %w", err)
	}

	if err := upsertSelfsignedTLSSecret(ctx, cs, rbacproxyNamespace, rbacproxyTLSSecret); err != nil {
		return fmt.Errorf("upsert tls secret: %w", err)
	}

	fmt.Printf("[seed] rbacproxy — SAs (authorized + unauthorized) + ClusterRole/Binding + Secret %s/%s\n",
		rbacproxyNamespace, rbacproxyTLSSecret)
	return nil
}

// upsertOpaqueSecret creates or updates a generic Secret (type Opaque).
// Used for the webconfig bundle — distinct from upsertSecret in main.go
// which goes through scenarios.Scenario.
func upsertOpaqueSecret(ctx context.Context, cs *kubernetes.Clientset, ns, name string, data map[string][]byte) error {
	want := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
			Labels:    map[string]string{managedByLabel: managedByValue},
		},
		Type: corev1.SecretTypeOpaque,
		Data: data,
	}
	_, err := cs.CoreV1().Secrets(ns).Update(ctx, want, metav1.UpdateOptions{})
	if apierrors.IsNotFound(err) {
		_, err = cs.CoreV1().Secrets(ns).Create(ctx, want, metav1.CreateOptions{})
	}
	return err
}

// upsertSelfsignedTLSSecret writes one kubernetes.io/tls Secret with a
// freshly generated self-signed leaf cert. The exporter will see this
// as "one cert to scrape" — content doesn't matter for auth-gating tests.
func upsertSelfsignedTLSSecret(ctx context.Context, cs *kubernetes.Clientset, ns, name string) error {
	cert, key, err := scenarios.Selfsigned(scenarios.CertSpec{
		CN:        name,
		O:         []string{"x509ce-e2e"},
		NotBefore: time.Now().Add(-5 * time.Minute),
		NotAfter:  time.Now().Add(1 * time.Hour),
		Algo:      scenarios.AlgoRSA2048,
	})
	if err != nil {
		return err
	}
	want := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
			Labels:    map[string]string{managedByLabel: managedByValue},
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			"tls.crt": scenarios.EncodeCertsPEM(cert),
			"tls.key": scenarios.EncodeKeyPEM(key),
		},
	}
	_, err = cs.CoreV1().Secrets(ns).Update(ctx, want, metav1.UpdateOptions{})
	if apierrors.IsNotFound(err) {
		_, err = cs.CoreV1().Secrets(ns).Create(ctx, want, metav1.CreateOptions{})
	}
	return err
}

func upsertServiceAccount(ctx context.Context, cs *kubernetes.Clientset, ns, name string) error {
	want := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
			Labels:    map[string]string{managedByLabel: managedByValue},
		},
	}
	_, err := cs.CoreV1().ServiceAccounts(ns).Update(ctx, want, metav1.UpdateOptions{})
	if apierrors.IsNotFound(err) {
		_, err = cs.CoreV1().ServiceAccounts(ns).Create(ctx, want, metav1.CreateOptions{})
	}
	return err
}

// upsertMetricsReaderClusterRole creates the cluster-scoped ClusterRole
// kube-rbac-proxy will SubjectAccessReview against. The single rule
// matches `GET /metrics` exactly (kube-rbac-proxy resolves the URL path
// to a `nonResourceURLs` lookup).
func upsertMetricsReaderClusterRole(ctx context.Context, cs *kubernetes.Clientset) error {
	want := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name:   rbacproxyClusterRole,
			Labels: map[string]string{managedByLabel: managedByValue},
		},
		Rules: []rbacv1.PolicyRule{
			{NonResourceURLs: []string{"/metrics"}, Verbs: []string{"get"}},
		},
	}
	_, err := cs.RbacV1().ClusterRoles().Update(ctx, want, metav1.UpdateOptions{})
	if apierrors.IsNotFound(err) {
		_, err = cs.RbacV1().ClusterRoles().Create(ctx, want, metav1.CreateOptions{})
	}
	return err
}

func upsertMetricsReaderBinding(ctx context.Context, cs *kubernetes.Clientset) error {
	want := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:   rbacproxyClusterRole,
			Labels: map[string]string{managedByLabel: managedByValue},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "ClusterRole",
			Name:     rbacproxyClusterRole,
		},
		Subjects: []rbacv1.Subject{{
			Kind:      "ServiceAccount",
			Name:      rbacproxyAuthorizedSA,
			Namespace: rbacproxyNamespace,
		}},
	}
	_, err := cs.RbacV1().ClusterRoleBindings().Update(ctx, want, metav1.UpdateOptions{})
	if apierrors.IsNotFound(err) {
		_, err = cs.RbacV1().ClusterRoleBindings().Create(ctx, want, metav1.CreateOptions{})
	}
	return err
}
