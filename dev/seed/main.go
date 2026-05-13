// Seed populates the dev cluster with the fixtures defined in
// dev/scenarios. Run via Tilt or directly:
//
//	go run ./dev/seed
//
// Idempotent: Secret/ConfigMap/Namespace are upserted, namespace labels are
// merged. Honours $KUBECONFIG / the in-cluster config; defaults to the
// current kubectl context.
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextclient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	aggregatorclient "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset"

	"github.com/enix/x509-certificate-exporter/v4/dev/scenarios"
)

const managedByLabel = "app.kubernetes.io/managed-by"
const managedByValue = "x509ce-dev-seed"

func main() {
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		clientcmd.NewDefaultClientConfigLoadingRules(),
		&clientcmd.ConfigOverrides{},
	).ClientConfig()
	if err != nil {
		log.Fatalf("kubeconfig: %v", err)
	}
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		log.Fatalf("client: %v", err)
	}

	ctx := context.Background()
	all := scenarios.All()

	// Group namespace labels across scenarios so we apply them all on the
	// initial namespace upsert.
	nsLabels := map[string]map[string]string{}
	for _, s := range all {
		for k, v := range s.NamespaceLabels {
			if nsLabels[s.Namespace] == nil {
				nsLabels[s.Namespace] = map[string]string{}
			}
			nsLabels[s.Namespace][k] = v
		}
	}
	seenNS := map[string]bool{}
	for _, s := range all {
		if !seenNS[s.Namespace] {
			if err := ensureNamespace(ctx, cs, s.Namespace, nsLabels[s.Namespace]); err != nil {
				log.Fatalf("namespace %s: %v", s.Namespace, err)
			}
			seenNS[s.Namespace] = true
		}
		switch s.Kind {
		case "Secret":
			if err := upsertSecret(ctx, cs, s); err != nil {
				log.Fatalf("secret %s/%s: %v", s.Namespace, s.Name, err)
			}
		case "ConfigMap":
			if err := upsertConfigMap(ctx, cs, s); err != nil {
				log.Fatalf("configmap %s/%s: %v", s.Namespace, s.Name, err)
			}
		default:
			log.Fatalf("unknown kind %q in scenario %s/%s", s.Kind, s.Namespace, s.Name)
		}
		fmt.Printf("[seed] %s %s/%s — keys=%v watched=%v\n", s.Kind, s.Namespace, s.Name, keys(s.Data), s.Watched)
	}
	seedAuxiliary(ctx, cs)
	seedCABundles(ctx, cs, cfg)
	fmt.Printf("[seed] %d scenarios applied across %d namespace(s)\n", len(all), len(seenNS))
}

func ensureNamespace(ctx context.Context, cs *kubernetes.Clientset, name string, extraLabels map[string]string) error {
	labels := map[string]string{managedByLabel: managedByValue}
	for k, v := range extraLabels {
		labels[k] = v
	}
	want := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels},
	}
	got, err := cs.CoreV1().Namespaces().Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err = cs.CoreV1().Namespaces().Create(ctx, want, metav1.CreateOptions{})
		return err
	}
	if err != nil {
		return err
	}
	if got.Labels == nil {
		got.Labels = map[string]string{}
	}
	changed := false
	for k, v := range labels {
		if got.Labels[k] != v {
			got.Labels[k] = v
			changed = true
		}
	}
	if !changed {
		return nil
	}
	_, err = cs.CoreV1().Namespaces().Update(ctx, got, metav1.UpdateOptions{})
	return err
}

func upsertSecret(ctx context.Context, cs *kubernetes.Clientset, s scenarios.Scenario) error {
	labels := map[string]string{managedByLabel: managedByValue}
	for k, v := range s.Labels {
		labels[k] = v
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      s.Name,
			Namespace: s.Namespace,
			Labels:    labels,
		},
		Type: corev1.SecretType(s.SecretType),
		Data: s.Data,
	}
	_, err := cs.CoreV1().Secrets(s.Namespace).Update(ctx, secret, metav1.UpdateOptions{})
	if apierrors.IsNotFound(err) {
		_, err = cs.CoreV1().Secrets(s.Namespace).Create(ctx, secret, metav1.CreateOptions{})
	}
	return err
}

func upsertConfigMap(ctx context.Context, cs *kubernetes.Clientset, s scenarios.Scenario) error {
	labels := map[string]string{managedByLabel: managedByValue}
	for k, v := range s.Labels {
		labels[k] = v
	}
	bin := map[string][]byte{}
	str := map[string]string{}
	for k, v := range s.Data {
		// PEM is text — keep it readable in `kubectl get cm -o yaml`. Other
		// payloads go into BinaryData. (We don't currently put PKCS#12 in
		// ConfigMaps but be tolerant.)
		if isProbablyText(v) {
			str[k] = string(v)
		} else {
			bin[k] = v
		}
	}
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      s.Name,
			Namespace: s.Namespace,
			Labels:    labels,
		},
		Data:       str,
		BinaryData: bin,
	}
	_, err := cs.CoreV1().ConfigMaps(s.Namespace).Update(ctx, cm, metav1.UpdateOptions{})
	if apierrors.IsNotFound(err) {
		_, err = cs.CoreV1().ConfigMaps(s.Namespace).Create(ctx, cm, metav1.CreateOptions{})
	}
	return err
}

func isProbablyText(b []byte) bool {
	for _, c := range b {
		if c == 0 {
			return false
		}
	}
	return true
}

func keys(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// seedCABundles applies the cluster-scoped cabundle scenarios. The
// resources are MutatingWebhookConfiguration / ValidatingWebhookConfiguration
// (admissionregistration.k8s.io) plus APIService (apiregistration.k8s.io)
// and CustomResourceDefinition with a conversion webhook
// (apiextensions.k8s.io). All four carry inline caBundle PEM fields
// generated from a self-signed cert per scenario. URLs are deliberately
// bogus — the webhooks never actually fire in the e2e cluster, the
// chart's cabundle source only reads `caBundle` and the resource's
// metadata.
func seedCABundles(ctx context.Context, cs *kubernetes.Clientset, cfg *rest.Config) {
	aggregator, err := aggregatorclient.NewForConfig(cfg)
	if err != nil {
		log.Fatalf("aggregator client: %v", err)
	}
	apiext, err := apiextclient.NewForConfig(cfg)
	if err != nil {
		log.Fatalf("apiextensions client: %v", err)
	}
	for _, sc := range scenarios.AllCABundles() {
		labels := map[string]string{managedByLabel: managedByValue}
		for k, v := range sc.Labels {
			labels[k] = v
		}
		switch sc.Kind {
		case scenarios.CABundleKindMutating:
			webhooks := make([]admissionv1.MutatingWebhook, 0, len(sc.Webhooks))
			for _, w := range sc.Webhooks {
				webhooks = append(webhooks, admissionv1.MutatingWebhook{
					Name:                    w.Name,
					ClientConfig:            admissionv1.WebhookClientConfig{URL: ptrString("https://x509ce-e2e.invalid/hook"), CABundle: makeCABundlePEM(w.CN)},
					SideEffects:             ptrSideEffectClass(admissionv1.SideEffectClassNone),
					AdmissionReviewVersions: []string{"v1"},
					Rules:                   []admissionv1.RuleWithOperations{{Operations: []admissionv1.OperationType{admissionv1.Create}, Rule: admissionv1.Rule{APIGroups: []string{"x509ce-e2e.example.com"}, APIVersions: []string{"v1"}, Resources: []string{"ignored"}}}},
				})
			}
			obj := &admissionv1.MutatingWebhookConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: sc.Name, Labels: labels},
				Webhooks:   webhooks,
			}
			if _, err := cs.AdmissionregistrationV1().MutatingWebhookConfigurations().Update(ctx, obj, metav1.UpdateOptions{}); err != nil {
				if !apierrors.IsNotFound(err) {
					log.Fatalf("mwc %s: %v", sc.Name, err)
				}
				if _, err := cs.AdmissionregistrationV1().MutatingWebhookConfigurations().Create(ctx, obj, metav1.CreateOptions{}); err != nil {
					log.Fatalf("mwc %s: %v", sc.Name, err)
				}
			}
		case scenarios.CABundleKindValidating:
			webhooks := make([]admissionv1.ValidatingWebhook, 0, len(sc.Webhooks))
			for _, w := range sc.Webhooks {
				webhooks = append(webhooks, admissionv1.ValidatingWebhook{
					Name:                    w.Name,
					ClientConfig:            admissionv1.WebhookClientConfig{URL: ptrString("https://x509ce-e2e.invalid/hook"), CABundle: makeCABundlePEM(w.CN)},
					SideEffects:             ptrSideEffectClass(admissionv1.SideEffectClassNone),
					AdmissionReviewVersions: []string{"v1"},
					Rules:                   []admissionv1.RuleWithOperations{{Operations: []admissionv1.OperationType{admissionv1.Create}, Rule: admissionv1.Rule{APIGroups: []string{"x509ce-e2e.example.com"}, APIVersions: []string{"v1"}, Resources: []string{"ignored"}}}},
				})
			}
			obj := &admissionv1.ValidatingWebhookConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: sc.Name, Labels: labels},
				Webhooks:   webhooks,
			}
			if _, err := cs.AdmissionregistrationV1().ValidatingWebhookConfigurations().Update(ctx, obj, metav1.UpdateOptions{}); err != nil {
				if !apierrors.IsNotFound(err) {
					log.Fatalf("vwc %s: %v", sc.Name, err)
				}
				if _, err := cs.AdmissionregistrationV1().ValidatingWebhookConfigurations().Create(ctx, obj, metav1.CreateOptions{}); err != nil {
					log.Fatalf("vwc %s: %v", sc.Name, err)
				}
			}
		case scenarios.CABundleKindAPIService:
			// APIServices have a single caBundle. The scenario shape
			// has one webhook entry with an empty name — we use its
			// CN as the cert subject. The Service block has to point
			// at *some* Service; we use a non-existent one in
			// kube-system, the apiserver will mark the APIService
			// "stale" but the resource itself is happily stored —
			// which is all the cabundle source needs to see.
			w := sc.Webhooks[0]
			obj := &apiregistrationv1.APIService{
				ObjectMeta: metav1.ObjectMeta{Name: sc.Name, Labels: labels},
				Spec: apiregistrationv1.APIServiceSpec{
					CABundle:             makeCABundlePEM(w.CN),
					Group:                "x509ce-e2e.example.com",
					Version:              "v1",
					GroupPriorityMinimum: 1000,
					VersionPriority:      15,
					Service:              &apiregistrationv1.ServiceReference{Namespace: "kube-system", Name: "x509ce-e2e-dummy", Port: ptrInt32(443)},
				},
			}
			if _, err := aggregator.ApiregistrationV1().APIServices().Update(ctx, obj, metav1.UpdateOptions{}); err != nil {
				if !apierrors.IsNotFound(err) {
					log.Fatalf("apiservice %s: %v", sc.Name, err)
				}
				if _, err := aggregator.ApiregistrationV1().APIServices().Create(ctx, obj, metav1.CreateOptions{}); err != nil {
					log.Fatalf("apiservice %s: %v", sc.Name, err)
				}
			}
		case scenarios.CABundleKindCRD:
			// CRD with a conversion webhook. The webhook URL points
			// nowhere reachable — the kube-apiserver only invokes it
			// when an object of this CRD is read/written across
			// versions, which never happens in the e2e (no instances
			// of x509cetenants are created).
			w := sc.Webhooks[0]
			obj := &apiextensionsv1.CustomResourceDefinition{
				ObjectMeta: metav1.ObjectMeta{Name: sc.Name, Labels: labels},
				Spec: apiextensionsv1.CustomResourceDefinitionSpec{
					Group: "x509ce-e2e.example.com",
					Names: apiextensionsv1.CustomResourceDefinitionNames{
						Plural:   "x509cetenants",
						Singular: "x509cetenant",
						Kind:     "X509ceTenant",
						ListKind: "X509ceTenantList",
					},
					Scope: apiextensionsv1.NamespaceScoped,
					Versions: []apiextensionsv1.CustomResourceDefinitionVersion{
						{
							Name:    "v1",
							Served:  true,
							Storage: true,
							Schema: &apiextensionsv1.CustomResourceValidation{
								OpenAPIV3Schema: &apiextensionsv1.JSONSchemaProps{Type: "object"},
							},
						},
					},
					Conversion: &apiextensionsv1.CustomResourceConversion{
						Strategy: apiextensionsv1.WebhookConverter,
						Webhook: &apiextensionsv1.WebhookConversion{
							ConversionReviewVersions: []string{"v1"},
							ClientConfig:             &apiextensionsv1.WebhookClientConfig{URL: ptrString("https://x509ce-e2e.invalid/hook"), CABundle: makeCABundlePEM(w.CN)},
						},
					},
				},
			}
			if _, err := apiext.ApiextensionsV1().CustomResourceDefinitions().Update(ctx, obj, metav1.UpdateOptions{}); err != nil {
				if !apierrors.IsNotFound(err) {
					log.Fatalf("crd %s: %v", sc.Name, err)
				}
				if _, err := apiext.ApiextensionsV1().CustomResourceDefinitions().Create(ctx, obj, metav1.CreateOptions{}); err != nil {
					log.Fatalf("crd %s: %v", sc.Name, err)
				}
			}
		}
		fmt.Printf("[seed] %s %s — entries=%d watched=%v\n", sc.Kind, sc.Name, len(sc.Webhooks), sc.Watched)
	}
}

func ptrInt32(v int32) *int32 { return &v }

// makeCABundlePEM generates a self-signed PEM-encoded certificate
// with the given CN, predictable lifetime so the e2e never sees an
// expired cert. Uses the same self-signing helper as the namespace-
// scoped scenarios so the resulting series are visually consistent.
func makeCABundlePEM(cn string) []byte {
	c, _, err := scenarios.Selfsigned(scenarios.CertSpec{
		CN:        cn,
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  scenarios.CABundleNotAfter,
		Algo:      scenarios.AlgoECDSAP256,
	})
	if err != nil {
		log.Fatalf("selfsigned %s: %v", cn, err)
	}
	return scenarios.EncodeCertsPEM(c)
}

func ptrSideEffectClass(v admissionv1.SideEffectClass) *admissionv1.SideEffectClass { return &v }

func ptrString(v string) *string { return &v }
