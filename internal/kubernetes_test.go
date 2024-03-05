package internal

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	model "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	fakecore "k8s.io/client-go/kubernetes/typed/core/v1/fake"
	testingk8s "k8s.io/client-go/testing"
)

func TestKubeAllSecrets(t *testing.T) {
	client := fake.NewSimpleClientset()
	n := 10
	if err := addKubeSecrets(client, n, "default"); err != nil {
		t.Fatal(err)
	}
	if err := addBrokenKubeSecret(client, "default"); err != nil {
		t.Fatal(err)
	}

	testRequest(t, &Exporter{kubeClient: client}, func(m []model.MetricFamily) {
		checkMetricsCount(t, m, n)
		metrics := getMetricsForName(m, "x509_read_errors")
		assert.Equal(t, 1., metrics[0].GetGauge().GetValue())
	})
}

func TestKubeIncludeNamespace(t *testing.T) {
	client := fake.NewSimpleClientset()
	n := 5
	if err := addKubeSecrets(client, n, "default"); err != nil {
		t.Fatal(err)
	}
	if err := addKubeSecrets(client, n, "some-other-ns"); err != nil {
		t.Fatal(err)
	}

	testRequest(t, &Exporter{
		kubeClient:            client,
		KubeIncludeNamespaces: []string{"default"},
	}, func(m []model.MetricFamily) {
		checkMetricsCount(t, m, n)
	})
}

func TestKubeIncludeMultipleNamespaces(t *testing.T) {
	client := fake.NewSimpleClientset()
	n := 5
	// create 5 secrets in ns0, ns2, ..., ns9
	for j := 0; j < 10; j++ {
		if err := addKubeSecrets(client, n, fmt.Sprintf("ns%d", j)); err != nil {
			t.Fatal(err)
		}
	}

	testRequest(t, &Exporter{
		kubeClient:            client,
		KubeIncludeNamespaces: []string{"ns2", "ns3", "ns5"},
	}, func(m []model.MetricFamily) {
		checkMetricsCount(t, m, 3*n)
	})
}

func TestKubeExcludeNamespace(t *testing.T) {
	client := fake.NewSimpleClientset()
	n := 5
	// create 5 secrets in ns0, ns2, ..., ns9
	for j := 0; j < 10; j++ {
		if err := addKubeSecrets(client, n, fmt.Sprintf("ns%d", j)); err != nil {
			t.Fatal(err)
		}
	}

	testRequest(t, &Exporter{
		kubeClient:            client,
		KubeExcludeNamespaces: []string{"ns5"},
	}, func(m []model.MetricFamily) {
		checkMetricsCount(t, m, 10*n-n)
	})
}

func TestKubeExcludeMultipleNamespaces(t *testing.T) {
	client := fake.NewSimpleClientset()
	n := 5
	// create 5 secrets in ns0, ns2, ..., ns9
	for j := 0; j < 10; j++ {
		if err := addKubeSecrets(client, n, fmt.Sprintf("ns%d", j)); err != nil {
			t.Fatal(err)
		}
	}

	testRequest(t, &Exporter{
		kubeClient:            client,
		KubeExcludeNamespaces: []string{"ns2", "ns8"},
	}, func(m []model.MetricFamily) {
		checkMetricsCount(t, m, 10*n-2*n)
	})
}

func TestKubeIncludeExcludeNamespaceMix(t *testing.T) {
	client := fake.NewSimpleClientset()
	if err := addKubeSecrets(client, 5, "default"); err != nil {
		t.Fatal(err)
	}
	testRequest(t, &Exporter{
		kubeClient:            client,
		KubeIncludeNamespaces: []string{"default"},
		KubeExcludeNamespaces: []string{"default"},
	}, func(m []model.MetricFamily) {
		checkMetricsCount(t, m, 0)
	})
}

func TestKubeIncludeExcludeNamespaceMix2(t *testing.T) {
	client := fake.NewSimpleClientset()
	n := 5
	for _, ns := range []string{"default", "kube-system"} {
		if err := addKubeSecrets(client, n, ns); err != nil {
			t.Fatal(err)
		}
	}

	testRequest(t, &Exporter{
		kubeClient:            client,
		KubeIncludeNamespaces: []string{"default", "kube-system"},
		KubeExcludeNamespaces: []string{"kube-system"},
	}, func(m []model.MetricFamily) {
		checkMetricsCount(t, m, n)
	})
}

func TestKubeIncludeExistingLabelWithoutValue(t *testing.T) {
	client := fake.NewSimpleClientset()
	ns := "default"
	if err := addKubeSecret(client, "test1", ns, map[string]string{"test1": "test"}); err != nil {
		t.Fatal(err)
	}
	if err := addKubeSecret(client, "test2", ns, map[string]string{"test2": "test"}); err != nil {
		t.Fatal(err)
	}

	testRequest(t, &Exporter{
		kubeClient:        client,
		KubeIncludeLabels: []string{"test2"},
	}, func(m []model.MetricFamily) {
		checkMetricsCount(t, m, 1)
	})
}

func TestKubeIncludeNonExistingLabelWithoutValue(t *testing.T) {
	client := fake.NewSimpleClientset()
	ns := "default"
	if err := addKubeSecret(client, "test1", ns, map[string]string{"test1": "test"}); err != nil {
		t.Fatal(err)
	}

	testRequest(t, &Exporter{
		kubeClient:        client,
		KubeIncludeLabels: []string{"xxxx"},
	}, func(m []model.MetricFamily) {
		checkMetricsCount(t, m, 0)
	})
}

func TestKubeIncludeExistingLabelWithValue(t *testing.T) {
	client := fake.NewSimpleClientset()
	ns := "default"
	if err := addKubeSecret(client, "test1", ns, map[string]string{"aze": "abc"}); err != nil {
		t.Fatal(err)
	}
	if err := addKubeSecret(client, "test2", ns, map[string]string{"foo": "abc"}); err != nil {
		t.Fatal(err)
	}

	testRequest(t, &Exporter{
		kubeClient:        client,
		KubeIncludeLabels: []string{"aze=abc"},
	}, func(m []model.MetricFamily) {
		checkMetricsCount(t, m, 1)
	})
}

func TestKubeIncludeNonExistingLabelWithValue(t *testing.T) {
	client := fake.NewSimpleClientset()
	ns := "default"
	if err := addKubeSecret(client, "test1", ns, map[string]string{"aze": "abc"}); err != nil {
		t.Fatal(err)
	}

	testRequest(t, &Exporter{
		kubeClient:        client,
		KubeIncludeLabels: []string{"xxx=xxx"},
	}, func(m []model.MetricFamily) {
		checkMetricsCount(t, m, 0)
	})
}

func TestKubeIncludeExistingLabelWithNonExistingValue(t *testing.T) {
	client := fake.NewSimpleClientset()
	ns := "default"
	if err := addKubeSecret(client, "test1", ns, map[string]string{"aze": "abc"}); err != nil {
		t.Fatal(err)
	}

	testRequest(t, &Exporter{
		kubeClient:        client,
		KubeIncludeLabels: []string{"aze=xxx"},
	}, func(m []model.MetricFamily) {
		checkMetricsCount(t, m, 0)
	})
}

// TODO: make all the label tests as subtests of a single one with setup?
func TestKubeExcludeExistingLabelWithoutValue(t *testing.T) {
	client := fake.NewSimpleClientset()
	ns := "default"
	for j := 0; j < 10; j++ {
		sid := fmt.Sprintf("test%d", j)
		if err := addKubeSecret(client, sid, ns, map[string]string{sid: "abc"}); err != nil {
			t.Fatal(err)
		}
	}

	testRequest(t, &Exporter{
		kubeClient:        client,
		KubeExcludeLabels: []string{"test1"},
	}, func(m []model.MetricFamily) {
		checkMetricsCount(t, m, 10-1)
	})
}

func TestKubeExcludeNonExistingLabelWithoutValue(t *testing.T) {
	client := fake.NewSimpleClientset()
	ns := "default"
	n := 10
	if err := addKubeSecrets(client, n, ns); err != nil {
		t.Fatal(err)
	}

	testRequest(t, &Exporter{
		kubeClient:        client,
		KubeExcludeLabels: []string{"xxxx"},
	}, func(m []model.MetricFamily) {
		checkMetricsCount(t, m, n)
	})
}

func TestKubeExcludeExistingLabelWithValue(t *testing.T) {
	client := fake.NewSimpleClientset()
	ns := "default"
	if err := addKubeSecret(client, "test1", ns, map[string]string{"aze": "abc"}); err != nil {
		t.Fatal(err)
	}
	if err := addKubeSecret(client, "test2", ns, map[string]string{"foo": "abc"}); err != nil {
		t.Fatal(err)
	}

	testRequest(t, &Exporter{
		kubeClient:        client,
		KubeExcludeLabels: []string{"aze=abc"},
	}, func(m []model.MetricFamily) {
		checkMetricsCount(t, m, 1)
	})
}

func TestKubeExcludeNonExistingLabelWithValue(t *testing.T) {
	client := fake.NewSimpleClientset()
	ns := "default"
	if err := addKubeSecret(client, "test1", ns, map[string]string{"aze": "abc"}); err != nil {
		t.Fatal(err)
	}
	if err := addKubeSecret(client, "test2", ns, map[string]string{"foo": "abc"}); err != nil {
		t.Fatal(err)
	}

	testRequest(t, &Exporter{
		kubeClient:        client,
		KubeExcludeLabels: []string{"xxx=xxx"},
	}, func(m []model.MetricFamily) {
		checkMetricsCount(t, m, 2)
	})
}

func TestKubeExcludeExistingLabelWithNonExistingValue(t *testing.T) {
	client := fake.NewSimpleClientset()
	ns := "default"
	if err := addKubeSecret(client, "test1", ns, map[string]string{"aze": "abc"}); err != nil {
		t.Fatal(err)
	}
	if err := addKubeSecret(client, "test2", ns, map[string]string{"foo": "abc"}); err != nil {
		t.Fatal(err)
	}

	testRequest(t, &Exporter{
		kubeClient:        client,
		KubeExcludeLabels: []string{"aze=xxx"},
	}, func(m []model.MetricFamily) {
		checkMetricsCount(t, m, 2)
	})
}

func TestKubeIncludeExcludeLabelMix(t *testing.T) {
	client := fake.NewSimpleClientset()
	ns := "default"
	n := 5
	if err := addKubeSecrets(client, n, ns); err != nil {
		t.Fatal(err)
	}

	testRequest(t, &Exporter{
		kubeClient:        client,
		KubeIncludeLabels: []string{"aze=abc"},
		KubeExcludeLabels: []string{"aze=abc"},
	}, func(m []model.MetricFamily) {
		checkMetricsCount(t, m, 0)
	})
}

func TestKubeIncludeExcludeLabelMix2(t *testing.T) {
	client := fake.NewSimpleClientset()
	ns := "default"
	for j := 0; j < 10; j++ {
		sid := fmt.Sprintf("test%d", j)
		if err := addKubeSecret(client, sid, ns, map[string]string{sid: "foo"}); err != nil {
			t.Fatal(err)
		}
	}

	testRequest(t, &Exporter{
		kubeClient:        client,
		KubeIncludeLabels: []string{"test1"},
		KubeExcludeLabels: []string{"test7=foo"},
	}, func(m []model.MetricFamily) {
		checkMetricsCount(t, m, 1)
	})
}

func TestKubeIncludeExcludeLabelMix3(t *testing.T) {
	client := fake.NewSimpleClientset()
	ns := "default"
	n := 10
	for j := 0; j < n; j++ {
		sid := fmt.Sprintf("test%d", j)
		if err := addKubeSecret(client, sid, ns, map[string]string{sid: "foo"}); err != nil {
			t.Fatal(err)
		}
	}

	testRequest(t, &Exporter{
		kubeClient:        client,
		KubeIncludeLabels: []string{"test1"},
		KubeExcludeLabels: []string{"xxxxx"},
	}, func(m []model.MetricFamily) {
		checkMetricsCount(t, m, 1)
	})
}

func TestKubeIncludeExcludeLabelMix4(t *testing.T) {
	client := fake.NewSimpleClientset()
	ns := "default"
	n := 10
	for j := 0; j < n; j++ {
		sid := fmt.Sprintf("test%d", j)
		if err := addKubeSecret(client, sid, ns, map[string]string{sid: "foo", "also": "this"}); err != nil {
			t.Fatal(err)
		}
	}

	testRequest(t, &Exporter{
		kubeClient:        client,
		KubeIncludeLabels: []string{"test1=foo", "also=this"},
		KubeExcludeLabels: []string{"test3=foo"},
	}, func(m []model.MetricFamily) {
		checkMetricsCount(t, m, 1)
	})
}

func TestKubeCustomSecretType(t *testing.T) {
	client := fake.NewSimpleClientset()
	if err := addSecretCustomType(client); err != nil {
		t.Fatal(err)
	}

	testRequest(t, &Exporter{
		kubeClient: client,
		KubeSecretTypes: []KubeSecretType{
			{Type: "istio.io/cert-and-key", Regexp: regexp.MustCompile(`cert-chain\.pem`)},
			{Type: "istio.io/cert-and-key", Regexp: regexp.MustCompile(`root-cert\.pem`)},
		},
	}, func(m []model.MetricFamily) {
		metric := getMetricsForName(m, "x509_cert_expired")
		assert.Len(t, metric, 2)
		checkLabels(t, metric[0].GetLabel(), "k8s/default/test-custom-type", true, 15)
		checkLabels(t, metric[1].GetLabel(), "k8s/default/test-custom-type", true, 15)
	})
}

func TestKubeMetricLabels(t *testing.T) {
	client := fake.NewSimpleClientset()
	ns := "default"
	n := 10
	for j := 0; j < n; j++ {
		sid := fmt.Sprintf("test%d", j)
		if err := addKubeSecret(client, sid, ns, map[string]string{sid: "foo"}); err != nil {
			t.Fatal(err)
		}
	}

	testRequest(t, &Exporter{
		kubeClient:            client,
		KubeIncludeNamespaces: []string{"default"},
		KubeIncludeLabels:     []string{"test1=foo"},
	}, func(m []model.MetricFamily) {
		metric := getMetricsForName(m, "x509_cert_expired")[0]
		checkLabels(t, metric.GetLabel(), "k8s/default/test-default-test1.crt", true, 15)
	})
}

func TestKubeListFailure(t *testing.T) {
	for _, object := range []string{"namespaces", "secrets"} {
		t.Run(object, func(t *testing.T) {
			client := fake.NewSimpleClientset()
			if err := addKubeSecrets(client, 5, "default"); err != nil {
				t.Fatal(err)
			}
			client.CoreV1().(*fakecore.FakeCoreV1).PrependReactor("list", object, func(action testingk8s.Action) (handled bool, ret runtime.Object, err error) {
				return true, nil, fmt.Errorf("list error")
			})

			testRequest(t, &Exporter{
				kubeClient: client,
			}, func(m []model.MetricFamily) {
				checkMetricsCount(t, m, 0)
				metrics := getMetricsForName(m, "x509_read_errors")
				assert.Equal(t, 1., metrics[0].GetGauge().GetValue())
			})
		})
	}
}

func TestKubeInvalidConfig(t *testing.T) {
	_, err := connectToKubernetesCluster("../test/kubeconfig-corrupted.yml", true, nil)
	assert.NotNil(t, err)
}

func TestKubeInvalidSecretType(t *testing.T) {
	_, err := ParseSecretType("aze")
	assert.Error(t, err)
}

func TestKubeEmptyStringKey(t *testing.T) {
	client := fake.NewSimpleClientset()
	if err := addBrokenKubeSecret2(client); err != nil {
		t.Fatal(err)
	}

	testRequest(t, &Exporter{
		kubeClient:        client,
		KubeIncludeLabels: []string{"empty=true"},
		KubeSecretTypes: []KubeSecretType{
			{Type: "kubernetes.io/tls", Regexp: regexp.MustCompile(`tls\.crt`)},
			{Type: "kubernetes.io/tls", Regexp: regexp.MustCompile(`tls\.key`)},
			{Type: "kubernetes.io/tls", Regexp: regexp.MustCompile(`nil\.key`)},
		}}, func(m []model.MetricFamily) {
		metrics := getMetricsForName(m, "x509_read_errors")
		assert.Equal(t, 0., metrics[0].GetGauge().GetValue())
	})
}

func checkMetricsCount(t *testing.T, allMetrics []model.MetricFamily, count int) {
	metrics := getMetricsForName(allMetrics, "x509_cert_expired")
	assert.Len(t, metrics, count, "invalid number of x509_cert_expired metrics")

	nbMetrics := getMetricsForName(allMetrics, "x509_cert_not_before")
	assert.Len(t, nbMetrics, count, "invalid number of x509_cert_not_before metrics")

	naMetrics := getMetricsForName(allMetrics, "x509_cert_not_after")
	assert.Len(t, naMetrics, count, "invalid number of x509_cert_not_after metrics")
}

func createNs(client kubernetes.Interface, name string) error {
	_, err := client.CoreV1().Namespaces().Create(context.Background(), &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
	}, metav1.CreateOptions{})

	if apierrors.IsAlreadyExists(err) {
		return nil
	}

	return err
}

func addKubeSecrets(client kubernetes.Interface, count int, ns string) error {
	for index := 0; index < count; index++ {
		name := fmt.Sprintf("test-%02d", index)
		if err := addKubeSecret(client, name, ns, nil); err != nil {
			return err
		}
	}

	return nil
}

func addKubeSecret(client kubernetes.Interface, name, ns string, labels map[string]string) error {
	if err := createNs(client, ns); err != nil {
		return err
	}
	certPath := fmt.Sprintf("/tmp/test-%s-%s.crt", ns, name)
	generateCertificate(certPath, time.Now())
	cert, err := os.ReadFile(certPath)
	if err != nil {
		return err
	}

	key, err := os.ReadFile(certPath + ".key")
	if err != nil {
		return err
	}

	secretName := filepath.Base(certPath)

	_, err = client.CoreV1().Secrets(ns).Create(context.Background(), &v1.Secret{
		Type: "kubernetes.io/tls",
		Data: map[string][]byte{
			"tls.crt": cert,
			"tls.key": key,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:   secretName,
			Labels: labels,
		},
	}, metav1.CreateOptions{})

	return err
}

func addSecretCustomType(client kubernetes.Interface) error {
	ns := "default"
	if err := createNs(client, ns); err != nil {
		return err
	}
	certPath := "/tmp/test-custom-type.crt"
	generateCertificate(certPath, time.Now())
	cert, err := os.ReadFile(certPath)
	if err != nil {
		return err
	}

	_, err = client.CoreV1().Secrets("default").Create(context.Background(), &v1.Secret{
		Type: "istio.io/cert-and-key",
		Data: map[string][]byte{
			"cert-chain.pem": cert,
			"root-cert.pem":  cert,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-custom-type",
			Namespace: ns,
		},
	}, metav1.CreateOptions{})

	return err
}

func addBrokenKubeSecret(client kubernetes.Interface, ns string) error {
	if err := createNs(client, ns); err != nil {
		return err
	}

	corruptedData, err := os.ReadFile("../test/corrupted.pem")
	if err != nil {
		return err
	}

	_, err = client.CoreV1().Secrets("default").Create(context.Background(), &v1.Secret{
		Type: "kubernetes.io/tls",
		Data: map[string][]byte{
			"tls.crt": corruptedData,
			"tls.key": {},
			"nil.crt": nil,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "corrupted-pem-data",
		},
	}, metav1.CreateOptions{})

	return err
}

func addBrokenKubeSecret2(client kubernetes.Interface) error {
	data, err := os.ReadFile("../test/basic.pem")
	if err != nil {
		return err
	}

	_, err = client.CoreV1().Secrets("default").Create(context.Background(), &v1.Secret{
		Type: "kubernetes.io/tls",
		Data: map[string][]byte{
			"tls.crt": data,
			"tls.key": {},
			"nil.crt": nil,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "empty-pem-data",
			Labels: map[string]string{
				"empty": "true",
			},
		},
	}, metav1.CreateOptions{})

	return err
}
