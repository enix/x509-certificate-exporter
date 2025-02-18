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
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
)

func Init() {
	log.SetLevel(log.DebugLevel)
}

func createSecrets(client kubernetes.Interface) error {
	if err := addKubeSecrets(client, 10, "default"); err != nil {
		return err
	}
	if err := addKubeSecrets(client, 10, "kube-system"); err != nil {
		return err
	}
	if err := addCustomKubeSecret(client); err != nil {
		return err
	}
	if err := addBrokenKubeSecret(client); err != nil {
		return err
	}
	if err := addBrokenKubeSecret2(client); err != nil {
		return err
	}

	return nil
}

func TestKubeNamespaceAndSecretsFiltering(t *testing.T) {
	tests := []struct {
		Name             string
		Exporter         Exporter
		MetricCount      int
		AdditionnalCheck func(m []model.MetricFamily)
	}{
		{
			Name:        "All secrets (no filtering)",
			MetricCount: 21,
			AdditionnalCheck: func(m []model.MetricFamily) {
				metrics := getMetricsForName(m, "x509_read_errors")
				assert.Equal(t, 1., metrics[0].GetGauge().GetValue())
			},
		}, {
			Name: "Include existing label without value",
			Exporter: Exporter{
				KubeIncludeLabels: []string{"test"},
			},
			MetricCount: 20,
		}, {
			Name: "Include non-existing label without value",
			Exporter: Exporter{
				KubeIncludeLabels: []string{"xxxx"},
			},
			MetricCount: 0,
		}, {
			Name: "Include existing label with value",
			Exporter: Exporter{
				KubeIncludeLabels: []string{"aze=abc"},
			},
			MetricCount: 20,
		}, {
			Name: "Include non-existing label with value",
			Exporter: Exporter{
				KubeIncludeLabels: []string{"xxx=xxx"},
			},
			MetricCount: 0,
		}, {
			Name: "Include existing label with non-existing value",
			Exporter: Exporter{
				KubeIncludeLabels: []string{"aze=xxx"},
			},
			MetricCount: 0,
		}, {
			Name: "Exclude existing label without value",
			Exporter: Exporter{
				KubeExcludeLabels: []string{"test"},
			},
			MetricCount: 1,
		}, {
			Name: "Exclude non-existing label without value",
			Exporter: Exporter{
				KubeExcludeLabels: []string{"xxxx"},
			},
			MetricCount: 21,
		}, {
			Name: "Exclude existing label with value",
			Exporter: Exporter{
				KubeExcludeLabels: []string{"aze=abc"},
			},
			MetricCount: 1,
		}, {
			Name: "Exclude non-existing label with value",
			Exporter: Exporter{
				KubeExcludeLabels: []string{"xxx=xxx"},
			},
			MetricCount: 21,
		}, {
			Name: "Exclude existing label with non-existing value",
			Exporter: Exporter{
				KubeExcludeLabels: []string{"aze=xxx"},
			},
			MetricCount: 21,
		}, {
			Name: "Include and exclude label mix",
			Exporter: Exporter{
				KubeIncludeLabels: []string{"aze=abc"},
				KubeExcludeLabels: []string{"aze=abc"},
			},
			MetricCount: 0,
		}, {
			Name: "Include and exclude label mix 2",
			Exporter: Exporter{
				KubeIncludeLabels: []string{"test"},
				KubeExcludeLabels: []string{"index=0"},
			},
			MetricCount: 18,
		}, {
			Name: "Include and exclude label mix 3",
			Exporter: Exporter{
				KubeIncludeLabels: []string{"test"},
				KubeExcludeLabels: []string{"xxxxx"},
			},
			MetricCount: 20,
		}, {
			Name: "Include and exclude label mix 4",
			Exporter: Exporter{
				KubeIncludeLabels: []string{"index=0", "test"},
				KubeExcludeLabels: []string{"index=1"},
			},
			MetricCount: 2,
		}, {
			Name: "Custom secret",
			Exporter: Exporter{
				KubeSecretTypes: []KubeSecretType{
					{Type: "istio.io/cert-and-key", Regexp: regexp.MustCompile(`cert-chain\.pem`)},
					{Type: "istio.io/cert-and-key", Regexp: regexp.MustCompile(`root-cert\.pem`)},
				},
			},
			MetricCount: 2,
			AdditionnalCheck: func(m []model.MetricFamily) {
				metric := getMetricsForName(m, "x509_cert_expired")
				assert.Len(t, metric, 2)
				checkLabels(t, metric[0].GetLabel(), "k8s/default/test-custom-type", true, 15)
				checkLabels(t, metric[1].GetLabel(), "k8s/default/test-custom-type", true, 15)
			},
		}, {
			Name: "Metric labels",
			Exporter: Exporter{
				KubeIncludeNamespaces: []string{"default"},
				KubeIncludeLabels:     []string{"index=0"},
			},
			MetricCount: 1,
			AdditionnalCheck: func(m []model.MetricFamily) {
				metric := getMetricsForName(m, "x509_cert_expired")[0]
				checkLabels(t, metric.GetLabel(), "k8s/default/test-default-0.crt", true, 15)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			tt.Exporter.kubeClient = fake.NewClientset()
			if err := createSecrets(tt.Exporter.kubeClient); err != nil {
				t.Fatal(err)
			}

			testRequest(t, &tt.Exporter, func(m []model.MetricFamily) {
				checkMetricsCount(t, m, tt.MetricCount)
			})
		})
	}
}

func TestKubeInvalidSecretType(t *testing.T) {
	_, err := ParseSecretType("aze")
	assert.Error(t, err)
}

func TestKubeEmptyStringKey(t *testing.T) {
	client := fake.NewClientset()
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
		},
	}, func(m []model.MetricFamily) {
		metrics := getMetricsForName(m, "x509_read_errors")
		assert.Equal(t, 0., metrics[0].GetGauge().GetValue())
	})
}

func TestKubeConnectionFromInsideFailure(t *testing.T) {
	e := &Exporter{}
	err := e.ConnectToKubernetesCluster("", nil)
	assert.NotNil(t, err)
}

func TestExporterFilterNamespaces(t *testing.T) {
	tests := []struct {
		Name               string
		Exporter           Exporter
		ExpectedNamespaces []string
	}{
		{
			Name:               "All namespaces (no filtering)",
			ExpectedNamespaces: []string{"default", "kube-system", "x509-exporter"},
		}, {
			Name: "Include namespace",
			Exporter: Exporter{
				KubeIncludeNamespaces: []string{"default"},
			},
			ExpectedNamespaces: []string{"default"},
		}, {
			Name: "Include multiple namespaces",
			Exporter: Exporter{
				KubeIncludeNamespaces: []string{"default", "kube-system"},
			},
			ExpectedNamespaces: []string{"default", "kube-system"},
		}, {
			Name: "Exclude namespace",
			Exporter: Exporter{
				KubeExcludeNamespaces: []string{"default"},
			},
			ExpectedNamespaces: []string{"kube-system", "x509-exporter"},
		}, {
			Name: "Exclude multiple namespaces",
			Exporter: Exporter{
				KubeExcludeNamespaces: []string{"default", "kube-system"},
			},
			ExpectedNamespaces: []string{"x509-exporter"},
		}, {
			Name: "Include and exclude namespace mix",
			Exporter: Exporter{
				KubeIncludeNamespaces: []string{"default"},
				KubeExcludeNamespaces: []string{"default"},
			},
			ExpectedNamespaces: []string{},
		}, {
			Name: "Include and exclude namespace mix 2",
			Exporter: Exporter{
				KubeIncludeNamespaces: []string{"default", "kube-system"},
				KubeExcludeNamespaces: []string{"kube-system"},
			},
			ExpectedNamespaces: []string{"default"},
		}, {
			Name: "Exlucde labels",
			Exporter: Exporter{
				KubeExcludeNamespaceLabels: []string{"foo"},
			},
			ExpectedNamespaces: []string{"kube-system", "x509-exporter"},
		},
		{
			Name: "Exclude labels with value",
			Exporter: Exporter{
				KubeExcludeNamespaceLabels: []string{"group=foo"},
			},
			ExpectedNamespaces: []string{"x509-exporter"},
		},
		{
			Name: "Include namespaces and exclude labels with value",
			Exporter: Exporter{
				KubeIncludeNamespaces:      []string{"default", "kube-system"},
				KubeExcludeNamespaceLabels: []string{"foo=bar"},
			},
			ExpectedNamespaces: []string{"kube-system"},
		},
	}

	namespaces := []v1.Namespace{
		{ObjectMeta: metav1.ObjectMeta{
			Name: "default",
			Labels: map[string]string{
				"foo":   "bar",
				"group": "foo",
			},
		}},
		{ObjectMeta: metav1.ObjectMeta{
			Name: "kube-system",
			Labels: map[string]string{
				"group": "foo",
			},
		}},
		{ObjectMeta: metav1.ObjectMeta{
			Name: "x509-exporter",
			Labels: map[string]string{
				"group": "bar",
			},
		}},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			filteredNamespaces := tt.Exporter.filterNamespaces(namespaces)
			assert.Equal(t, tt.ExpectedNamespaces, filteredNamespaces)
		})
	}
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
		labels := map[string]string{
			"test":  "",
			"aze":   "abc",
			"index": fmt.Sprintf("%d", index),
		}
		if err := addKubeSecret(client, name, ns, labels); err != nil {
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

func addCustomKubeSecret(client kubernetes.Interface) error {
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
			Name: "test-custom-type",
		},
	}, metav1.CreateOptions{})

	if err != nil {
		return err
	}

	return nil
}

func addBrokenKubeSecret(client kubernetes.Interface) error {
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

	if err != nil {
		return err
	}

	return nil
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

	if err != nil {
		return err
	}

	return err
}
