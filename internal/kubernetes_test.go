package internal

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"testing"
	"time"

	model "github.com/prometheus/client_model/go"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

var sharedKubeClient *kubernetes.Clientset

func TestMain(m *testing.M) {
	var err error
	log.SetLevel(log.DebugLevel)

	output, err := exec.Command("bash", "-c", "kubectl --insecure-skip-tls-verify config view --raw > kubeconfig").CombinedOutput()
	log.Debug(string(output))
	if err != nil {
		panic(err)
	}

	output, err = exec.Command("bash", "-c", "kubectl --insecure-skip-tls-verify apply -f ../test/k8s-no-access-role.yml").CombinedOutput()
	log.Debug(string(output))
	if err != nil {
		panic(err)
	}

	output, err = exec.Command("bash", "-c", "kubectl --insecure-skip-tls-verify apply -f ../test/k8s-list-only-role.yml").CombinedOutput()
	log.Debug(string(output))
	if err != nil {
		panic(err)
	}

	output, err = exec.Command("bash", "-c", "../test/create-k8s-config-for-sa.sh x509-certificate-exporter").CombinedOutput()
	log.Debug(string(output))
	if err != nil {
		panic(err)
	}

	output, err = exec.Command("bash", "-c", "../test/create-k8s-config-for-sa.sh x509-certificate-exporter-list").CombinedOutput()
	log.Debug(string(output))
	if err != nil {
		panic(err)
	}

	sharedKubeClient, err = connectToKubernetesCluster("kubeconfig", true)
	if err != nil {
		panic(err)
	}

	err = addKubeSecrets(10, "default")
	if err != nil {
		cleanupSecrets()
		addKubeSecrets(10, "default")
	}

	addKubeSecrets(10, "kube-system")
	addCustomKubeSecret()
	addBrokenKubeSecret()
	addBrokenKubeSecret2()

	status := m.Run()

	cleanupSecrets()
	os.Remove("kubeconfig")
	os.Remove("kubeconfig.x509-certificate-exporter")
	os.Remove("kubeconfig.x509-certificate-exporter-list")
	os.Exit(status)
}

func TestKubeAllSecrets(t *testing.T) {
	testRequestKube(t, &Exporter{}, func(m []model.MetricFamily) {
		checkMetricsCount(t, m, 20)
		metrics := getMetricsForName(m, "x509_read_errors")
		assert.Equal(t, 1., metrics[0].GetGauge().GetValue())
	})
}

func TestKubeIncludeNamespace(t *testing.T) {
	testRequestKube(t, &Exporter{
		KubeIncludeNamespaces: []string{"default"},
	}, func(m []model.MetricFamily) {
		checkMetricsCount(t, m, 10)
	})
}

func TestKubeIncludeMultipleNamespaces(t *testing.T) {
	testRequestKube(t, &Exporter{
		KubeIncludeNamespaces: []string{"default", "kube-system"},
	}, func(m []model.MetricFamily) {
		checkMetricsCount(t, m, 20)
	})
}

func TestKubeExcludeNamespace(t *testing.T) {
	testRequestKube(t, &Exporter{
		KubeExcludeNamespaces: []string{"default"},
	}, func(m []model.MetricFamily) {
		checkMetricsCount(t, m, 10)
	})
}

func TestKubeExcludeMultipleNamespaces(t *testing.T) {
	testRequestKube(t, &Exporter{
		KubeExcludeNamespaces: []string{"default", "kube-system"},
	}, func(m []model.MetricFamily) {
		checkMetricsCount(t, m, 0)
	})
}

func TestKubeIncludeExcludeNamespaceMix(t *testing.T) {
	testRequestKube(t, &Exporter{
		KubeIncludeNamespaces: []string{"default"},
		KubeExcludeNamespaces: []string{"default"},
	}, func(m []model.MetricFamily) {
		checkMetricsCount(t, m, 0)
	})
}

func TestKubeIncludeExcludeNamespaceMix2(t *testing.T) {
	testRequestKube(t, &Exporter{
		KubeIncludeNamespaces: []string{"default", "kube-system"},
		KubeExcludeNamespaces: []string{"kube-system"},
	}, func(m []model.MetricFamily) {
		checkMetricsCount(t, m, 10)
	})
}

func TestKubeIncludeExistingLabelWithoutValue(t *testing.T) {
	testRequestKube(t, &Exporter{
		KubeIncludeLabels: []string{"test"},
	}, func(m []model.MetricFamily) {
		checkMetricsCount(t, m, 20)
	})
}

func TestKubeIncludeNonExistingLabelWithoutValue(t *testing.T) {
	testRequestKube(t, &Exporter{
		KubeIncludeLabels: []string{"xxxx"},
	}, func(m []model.MetricFamily) {
		checkMetricsCount(t, m, 0)
	})
}

func TestKubeIncludeExistingLabelWithValue(t *testing.T) {
	testRequestKube(t, &Exporter{
		KubeIncludeLabels: []string{"aze=abc"},
	}, func(m []model.MetricFamily) {
		checkMetricsCount(t, m, 20)
	})
}

func TestKubeIncludeNonExistingLabelWithValue(t *testing.T) {
	testRequestKube(t, &Exporter{
		KubeIncludeLabels: []string{"xxx=xxx"},
	}, func(m []model.MetricFamily) {
		checkMetricsCount(t, m, 0)
	})
}

func TestKubeIncludeExistingLabelWithNonExistingValue(t *testing.T) {
	testRequestKube(t, &Exporter{
		KubeIncludeLabels: []string{"aze=xxx"},
	}, func(m []model.MetricFamily) {
		checkMetricsCount(t, m, 0)
	})
}

func TestKubeExcludeExistingLabelWithoutValue(t *testing.T) {
	testRequestKube(t, &Exporter{
		KubeExcludeLabels: []string{"test"},
	}, func(m []model.MetricFamily) {
		checkMetricsCount(t, m, 0)
	})
}

func TestKubeExcludeNonExistingLabelWithoutValue(t *testing.T) {
	testRequestKube(t, &Exporter{
		KubeExcludeLabels: []string{"xxxx"},
	}, func(m []model.MetricFamily) {
		checkMetricsCount(t, m, 20)
	})
}

func TestKubeExcludeExistingLabelWithValue(t *testing.T) {
	testRequestKube(t, &Exporter{
		KubeExcludeLabels: []string{"aze=abc"},
	}, func(m []model.MetricFamily) {
		checkMetricsCount(t, m, 0)
	})
}

func TestKubeExcludeNonExistingLabelWithValue(t *testing.T) {
	testRequestKube(t, &Exporter{
		KubeExcludeLabels: []string{"xxx=xxx"},
	}, func(m []model.MetricFamily) {
		checkMetricsCount(t, m, 20)
	})
}

func TestKubeExcludeExistingLabelWithNonExistingValue(t *testing.T) {
	testRequestKube(t, &Exporter{
		KubeExcludeLabels: []string{"aze=xxx"},
	}, func(m []model.MetricFamily) {
		checkMetricsCount(t, m, 20)
	})
}

func TestKubeIncludeExcludeLabelMix(t *testing.T) {
	testRequestKube(t, &Exporter{
		KubeIncludeLabels: []string{"aze=abc"},
		KubeExcludeLabels: []string{"aze=abc"},
	}, func(m []model.MetricFamily) {
		checkMetricsCount(t, m, 0)
	})
}

func TestKubeIncludeExcludeLabelMix2(t *testing.T) {
	testRequestKube(t, &Exporter{
		KubeIncludeLabels: []string{"test"},
		KubeExcludeLabels: []string{"index=0"},
	}, func(m []model.MetricFamily) {
		checkMetricsCount(t, m, 18)
	})
}

func TestKubeIncludeExcludeLabelMix3(t *testing.T) {
	testRequestKube(t, &Exporter{
		KubeIncludeLabels: []string{"test"},
		KubeExcludeLabels: []string{"xxxxx"},
	}, func(m []model.MetricFamily) {
		checkMetricsCount(t, m, 20)
	})
}

func TestKubeIncludeExcludeLabelMix4(t *testing.T) {
	testRequestKube(t, &Exporter{
		KubeIncludeLabels: []string{"index=0", "test"},
		KubeExcludeLabels: []string{"index=1"},
	}, func(m []model.MetricFamily) {
		checkMetricsCount(t, m, 2)
	})
}

func TestKubeCustomSecret(t *testing.T) {
	testRequestKube(t, &Exporter{
		KubeSecretTypes: []string{
			"istio.io/cert-and-key:cert-chain.pem",
			"istio.io/cert-and-key:root-cert.pem",
		},
	}, func(m []model.MetricFamily) {
		metric := getMetricsForName(m, "x509_cert_expired")
		assert.Len(t, metric, 2)
		checkLabels(t, metric[0].GetLabel(), "k8s/default/test-custom-type", true, 15)
		checkLabels(t, metric[1].GetLabel(), "k8s/default/test-custom-type", true, 15)
	})
}

func TestKubeMetricLabels(t *testing.T) {
	testRequestKube(t, &Exporter{
		KubeIncludeNamespaces: []string{"default"},
		KubeIncludeLabels:     []string{"index=0"},
	}, func(m []model.MetricFamily) {
		metric := getMetricsForName(m, "x509_cert_expired")[0]
		checkLabels(t, metric.GetLabel(), "k8s/default/test-default-0.crt", true, 15)
	})
}

func TestKubeNamespaceListFailure(t *testing.T) {
	kubeClient, err := connectToKubernetesCluster("kubeconfig.x509-certificate-exporter", true)
	if err != nil {
		panic(err)
	}

	testRequest(t, &Exporter{
		kubeClient: kubeClient,
	}, func(m []model.MetricFamily) {
		checkMetricsCount(t, m, 0)
		metrics := getMetricsForName(m, "x509_read_errors")
		assert.Equal(t, 1., metrics[0].GetGauge().GetValue())
	})
}

func TestKubeSecretsListFailure(t *testing.T) {
	kubeClient, err := connectToKubernetesCluster("kubeconfig.x509-certificate-exporter-list", true)
	if err != nil {
		panic(err)
	}

	testRequest(t, &Exporter{
		kubeClient: kubeClient,
	}, func(m []model.MetricFamily) {
		checkMetricsCount(t, m, 0)
		metrics := getMetricsForName(m, "x509_read_errors")
		assert.Equal(t, 5., metrics[0].GetGauge().GetValue())
	})
}

func TestKubeInvalidConfig(t *testing.T) {
	_, err := connectToKubernetesCluster("../test/kubeconfig-corrupted.yml", true)
	assert.NotNil(t, err)
}

func TestKubeInvalidConfig2(t *testing.T) {
	config, err := parseKubeConfig("kubeconfig")
	if err != nil {
		t.Error(err)
		return
	}

	config.Host = "dummy"
	kubeClient, err := getKubeClient(config)
	assert.NotNil(t, err)
	assert.Nil(t, kubeClient)
}

func TestKubeInvalidConfig3(t *testing.T) {
	config, err := parseKubeConfig("kubeconfig")
	if err != nil {
		t.Error(err)
		return
	}

	config.QPS = 1
	config.Burst = -1
	config.RateLimiter = nil
	kubeClient, err := getKubeClient(config)
	assert.NotNil(t, err)
	assert.Nil(t, kubeClient)
}

func TestKubeInvalidSecretType(t *testing.T) {
	testRequestKube(t, &Exporter{
		KubeIncludeNamespaces: []string{"default"},
		KubeSecretTypes:       []string{"aze"},
	}, func(m []model.MetricFamily) {
		metrics := getMetricsForName(m, "x509_read_errors")
		assert.Equal(t, 1., metrics[0].GetGauge().GetValue())
	})
}

func TestKubeEmptyStringKey(t *testing.T) {
	testRequestKube(t, &Exporter{
		KubeIncludeLabels: []string{"empty=true"},
		KubeSecretTypes:   []string{"kubernetes.io/tls:tls.crt", "kubernetes.io/tls:tls.key", "kubernetes.io/tls:nil.key"},
	}, func(m []model.MetricFamily) {
		metrics := getMetricsForName(m, "x509_read_errors")
		assert.Equal(t, 0., metrics[0].GetGauge().GetValue())
	})
}

func TestKubeConnectionFromInsideFailure(t *testing.T) {
	e := &Exporter{}
	err := e.ConnectToKubernetesCluster("")
	assert.NotNil(t, err)
}

func testRequestKube(t *testing.T, e *Exporter, f func(metrics []model.MetricFamily)) {
	e.kubeClient = sharedKubeClient
	testRequest(t, e, f)
}

func checkMetricsCount(t *testing.T, allMetrics []model.MetricFamily, count int) {
	metrics := getMetricsForName(allMetrics, "x509_cert_expired")
	assert.Len(t, metrics, count, "invalid number of x509_cert_expired metrics")

	nbMetrics := getMetricsForName(allMetrics, "x509_cert_not_before")
	assert.Len(t, nbMetrics, count, "invalid number of x509_cert_not_before metrics")

	naMetrics := getMetricsForName(allMetrics, "x509_cert_not_after")
	assert.Len(t, naMetrics, count, "invalid number of x509_cert_not_after metrics")
}

func addKubeSecrets(count int, ns string) error {
	for index := 0; index < count; index++ {
		certPath := fmt.Sprintf("/tmp/test-%s-%d.crt", ns, index)
		generateCertificate(certPath, time.Now())
		cert, err := os.ReadFile(certPath)
		if err != nil {
			return err
		}

		key, err := os.ReadFile(certPath + ".key")
		if err != nil {
			return err
		}

		_, err = sharedKubeClient.CoreV1().Secrets(ns).Create(context.Background(), &v1.Secret{
			Type: "kubernetes.io/tls",
			Data: map[string][]byte{
				"tls.crt": cert,
				"tls.key": key,
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: filepath.Base(certPath),
				Labels: map[string]string{
					"test":  "",
					"aze":   "abc",
					"index": fmt.Sprintf("%d", index),
				},
			},
		}, metav1.CreateOptions{})

		if err != nil {
			return err
		}
	}

	return nil
}

func addCustomKubeSecret() {
	certPath := "/tmp/test-custom-type.crt"
	generateCertificate(certPath, time.Now())
	cert, err := os.ReadFile(certPath)
	if err != nil {
		panic(err)
	}

	_, err = sharedKubeClient.CoreV1().Secrets("default").Create(context.Background(), &v1.Secret{
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
		panic(err)
	}
}

func removeCustomKubeSecret() {
	sharedKubeClient.CoreV1().Secrets("default").Delete(context.Background(), "test-custom-type", metav1.DeleteOptions{})
}

func addBrokenKubeSecret() {
	corruptedData, err := os.ReadFile("../test/corrupted.pem")
	if err != nil {
		panic(err)
	}

	_, err = sharedKubeClient.CoreV1().Secrets("default").Create(context.Background(), &v1.Secret{
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
		panic(err)
	}
}

func addBrokenKubeSecret2() {
	data, err := os.ReadFile("../test/basic.pem")
	if err != nil {
		panic(err)
	}

	_, err = sharedKubeClient.CoreV1().Secrets("default").Create(context.Background(), &v1.Secret{
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
		panic(err)
	}
}

func removeBrokenKubeSecret() {
	sharedKubeClient.CoreV1().Secrets("default").Delete(context.TODO(), "corrupted-pem-data", metav1.DeleteOptions{})
}

func removeBrokenKubeSecret2() {
	sharedKubeClient.CoreV1().Secrets("default").Delete(context.TODO(), "empty-pem-data", metav1.DeleteOptions{})
}

func removeAllKubeSecrets(count int, ns string) {
	for index := 0; index < count; index++ {
		name := fmt.Sprintf("test-%s-%d.crt", ns, index)
		err := sharedKubeClient.CoreV1().Secrets(ns).Delete(context.TODO(), name, metav1.DeleteOptions{})
		if err != nil {
			panic(err)
		}

		removeGeneratedCertificate(path.Join("/tmp", name))
	}
}

func cleanupSecrets() {
	removeAllKubeSecrets(10, "default")
	removeAllKubeSecrets(10, "kube-system")
	removeCustomKubeSecret()
	removeBrokenKubeSecret()
	removeBrokenKubeSecret2()
}
