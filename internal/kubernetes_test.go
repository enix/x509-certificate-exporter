package internal

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
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

	sharedKubeClient, err = connectToKubernetesCluster("kubeconfig", true, nil)
	if err != nil {
		panic(err)
	}

	// Make tests repeatable on a test cluster by deleting existing secret upfront
	cleanup := func(failOnError bool) {
		removeAllKubeSecrets(10, "default", failOnError)
		removeAllKubeSecrets(10, "kube-system", failOnError)
		removeCustomKubeSecret()
		removeBrokenKubeSecret()
		removeBrokenKubeSecret2()
	}
	cleanup(false)

	//nolint:errcheck
	addKubeSecrets(10, "default")
	//nolint:errcheck
	addKubeSecrets(10, "kube-system")
	addCustomKubeSecret()
	addBrokenKubeSecret()
	addBrokenKubeSecret2()

	status := m.Run()

	cleanup(true)

	os.Remove("kubeconfig")
	os.Remove("kubeconfig.x509-certificate-exporter")
	os.Remove("kubeconfig.x509-certificate-exporter-list")
	os.Exit(status)
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
			testRequestKube(t, &tt.Exporter, func(m []model.MetricFamily) {
				checkMetricsCount(t, m, tt.MetricCount)
			})
		})
	}
}

func TestKubeNamespaceListFailure(t *testing.T) {
	kubeClient, err := connectToKubernetesCluster("kubeconfig.x509-certificate-exporter", true, nil)
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
	kubeClient, err := connectToKubernetesCluster("kubeconfig.x509-certificate-exporter-list", true, nil)
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
	_, err := connectToKubernetesCluster("../test/kubeconfig-corrupted.yml", true, nil)
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
	_, err := ParseSecretType("aze")
	assert.Error(t, err)
}

func TestKubeEmptyStringKey(t *testing.T) {
	testRequestKube(t, &Exporter{
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

		secretName := filepath.Base(certPath)

		_, err = sharedKubeClient.CoreV1().Secrets(ns).Create(context.Background(), &v1.Secret{
			Type: "kubernetes.io/tls",
			Data: map[string][]byte{
				"tls.crt": cert,
				"tls.key": key,
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: secretName,
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
	//nolint:errcheck
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
	//nolint:errcheck
	sharedKubeClient.CoreV1().Secrets("default").Delete(context.TODO(), "corrupted-pem-data", metav1.DeleteOptions{})
}

func removeBrokenKubeSecret2() {
	//nolint:errcheck
	sharedKubeClient.CoreV1().Secrets("default").Delete(context.TODO(), "empty-pem-data", metav1.DeleteOptions{})
}

func removeAllKubeSecrets(count int, ns string, failOnError bool) {
	for index := 0; index < count; index++ {
		name := fmt.Sprintf("test-%s-%d.crt", ns, index)
		err := sharedKubeClient.CoreV1().Secrets(ns).Delete(context.TODO(), name, metav1.DeleteOptions{})
		if err != nil && failOnError {
			panic(err)
		}

		removeGeneratedCertificate(path.Join("/tmp", name))
	}
}
