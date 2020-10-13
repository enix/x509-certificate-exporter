package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	exporter "enix.io/x509-exporter/internal"
	model "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/stretchr/testify/assert"
)

const port = 9090

func TestRegularStartup(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)

	e := &exporter.Exporter{
		Port:  port,
		Files: []string{path.Join(filepath.Dir(filename), "../../test/basic.pem")},
	}

	go e.ListenAndServe()
	time.Sleep(3 * time.Second)

	res, err := http.Get(fmt.Sprintf("http://localhost:%d/metrics", port))
	if err != nil || res.StatusCode != 200 {
		t.Errorf("exporter did not start within 3 seconds")
		return
	}

	e.Shutdown()
}

func TestNoInput(t *testing.T) {
	testRequest(t, &exporter.Exporter{
		Port: port,
	}, func(metrics []model.MetricFamily) {
		metric := getMetricsForName(metrics, "x509_cert_expired")
		assert.Empty(t, metric, "found x509_cert_expired despite nothing is watched")
	})
}

func TestSinglePEMNotExpired(t *testing.T) {
	testSinglePEM(t, 0, time.Now())
}

func TestSinglePEMExpired(t *testing.T) {
	testSinglePEM(t, 1, time.Now().Add(-2*time.Hour))
}

func TestMultiplePEM(t *testing.T) {
	notBefore := time.Now()
	notAfter := notBefore.Add(time.Hour)
	nbVal := float64(notBefore.Unix())
	naVal := float64(notAfter.Unix())

	generateCertificate("/tmp/test.pem", notBefore)
	generateCertificate("/tmp/test2.pem", notBefore)
	generateCertificate("/tmp/test3.pem", notBefore)
	generateCertificate("/tmp/test4.pem", notBefore)

	testRequest(t, &exporter.Exporter{
		Port:  port,
		Files: []string{"/tmp/test.pem", "/tmp/test2.pem", "/tmp/test3.pem", "/tmp/test4.pem"},
	}, func(metrics []model.MetricFamily) {
		foundMetrics := getMetricsForName(metrics, "x509_cert_expired")
		assert.Len(t, foundMetrics, 4, "missing x509_cert_expired metric(s)")
		for _, m := range foundMetrics {
			assert.Equal(t, 0., m.GetGauge().GetValue(), fmt.Sprintf("x509_cert_expired should be %f", 0.))
		}

		foundNbMetrics := getMetricsForName(metrics, "x509_cert_not_before")
		assert.Len(t, foundNbMetrics, 4, "missing x509_cert_not_before metric(s)")
		for _, m := range foundNbMetrics {
			assert.Equal(t, nbVal, m.GetGauge().GetValue(), fmt.Sprintf("x509_cert_not_before should be %f", nbVal))
		}

		foundNaMetrics := getMetricsForName(metrics, "x509_cert_not_after")
		assert.Len(t, foundNaMetrics, 4, "missing x509_cert_not_after metric(s)")
		for _, m := range foundNaMetrics {
			assert.Equal(t, naVal, m.GetGauge().GetValue(), fmt.Sprintf("x509_cert_not_after should be %f", naVal))
		}

		os.Remove("/tmp/test.pem")
		os.Remove("/tmp/test2.pem")
		os.Remove("/tmp/test3.pem")
		os.Remove("/tmp/test4.pem")
	})
}

func TestFolder(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)

	testRequest(t, &exporter.Exporter{
		Port:        port,
		Directories: []string{path.Join(filepath.Dir(filename), "../../test")},
	}, func(metrics []model.MetricFamily) {
		foundMetrics := getMetricsForName(metrics, "x509_cert_expired")
		assert.Len(t, foundMetrics, 3, "missing x509_cert_expired metric(s)")

		foundNbMetrics := getMetricsForName(metrics, "x509_cert_not_before")
		assert.Len(t, foundNbMetrics, 3, "missing x509_cert_not_before metric(s)")

		foundNaMetrics := getMetricsForName(metrics, "x509_cert_not_after")
		assert.Len(t, foundNaMetrics, 3, "missing x509_cert_not_after metric(s)")
	})
}

func TestYAMLEmbedded(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)

	testRequest(t, &exporter.Exporter{
		Port:      port,
		YAMLs:     []string{path.Join(filepath.Dir(filename), "../../test/yaml-embedded.conf")},
		YAMLPaths: exporter.DefaultYamlPaths,
	}, func(metrics []model.MetricFamily) {
		foundMetrics := getMetricsForName(metrics, "x509_cert_expired")
		assert.Len(t, foundMetrics, 2, "missing x509_cert_expired metric(s)")

		foundNbMetrics := getMetricsForName(metrics, "x509_cert_not_before")
		assert.Len(t, foundNbMetrics, 2, "missing x509_cert_not_before metric(s)")

		foundNaMetrics := getMetricsForName(metrics, "x509_cert_not_after")
		assert.Len(t, foundNaMetrics, 2, "missing x509_cert_not_after metric(s)")
	})
}

func TestYAMLPath(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)

	testRequest(t, &exporter.Exporter{
		Port:      port,
		YAMLs:     []string{path.Join(filepath.Dir(filename), "../../test/yaml-paths.conf")},
		YAMLPaths: exporter.DefaultYamlPaths,
	}, func(metrics []model.MetricFamily) {
		foundMetrics := getMetricsForName(metrics, "x509_cert_expired")
		assert.Len(t, foundMetrics, 2, "missing x509_cert_expired metric(s)")

		foundNbMetrics := getMetricsForName(metrics, "x509_cert_not_before")
		assert.Len(t, foundNbMetrics, 2, "missing x509_cert_not_before metric(s)")

		foundNaMetrics := getMetricsForName(metrics, "x509_cert_not_after")
		assert.Len(t, foundNaMetrics, 2, "missing x509_cert_not_after metric(s)")
	})
}

func TestYAMLMixed(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)

	testRequest(t, &exporter.Exporter{
		Port:      port,
		YAMLs:     []string{path.Join(filepath.Dir(filename), "../../test/yaml-mixed.conf")},
		YAMLPaths: exporter.DefaultYamlPaths,
	}, func(metrics []model.MetricFamily) {
		foundMetrics := getMetricsForName(metrics, "x509_cert_expired")
		assert.Len(t, foundMetrics, 2, "missing x509_cert_expired metric(s)")

		foundNbMetrics := getMetricsForName(metrics, "x509_cert_not_before")
		assert.Len(t, foundNbMetrics, 2, "missing x509_cert_not_before metric(s)")

		foundNaMetrics := getMetricsForName(metrics, "x509_cert_not_after")
		assert.Len(t, foundNaMetrics, 2, "missing x509_cert_not_after metric(s)")
	})
}

func TestNonExistentPEMFile(t *testing.T) {
	testRequest(t, &exporter.Exporter{
		Port:  port,
		Files: []string{"./does-not-exists.pem"},
	}, func(metrics []model.MetricFamily) {
		foundMetrics := getMetricsForName(metrics, "x509_cert_expired")
		assert.Len(t, foundMetrics, 0, "missing x509_cert_expired metric(s)")

		foundNbMetrics := getMetricsForName(metrics, "x509_cert_not_before")
		assert.Len(t, foundNbMetrics, 0, "missing x509_cert_not_before metric(s)")

		foundNaMetrics := getMetricsForName(metrics, "x509_cert_not_after")
		assert.Len(t, foundNaMetrics, 0, "missing x509_cert_not_after metric(s)")

		errorMetric := getMetricsForName(metrics, "x509_read_errors")
		assert.Len(t, errorMetric, 1, "missing x509_read_errors metric")
		assert.Equal(t, errorMetric[0].GetGauge().GetValue(), 1., "invalid x509_read_errors value")
	})
}

func TestNonExistentYAMLFile(t *testing.T) {
	testRequest(t, &exporter.Exporter{
		Port:      port,
		YAMLs:     []string{"./does-not-exists.yaml"},
		YAMLPaths: exporter.DefaultYamlPaths,
	}, func(metrics []model.MetricFamily) {
		foundMetrics := getMetricsForName(metrics, "x509_cert_expired")
		assert.Len(t, foundMetrics, 0, "missing x509_cert_expired metric(s)")

		foundNbMetrics := getMetricsForName(metrics, "x509_cert_not_before")
		assert.Len(t, foundNbMetrics, 0, "missing x509_cert_not_before metric(s)")

		foundNaMetrics := getMetricsForName(metrics, "x509_cert_not_after")
		assert.Len(t, foundNaMetrics, 0, "missing x509_cert_not_after metric(s)")

		errorMetric := getMetricsForName(metrics, "x509_read_errors")
		assert.Len(t, errorMetric, 1, "missing x509_read_errors metric")
		assert.Equal(t, errorMetric[0].GetGauge().GetValue(), 1., "invalid x509_read_errors value")
	})
}

func TestNonExistentDir(t *testing.T) {
	testRequest(t, &exporter.Exporter{
		Port:        port,
		Directories: []string{"./does-not-exists"},
	}, func(metrics []model.MetricFamily) {
		foundMetrics := getMetricsForName(metrics, "x509_cert_expired")
		assert.Len(t, foundMetrics, 0, "missing x509_cert_expired metric(s)")

		foundNbMetrics := getMetricsForName(metrics, "x509_cert_not_before")
		assert.Len(t, foundNbMetrics, 0, "missing x509_cert_not_before metric(s)")

		foundNaMetrics := getMetricsForName(metrics, "x509_cert_not_after")
		assert.Len(t, foundNaMetrics, 0, "missing x509_cert_not_after metric(s)")

		errorMetric := getMetricsForName(metrics, "x509_read_errors")
		assert.Len(t, errorMetric, 1, "missing x509_read_errors metric")
		assert.Equal(t, errorMetric[0].GetGauge().GetValue(), 1., "invalid x509_read_errors value")
	})
}

func TestNonExistentYAMLPath(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)

	testRequest(t, &exporter.Exporter{
		Port:      port,
		YAMLs:     []string{path.Join(filepath.Dir(filename), "../../test/yaml-paths-error.conf")},
		YAMLPaths: exporter.DefaultYamlPaths,
	}, func(metrics []model.MetricFamily) {
		foundMetrics := getMetricsForName(metrics, "x509_cert_expired")
		assert.Len(t, foundMetrics, 0, "missing x509_cert_expired metric(s)")

		foundNbMetrics := getMetricsForName(metrics, "x509_cert_not_before")
		assert.Len(t, foundNbMetrics, 0, "missing x509_cert_not_before metric(s)")

		foundNaMetrics := getMetricsForName(metrics, "x509_cert_not_after")
		assert.Len(t, foundNaMetrics, 0, "missing x509_cert_not_after metric(s)")

		errorMetric := getMetricsForName(metrics, "x509_read_errors")
		assert.Len(t, errorMetric, 1, "missing x509_read_errors metric")
		assert.Equal(t, errorMetric[0].GetGauge().GetValue(), 1., "invalid x509_read_errors value")
	})
}

func TestCorruptedCertInYAML(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)

	testRequest(t, &exporter.Exporter{
		Port:      port,
		YAMLs:     []string{path.Join(filepath.Dir(filename), "../../test/yaml-embedded-error.conf")},
		YAMLPaths: exporter.DefaultYamlPaths,
	}, func(metrics []model.MetricFamily) {
		foundMetrics := getMetricsForName(metrics, "x509_cert_expired")
		assert.Len(t, foundMetrics, 0, "missing x509_cert_expired metric(s)")

		foundNbMetrics := getMetricsForName(metrics, "x509_cert_not_before")
		assert.Len(t, foundNbMetrics, 0, "missing x509_cert_not_before metric(s)")

		foundNaMetrics := getMetricsForName(metrics, "x509_cert_not_after")
		assert.Len(t, foundNaMetrics, 0, "missing x509_cert_not_after metric(s)")

		errorMetric := getMetricsForName(metrics, "x509_read_errors")
		assert.Len(t, errorMetric, 1, "missing x509_read_errors metric")
		assert.Equal(t, errorMetric[0].GetGauge().GetValue(), 1., "invalid x509_read_errors value")
	})
}

func TestBindAddrAlreadyInUse(t *testing.T) {
	listener, _ := net.Listen("tcp", ":9090")
	e := &exporter.Exporter{Port: 9090}
	err := e.ListenAndServe()
	listener.Close()
	assert.NotNil(t, err, "no error was returned for bind failure")
}

func TestLoadFileAsDir(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)

	testRequest(t, &exporter.Exporter{
		Port:        port,
		Directories: []string{path.Join(filepath.Dir(filename), "../../test/basic.pem")},
	}, func(metrics []model.MetricFamily) {
		foundMetrics := getMetricsForName(metrics, "x509_cert_expired")
		assert.Len(t, foundMetrics, 0, "missing x509_cert_expired metric(s)")

		foundNbMetrics := getMetricsForName(metrics, "x509_cert_not_before")
		assert.Len(t, foundNbMetrics, 0, "missing x509_cert_not_before metric(s)")

		foundNaMetrics := getMetricsForName(metrics, "x509_cert_not_after")
		assert.Len(t, foundNaMetrics, 0, "missing x509_cert_not_after metric(s)")

		errorMetric := getMetricsForName(metrics, "x509_read_errors")
		assert.Len(t, errorMetric, 1, "missing x509_read_errors metric")
		assert.Equal(t, errorMetric[0].GetGauge().GetValue(), 1., "invalid x509_read_errors value")
	})
}

func TestLoadDirAsFile(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)

	testRequest(t, &exporter.Exporter{
		Port:  port,
		Files: []string{path.Join(filepath.Dir(filename), "../../test")},
	}, func(metrics []model.MetricFamily) {
		foundMetrics := getMetricsForName(metrics, "x509_cert_expired")
		assert.Len(t, foundMetrics, 0, "missing x509_cert_expired metric(s)")

		foundNbMetrics := getMetricsForName(metrics, "x509_cert_not_before")
		assert.Len(t, foundNbMetrics, 0, "missing x509_cert_not_before metric(s)")

		foundNaMetrics := getMetricsForName(metrics, "x509_cert_not_after")
		assert.Len(t, foundNaMetrics, 0, "missing x509_cert_not_after metric(s)")

		errorMetric := getMetricsForName(metrics, "x509_read_errors")
		assert.Len(t, errorMetric, 1, "missing x509_read_errors metric")
		assert.Equal(t, errorMetric[0].GetGauge().GetValue(), 1., "invalid x509_read_errors value")
	})
}

func TestInvalidYAMLMatchExpr(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)

	testRequest(t, &exporter.Exporter{
		Port:  port,
		YAMLs: []string{path.Join(filepath.Dir(filename), "../../test/yaml-embedded.conf")},
		YAMLPaths: []exporter.YAMLCertRef{
			{
				CertMatchExpr: "clusters.[*].cluster.certificate-authority-data",
				IDMatchExpr:   "clusters.[.name",
				Format:        exporter.YAMLCertFormatBase64,
			},
		},
	}, func(metrics []model.MetricFamily) {
		foundMetrics := getMetricsForName(metrics, "x509_cert_expired")
		assert.Len(t, foundMetrics, 0, "extra x509_cert_expired metric(s)")

		foundNbMetrics := getMetricsForName(metrics, "x509_cert_not_before")
		assert.Len(t, foundNbMetrics, 0, "extra x509_cert_not_before metric(s)")

		foundNaMetrics := getMetricsForName(metrics, "x509_cert_not_after")
		assert.Len(t, foundNaMetrics, 0, "extra x509_cert_not_after metric(s)")

		errorMetric := getMetricsForName(metrics, "x509_read_errors")
		assert.Len(t, errorMetric, 1, "missing x509_read_errors metric")
		assert.Equal(t, errorMetric[0].GetGauge().GetValue(), 1., "invalid x509_read_errors value")
	})
}

func TestMultipleErrors(t *testing.T) {
	testRequest(t, &exporter.Exporter{
		Port:        port,
		Files:       []string{"does", "not", "exist"},
		Directories: []string{"toto"},
		YAMLs:       []string{"lol", "aze"},
	}, func(metrics []model.MetricFamily) {
		errorMetric := getMetricsForName(metrics, "x509_read_errors")
		assert.Len(t, errorMetric, 1, "missing x509_read_errors metric")
		assert.Equal(t, errorMetric[0].GetGauge().GetValue(), 6., "invalid x509_read_errors value")
	})
}

func testSinglePEM(t *testing.T, expired float64, notBefore time.Time) {
	generateCertificate("/tmp/test.pem", notBefore)

	testRequest(t, &exporter.Exporter{
		Port:  port,
		Files: []string{"/tmp/test.pem"},
	}, func(metrics []model.MetricFamily) {
		metric := getMetricsForName(metrics, "x509_cert_expired")
		assert.NotEmpty(t, metric, "missing x509_cert_expired metric")
		value := metric[0].GetGauge().GetValue()
		assert.Equal(t, expired, value, fmt.Sprintf("x509_cert_expired should be %f", expired))
		checkLabels(t, metric[0].GetLabel())

		nbMetric := getMetricsForName(metrics, "x509_cert_not_before")
		assert.NotEmpty(t, nbMetric, "missing x509_cert_not_before metric")
		nbValue := nbMetric[0].GetGauge().GetValue()
		assert.Equal(t, float64(notBefore.Unix()), nbValue, "x509_cert_not_before has invalid value")
		checkLabels(t, nbMetric[0].GetLabel())

		naMetric := getMetricsForName(metrics, "x509_cert_not_after")
		assert.NotEmpty(t, naMetric, "missing x509_cert_not_after metric")
		naValue := naMetric[0].GetGauge().GetValue()
		assert.Equal(t, float64(notBefore.Add(time.Hour).Unix()), naValue, "x509_cert_not_after has invalid value")
		checkLabels(t, naMetric[0].GetLabel())

		os.Remove("/tmp/test.pem")
	})
}

func checkLabels(t *testing.T, labels []*model.LabelPair) {
	assert.Len(t, labels, 15, "Missing labels")

	for _, label := range labels {
		if label.GetName() == "filename" {
			assert.Equal(t, "test.pem", label.GetValue(), "Invalid label value for %s", label.GetName())
		} else if label.GetName() == "filepath" {
			assert.Equal(t, "/tmp/test.pem", label.GetValue(), "Invalid label value for %s", label.GetName())
		} else if label.GetName() == "serial_number" {
			assert.Equal(t, "1", label.GetValue(), "Invalid label value for %s", label.GetName())
		} else {
			assert.Equal(t, strings.Split(label.GetName(), "_")[1], label.GetValue(), "Invalid label value for %s", label.GetName())
		}
	}
}

func testRequest(t *testing.T, e *exporter.Exporter, cb func(metrics []model.MetricFamily)) {
	e.DiscoverCertificates()
	e.Listen()
	go func() {
		res, err := http.Get(fmt.Sprintf("http://localhost:%d/metrics", port))
		if err != nil {
			t.Error(err)
			return
		}

		var metric model.MetricFamily
		metrics := []model.MetricFamily{}

		decoder := expfmt.NewDecoder(res.Body, expfmt.FmtText)
		for {
			if err := decoder.Decode(&metric); err != nil {
				break
			}

			metrics = append(metrics, metric)
		}

		fmt.Printf("%d", len(metrics))
		cb(metrics)
		e.Shutdown()
	}()
	e.Serve()
}

func getMetricsForName(metrics []model.MetricFamily, name string) []*model.Metric {
	for _, metric := range metrics {
		if metric.GetName() == name {
			return metric.GetMetric()
		}
	}

	return nil
}

func getPublicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}

func generateCertificate(path string, notBefore time.Time) {
	priv, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:         "CN",
			Organization:       []string{"O"},
			Country:            []string{"C"},
			OrganizationalUnit: []string{"OU"},
			StreetAddress:      []string{"ST"},
			Locality:           []string{"L"},
		},
		NotBefore: notBefore,
		NotAfter:  notBefore.Add(time.Hour),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, getPublicKey(priv), priv)
	if err != nil {
		log.Fatalf("Failed to create certificate: %s", err)
	}
	out := &bytes.Buffer{}
	pem.Encode(out, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	ioutil.WriteFile(path, out.Bytes(), 00644)
	out.Reset()
}
