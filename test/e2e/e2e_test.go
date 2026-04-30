//go:build e2e

// End-to-end test: scrape /metrics from a running exporter and assert that
// every dev/scenarios entry shows up with the expected behaviour. Run via
// `task test:e2e` (which also brings up the cluster + seeds it). To run only the
// assertions against a pre-running exporter, set E2E_METRICS_URL and run
// `go test -tags=e2e -v ./test/e2e/...`.
package e2e

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"

	"github.com/enix/x509-certificate-exporter/v4/dev/scenarios"
)

const (
	defaultMetricsURL = "http://127.0.0.1:9793/metrics"
	scrapeAttempts    = 12
	scrapeBackoff     = 5 * time.Second
)

func metricsURL() string {
	if u := os.Getenv("E2E_METRICS_URL"); u != "" {
		return u
	}
	return defaultMetricsURL
}

// scrape fetches and parses the exporter's text-format metric exposition.
// It retries until the exporter has had a chance to discover every seeded
// object — k8s informers + cache settle within a few seconds.
func scrape(t *testing.T) map[string]*dto.MetricFamily {
	t.Helper()
	var lastErr error
	var lastFams map[string]*dto.MetricFamily
	for i := 0; i < scrapeAttempts; i++ {
		fams, err := tryScrape(metricsURL())
		if err == nil && hasInitialReadyState(fams) {
			return fams
		}
		lastErr = err
		lastFams = fams
		time.Sleep(scrapeBackoff)
	}
	t.Fatalf("exporter never returned ready metrics: lastErr=%v\n%s", lastErr, summarise(lastFams))
	return nil
}

// summarise gives a one-shot snapshot of why hasInitialReadyState is failing.
func summarise(fams map[string]*dto.MetricFamily) string {
	if fams == nil {
		return "(no metrics scraped)"
	}
	out := fmt.Sprintf("scraped %d metric families\n", len(fams))
	for _, name := range []string{"x509_source_up", "x509_source_bundles", "x509_source_errors_total", "x509_cert_not_after"} {
		fam := fams[name]
		if fam == nil {
			out += fmt.Sprintf("  %s: <missing>\n", name)
			continue
		}
		out += fmt.Sprintf("  %s: %d series\n", name, len(fam.GetMetric()))
		for _, m := range fam.GetMetric() {
			labels := ""
			for _, l := range m.GetLabel() {
				labels += fmt.Sprintf(" %s=%q", l.GetName(), l.GetValue())
			}
			val := 0.0
			if g := m.GetGauge(); g != nil {
				val = g.GetValue()
			} else if c := m.GetCounter(); c != nil {
				val = c.GetValue()
			}
			out += fmt.Sprintf("    {%s } = %v\n", labels, val)
		}
	}
	return out
}

func tryScrape(url string) (map[string]*dto.MetricFamily, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, body)
	}
	// prometheus/common >=0.62 requires an explicit validation scheme;
	// the zero-value TextParser panics on the first metric name.
	p := expfmt.NewTextParser(model.UTF8Validation)
	return p.TextToMetricFamilies(resp.Body)
}

// hasInitialReadyState waits for x509_source_up == 1 on the kubernetes
// source AND at least one x509_cert_not_after series. The first signals
// "informers have synced and the source's OnReady fired", the second
// confirms that the registry has actually emitted cert metrics.
func hasInitialReadyState(fams map[string]*dto.MetricFamily) bool {
	upFam := fams["x509_source_up"]
	if upFam == nil {
		return false
	}
	any := false
	for _, m := range upFam.GetMetric() {
		if m.GetGauge().GetValue() != 1 {
			return false
		}
		any = true
	}
	if !any {
		return false
	}
	return fams["x509_cert_not_after"] != nil
}

func TestExporterCoversAllScenarios(t *testing.T) {
	fams := scrape(t)
	notAfter := fams["x509_cert_not_after"]
	expired := fams["x509_cert_expired"]
	notBefore := fams["x509_cert_not_before"]
	certError := fams["x509_cert_error"]
	srcErrors := fams["x509_source_errors_total"]
	if notAfter == nil || expired == nil {
		t.Fatalf("missing core x509_cert_* metric families (have %d families)", len(fams))
	}

	for _, sc := range scenarios.All() {
		sc := sc
		t.Run(fmt.Sprintf("%s/%s/%s", sc.Kind, sc.Namespace, sc.Name), func(t *testing.T) {
			if !sc.Watched {
				assertNoSeries(t, notAfter, sc)
				return
			}
			for _, e := range sc.Expect {
				if e.ParseError != "" {
					assertParseError(t, srcErrors, certError, sc, e)
					continue
				}
				assertCertSeries(t, notAfter, expired, notBefore, sc, e)
			}
		})
	}

	// Ancillary global checks.
	t.Run("source_up", func(t *testing.T) {
		fam := fams["x509_source_up"]
		if fam == nil {
			t.Fatal("x509_source_up missing")
		}
		want := map[string]string{
			"source_kind": "kubernetes",
			"source_name": "cluster-secrets",
		}
		m := find(fam, want)
		if m == nil {
			t.Fatalf("no x509_source_up series with %v", want)
		}
		if m.GetGauge().GetValue() != 1 {
			t.Fatalf("x509_source_up{kubernetes/cluster-secrets} = %v, want 1", m.GetGauge().GetValue())
		}
	})

	t.Run("source_bundles_present", func(t *testing.T) {
		fam := fams["x509_source_bundles"]
		if fam == nil {
			t.Fatal("x509_source_bundles missing")
		}
		var total float64
		for _, m := range fam.GetMetric() {
			total += m.GetGauge().GetValue()
		}
		if total <= 0 {
			t.Fatalf("expected x509_source_bundles total > 0, got %v", total)
		}
	})
}

func assertNoSeries(t *testing.T, fam *dto.MetricFamily, sc scenarios.Scenario) {
	t.Helper()
	if fam == nil {
		return
	}
	for _, m := range fam.GetMetric() {
		if labelEq(m, "secret_namespace", sc.Namespace) && labelEq(m, "secret_name", sc.Name) {
			t.Fatalf("scenario marked Watched=false but x509_cert_not_after has series: %s", m.String())
		}
	}
}

func assertCertSeries(t *testing.T, notAfter, expired, notBefore *dto.MetricFamily, sc scenarios.Scenario, e scenarios.ExpectCert) {
	t.Helper()
	nsLabel, nameLabel, keyLabel := sourceLabels(sc.Kind)
	want := map[string]string{
		nsLabel:      sc.Namespace,
		nameLabel:    sc.Name,
		keyLabel:     e.Key,
		"subject_CN": e.SubjectCN,
	}
	naMetric := find(notAfter, want)
	if naMetric == nil {
		t.Fatalf("no x509_cert_not_after series with %v", want)
	}
	exMetric := find(expired, want)
	if exMetric == nil {
		t.Fatalf("no x509_cert_expired series with %v", want)
	}
	got := exMetric.GetGauge().GetValue()
	switch e.Lifecycle {
	case scenarios.LifecycleExpired:
		if got != 1 {
			t.Fatalf("%s/%s key=%s: expected expired=1, got %v", sc.Namespace, sc.Name, e.Key, got)
		}
	case scenarios.LifecycleValid, scenarios.LifecycleNotYetValid:
		if got != 0 {
			t.Fatalf("%s/%s key=%s: expected expired=0, got %v", sc.Namespace, sc.Name, e.Key, got)
		}
	}
	if e.Lifecycle == scenarios.LifecycleNotYetValid {
		nbMetric := find(notBefore, want)
		if nbMetric == nil {
			t.Fatalf("no x509_cert_not_before series with %v", want)
		}
		nb := nbMetric.GetGauge().GetValue()
		if int64(nb) <= time.Now().Unix() {
			t.Fatalf("%s/%s: NotBefore=%v should be in the future", sc.Namespace, sc.Name, nb)
		}
	}
}

func assertParseError(t *testing.T, srcErrors, certError *dto.MetricFamily, sc scenarios.Scenario, e scenarios.ExpectCert) {
	t.Helper()
	// bad_pem (Index>=0) emits an x509_cert_error series. The other
	// reasons (bad_pkcs12, bad_passphrase, no_certificate_found) only bump
	// the source-level counter.
	if e.ParseError == scenarios.ErrBadPEM {
		want := map[string]string{
			"secret_namespace": sc.Namespace,
			"secret_name":      sc.Name,
			"secret_key":       e.Key,
		}
		if find(certError, want) == nil {
			t.Fatalf("expected x509_cert_error series for %s/%s key=%s", sc.Namespace, sc.Name, e.Key)
		}
	}
	if srcErrors == nil {
		t.Fatalf("x509_source_errors_total is missing")
	}
	for _, m := range srcErrors.GetMetric() {
		if labelEq(m, "reason", string(e.ParseError)) && m.GetCounter().GetValue() > 0 {
			return
		}
	}
	t.Fatalf("expected x509_source_errors_total{reason=%q} > 0", e.ParseError)
}

func sourceLabels(kind string) (ns, name, key string) {
	if kind == "ConfigMap" {
		return "configmap_namespace", "configmap_name", "configmap_key"
	}
	return "secret_namespace", "secret_name", "secret_key"
}

func find(fam *dto.MetricFamily, want map[string]string) *dto.Metric {
	if fam == nil {
		return nil
	}
	for _, m := range fam.GetMetric() {
		match := true
		for k, v := range want {
			if !labelEq(m, k, v) {
				match = false
				break
			}
		}
		if match {
			return m
		}
	}
	return nil
}

func labelEq(m *dto.Metric, name, value string) bool {
	for _, l := range m.GetLabel() {
		if l.GetName() == name {
			return l.GetValue() == value
		}
	}
	return false
}

// Sanity: surface a printable line per failure to ease debugging.
func init() {
	if v := os.Getenv("E2E_VERBOSE"); v != "" {
		fmt.Fprintln(os.Stderr, "[e2e] metrics URL:", metricsURL())
	}
}
