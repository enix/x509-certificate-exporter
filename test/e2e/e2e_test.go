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
	"path"
	"strings"
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

// metricsURLs returns the list of /metrics endpoints to scrape and merge.
// E2E_METRICS_URL accepts a comma-separated list; the chart deploys two
// independent workloads (Deployment + DaemonSet) on different pods, so we
// scrape one URL per workload and union their metric families.
func metricsURLs() []string {
	v := os.Getenv("E2E_METRICS_URL")
	if v == "" {
		return []string{defaultMetricsURL}
	}
	return strings.Split(v, ",")
}

// scrape fetches and parses every URL returned by metricsURLs(), then
// merges the metric families. It retries until each endpoint has had a
// chance to discover every seeded object.
func scrape(t *testing.T) map[string]*dto.MetricFamily {
	t.Helper()
	urls := metricsURLs()
	var lastErr error
	var lastFams map[string]*dto.MetricFamily
	for i := 0; i < scrapeAttempts; i++ {
		merged := map[string]*dto.MetricFamily{}
		ok := true
		var err error
		for _, u := range urls {
			fams, e := tryScrape(u)
			if e != nil {
				err = e
				ok = false
				break
			}
			mergeFamilies(merged, fams)
		}
		if ok && hasInitialReadyState(merged) {
			return merged
		}
		lastErr = err
		lastFams = merged
		time.Sleep(scrapeBackoff)
	}
	t.Fatalf("exporter never returned ready metrics: lastErr=%v\n%s", lastErr, summarise(lastFams))
	return nil
}

// mergeFamilies appends metrics from src into dst, family-by-family. Each
// family is keyed by name; metrics within a family are concatenated. We
// don't dedupe by labelset because the two scraped pods report disjoint
// series (different sources, different filepath/secret_namespace labels).
func mergeFamilies(dst, src map[string]*dto.MetricFamily) {
	for name, fam := range src {
		if existing, ok := dst[name]; ok {
			existing.Metric = append(existing.Metric, fam.Metric...)
			continue
		}
		dst[name] = fam
	}
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

// hasInitialReadyState waits for every expected source to report
// x509_source_up == 1 AND for cert series from each to materialise. The
// chart deploys two distinct sources we scrape independently — a K8s
// LIST+WATCH one (cluster-secrets) and a file walker (host-paths-nodes)
// — and either can converge on an empty result faster than the other,
// so we explicitly require both before letting the assertion phase run.
func hasInitialReadyState(fams map[string]*dto.MetricFamily) bool {
	upFam := fams["x509_source_up"]
	if upFam == nil {
		return false
	}
	wantSources := map[string]bool{
		"cluster-secrets":   false,
		"host-paths-nodes":  false,
	}
	for _, m := range upFam.GetMetric() {
		if m.GetGauge().GetValue() != 1 {
			continue
		}
		var name string
		for _, l := range m.GetLabel() {
			if l.GetName() == "source_name" {
				name = l.GetValue()
				break
			}
		}
		if _, want := wantSources[name]; want {
			wantSources[name] = true
		}
	}
	for _, ok := range wantSources {
		if !ok {
			return false
		}
	}

	// Also wait until at least one filepath-tagged cert series has shown
	// up — otherwise the hostPath walker may have completed its first walk
	// (so up=1) without yet having emitted any cert because the seed Job
	// raced ahead of it. The assertion loop wants concrete series.
	naFam := fams["x509_cert_not_after"]
	if naFam == nil {
		return false
	}
	hostPathSeen := false
	k8sSeen := false
	for _, m := range naFam.GetMetric() {
		for _, l := range m.GetLabel() {
			switch l.GetName() {
			case "filepath":
				if l.GetValue() != "" {
					hostPathSeen = true
				}
			case "secret_name", "configmap_name":
				if l.GetValue() != "" {
					k8sSeen = true
				}
			}
		}
	}
	return hostPathSeen && k8sSeen
}

func TestExporterCoversAllScenarios(t *testing.T) {
	fams := scrape(t)
	notAfter := fams["x509_cert_not_after"]
	expired := fams["x509_cert_expired"]
	notBefore := fams["x509_cert_not_before"]
	certError := fams["x509_cert_error"]
	srcErrors := fams["x509_source_errors_total"]
	crlNextUpdate := fams["x509_crl_next_update"]
	crlStale := fams["x509_crl_stale"]
	crlNumber := fams["x509_crl_number"]
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
			for _, e := range sc.ExpectCRLs {
				assertCRLSeries(t, crlNextUpdate, crlStale, crlNumber, sc, e)
			}
		})
	}

	// hostPath scenarios — PEM files and symlinks materialised by the
	// seed-hostpath Job and watched by the chart's hostPathsExporter
	// DaemonSet (see test/e2e/values.yaml + test/e2e/seed-hostpath.yaml).
	for _, sc := range scenarios.AllHostPath() {
		sc := sc
		t.Run(path.Join("HostPath", sc.Path), func(t *testing.T) {
			if sc.ExpectReason != "" {
				assertHostPathReason(t, srcErrors, sc)
				return
			}
			assertHostPathCert(t, notAfter, expired, sc)
		})
	}

	// cabundle scenarios — cluster-scoped admission resources with
	// inline caBundle PEM fields. The seed binary applies them
	// (seedCABundles in dev/seed/main.go) and the chart's
	// cabundlesExporter source emits one series per webhook entry.
	for _, sc := range scenarios.AllCABundles() {
		sc := sc
		t.Run(fmt.Sprintf("CABundle/%s/%s", sc.Kind, sc.Name), func(t *testing.T) {
			if !sc.Watched {
				assertNoCABundleSeries(t, notAfter, sc)
				return
			}
			for _, w := range sc.Webhooks {
				assertCABundleEntry(t, notAfter, expired, sc, w)
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

	// memory_under_budget is a smoke check on the exporter's resident
	// memory after the initial sync has completed. The dev cluster only
	// holds a handful of TLS Secrets/ConfigMaps, so 80 MiB is generous —
	// well above the typical ~15 MiB but well below what a regression
	// to "cache every Secret" would push the pod to. The metric is
	// emitted by Prometheus's process collector; if it disappears (e.g.
	// build flag change) we just skip rather than fail.
	t.Run("memory_under_budget", func(t *testing.T) {
		fam := fams["process_resident_memory_bytes"]
		if fam == nil || len(fam.GetMetric()) == 0 {
			t.Skip("process_resident_memory_bytes not exposed")
		}
		const budget = 80 * 1024 * 1024 // 80 MiB
		var maxRSS float64
		for _, m := range fam.GetMetric() {
			if v := m.GetGauge().GetValue(); v > maxRSS {
				maxRSS = v
			}
		}
		if maxRSS > budget {
			t.Fatalf("exporter RSS %.0f bytes (%.0f MiB) exceeds budget of %d MiB",
				maxRSS, maxRSS/1024/1024, budget>>20)
		}
		t.Logf("max exporter RSS across scraped pods: %.1f MiB (budget %d MiB)",
			maxRSS/1024/1024, budget>>20)
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
	// Exposed object labels: each entry in ExposedLabels maps a bare
	// label name (as configured under exposeSecretLabels /
	// exposeConfigMapLabels) to the value the e2e expects to read on
	// the resulting Prometheus series. The label name on the metric is
	// `secret_label_<bare>` for Kind=="Secret",
	// `configmap_label_<bare>` for Kind=="ConfigMap".
	if len(e.ExposedLabels) > 0 {
		var prefix string
		switch sc.Kind {
		case "Secret":
			prefix = "secret_label_"
		case "ConfigMap":
			prefix = "configmap_label_"
		default:
			t.Fatalf("ExposedLabels asserted on unsupported Kind %q", sc.Kind)
		}
		for k, v := range e.ExposedLabels {
			labelName := prefix + k
			got := labelValue(naMetric, labelName)
			if got != v {
				t.Fatalf("%s/%s key=%s: %s = %q, want %q",
					sc.Namespace, sc.Name, e.Key, labelName, got, v)
			}
		}
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

func assertHostPathCert(t *testing.T, notAfter, expired *dto.MetricFamily, sc scenarios.HostPathScenario) {
	t.Helper()
	want := map[string]string{
		"filepath":   sc.FilepathLabel,
		"subject_CN": sc.SubjectCN,
	}
	if find(notAfter, want) == nil {
		t.Fatalf("no x509_cert_not_after series with %v", want)
	}
	if exMetric := find(expired, want); exMetric == nil {
		t.Fatalf("no x509_cert_expired series with %v", want)
	} else if got := exMetric.GetGauge().GetValue(); got != 0 {
		t.Fatalf("hostPath %s: expected expired=0, got %v", sc.Path, got)
	}
}

func assertCABundleEntry(t *testing.T, notAfter, expired *dto.MetricFamily, sc scenarios.CABundleScenario, w scenarios.CABundleWebhook) {
	t.Helper()
	want := map[string]string{
		"cabundle_resource_kind": string(sc.Kind),
		"cabundle_resource_name": sc.Name,
		"cabundle_entry":         w.Name,
		"subject_CN":             w.CN,
	}
	notAfterMetric := find(notAfter, want)
	if notAfterMetric == nil {
		t.Fatalf("no x509_cert_not_after series with %v", want)
	}
	// The seed fabricates 180-day certs (see scenarios.CABundleNotAfter)
	// so the series must report `expired=0`. Catches a regression
	// where the chart somehow misroutes the cabundle source through
	// a parser that fails to read NotAfter.
	if exp := find(expired, want); exp == nil {
		t.Fatalf("no x509_cert_expired series with %v", want)
	} else if got := exp.GetGauge().GetValue(); got != 0 {
		t.Fatalf("cabundle %s/%s entry %q: expected expired=0, got %v", sc.Kind, sc.Name, w.Name, got)
	}
	// The chart's test/e2e/values.yaml sets `exposeLabels:
	// [app.kubernetes.io/managed-by]` and each scenario carries that
	// resource-level label set to "x509ce-e2e". The matching
	// Prometheus label must surface on the series.
	const labelName = "cabundle_label_app_kubernetes_io_managed_by"
	if !labelEq(notAfterMetric, labelName, "x509ce-e2e") {
		t.Fatalf("cabundle %s/%s entry %q: expected %s=x509ce-e2e, labels=%+v",
			sc.Kind, sc.Name, w.Name, labelName, notAfterMetric.GetLabel())
	}
}

func assertNoCABundleSeries(t *testing.T, notAfter *dto.MetricFamily, sc scenarios.CABundleScenario) {
	t.Helper()
	for _, m := range notAfter.GetMetric() {
		if labelEq(m, "cabundle_resource_kind", string(sc.Kind)) && labelEq(m, "cabundle_resource_name", sc.Name) {
			t.Fatalf("unexpected x509_cert_not_after series for excluded cabundle %s/%s: %+v", sc.Kind, sc.Name, m.GetLabel())
		}
	}
}

func assertCRLSeries(t *testing.T, crlNextUpdate, crlStale, crlNumber *dto.MetricFamily, sc scenarios.Scenario, e scenarios.ExpectCRL) {
	t.Helper()
	if crlNextUpdate == nil {
		t.Fatalf("x509_crl_next_update missing — exporter built without CRL support?")
	}
	nsLabel, nameLabel, keyLabel := sourceLabels(sc.Kind)
	want := map[string]string{
		nsLabel:     sc.Namespace,
		nameLabel:   sc.Name,
		keyLabel:    e.Key,
		"issuer_CN": e.IssuerCN,
	}
	nu := find(crlNextUpdate, want)
	if nu == nil {
		t.Fatalf("no x509_crl_next_update series with %v", want)
	}
	// We don't compare the raw Unix value to ExpectCRL.NextUpdate
	// because the seed and the e2e test are separate processes that
	// both call scenarios.All() at slightly different `time.Now()`
	// instants. Each run re-generates its own CRL with a fresh
	// NextUpdate, so the exporter exposes the seed's value and the
	// test's expectation drifts seconds (sometimes minutes) ahead.
	// What actually matters here — that the series is present, that
	// it correctly maps to (issuer, number), and that stale reflects
	// the right side of now — is asserted below.
	if crlStale != nil {
		stale := find(crlStale, want)
		if stale == nil {
			t.Fatalf("no x509_crl_stale series with %v", want)
		}
		got := stale.GetGauge().GetValue()
		exp := 0.0
		if e.Stale {
			exp = 1
		}
		if got != exp {
			t.Fatalf("x509_crl_stale for %s/%s key=%s: got %v, want %v",
				sc.Namespace, sc.Name, e.Key, got, exp)
		}
	}
	if crlNumber != nil {
		num := find(crlNumber, want)
		if num == nil {
			t.Fatalf("no x509_crl_number series with %v", want)
		}
		if got := int64(num.GetGauge().GetValue()); got != e.Number {
			t.Fatalf("x509_crl_number for %s/%s key=%s: got %d, want %d",
				sc.Namespace, sc.Name, e.Key, got, e.Number)
		}
	}
}

func assertHostPathReason(t *testing.T, srcErrors *dto.MetricFamily, sc scenarios.HostPathScenario) {
	t.Helper()
	if srcErrors == nil {
		t.Fatalf("x509_source_errors_total missing; cannot assert reason=%q", sc.ExpectReason)
	}
	for _, m := range srcErrors.GetMetric() {
		if labelEq(m, "reason", string(sc.ExpectReason)) && m.GetCounter().GetValue() > 0 {
			return
		}
	}
	t.Fatalf("expected x509_source_errors_total{reason=%q} > 0 for %s", sc.ExpectReason, sc.Path)
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

// labelValue returns the Prometheus label value attached to m for the
// given label name, or "" if the label is absent (Prometheus models
// missing labels as empty strings, so the absent / present-as-empty
// distinction doesn't matter for assertion purposes here).
func labelValue(m *dto.Metric, name string) string {
	for _, l := range m.GetLabel() {
		if l.GetName() == name {
			return l.GetValue()
		}
	}
	return ""
}

// Sanity: surface a printable line per failure to ease debugging.
func init() {
	if v := os.Getenv("E2E_VERBOSE"); v != "" {
		fmt.Fprintln(os.Stderr, "[e2e] metrics URLs:", metricsURLs())
	}
}
