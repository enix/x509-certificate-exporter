package k8s

import (
	"context"
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/enix/x509-certificate-exporter/v4/pkg/cert"
	"github.com/enix/x509-certificate-exporter/v4/pkg/registry"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/metrics"
)

var once sync.Once

// RegisterMetrics wires up client-go's global metrics providers to our
// Registry. The logger is used by the request-result hook to surface
// degraded apiserver responses (429 throttling, 5xx, 401/403) at WARN
// level — without this, client-go's internal retry loop absorbs these
// errors and the user only sees them via x509_source_errors_total
// metrics, never in the logs.
func RegisterMetrics(reg *registry.Registry, logger *slog.Logger) {
	once.Do(func() {
		if logger == nil {
			logger = slog.Default()
		}
		metrics.Register(metrics.RegisterOpts{
			RequestLatency: &requestLatency{reg: reg},
			RequestResult: &requestResult{
				reg: reg,
				log: logger.With("source_kind", "kubernetes"),
			},
		})

		// 2. Informer queues
		cache.SetInformerMetricsProvider(&informerMetrics{reg: reg})
		cache.SetReflectorMetricsProvider(&reflectorMetrics{reg: reg})
	})
}

// -- API Latency & Results

type requestLatency struct {
	reg *registry.Registry
}

func (l *requestLatency) Observe(ctx context.Context, verb string, u url.URL, latency time.Duration) {
	resource := extractResource(u.Path)
	l.reg.ObserveKubeRequest(verb, resource, latency)
}

type requestResult struct {
	reg *registry.Registry
	log *slog.Logger
}

// Increment is called by client-go on every HTTP response from the
// kube-apiserver. We forward problematic codes both to the
// x509_source_errors_total counter and to the logger at WARN — the
// counter on its own is easy to miss when troubleshooting a "the
// exporter is acting weird" report from a user without --debug.
//
// The hook fires per-response, so a sustained outage produces a steady
// stream of identical WARN lines. That's intentional: it makes the
// problem visible. Rate-limiting could be added if the noise becomes
// an issue, but in practice problematic codes are rare on a healthy
// cluster.
func (r *requestResult) Increment(ctx context.Context, code string, method string, host string) {
	switch {
	case code == "429":
		r.reg.MarkSourceError("kubernetes", "kube-api", cert.ReasonRateLimited)
		r.log.Warn("kube-apiserver throttled the request",
			"code", code, "method", method, "host", host)
	case code == "401" || code == "403":
		r.reg.MarkSourceError("kubernetes", "kube-api", cert.ReasonHTTPPrefix+code)
		r.log.Warn("kube-apiserver rejected the request (auth/RBAC)",
			"code", code, "method", method, "host", host)
	case strings.HasPrefix(code, "5"):
		r.reg.MarkSourceError("kubernetes", "kube-api", cert.ReasonHTTPPrefix+code)
		r.log.Warn("kube-apiserver returned a server error",
			"code", code, "method", method, "host", host)
	}
}

func extractResource(path string) string {
	parts := strings.Split(path, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return "unknown"
}

// -- Informer / Cache Metrics

type informerMetrics struct {
	reg *registry.Registry
}

func (m *informerMetrics) NewQueuedItemMetric(id cache.InformerNameAndResource) cache.GaugeMetric {
	return &queueDepth{reg: m.reg, sourceName: "kubernetes", resource: id.GroupVersionResource().Resource}
}

func (m *informerMetrics) NewProcessingLatencyMetric(id cache.InformerNameAndResource) cache.HistogramMetric {
	return noopHistogram{}
}

func (m *informerMetrics) NewStoreResourceVersionMetric(id cache.InformerNameAndResource) cache.GaugeMetric {
	return noopGauge{}
}

type queueDepth struct {
	reg        *registry.Registry
	sourceName string
	resource   string
}

func (q *queueDepth) Set(val float64) {
	q.reg.SetInformerQueueDepth(q.sourceName, q.resource, int(val))
}

// -- Reflector Metrics

type reflectorMetrics struct {
	reg *registry.Registry
}

func (m *reflectorMetrics) NewListsMetric(name string) cache.CounterMetric { return noopCounter{} }
func (m *reflectorMetrics) NewListDurationMetric(name string) cache.SummaryMetric {
	return noopSummary{}
}
func (m *reflectorMetrics) NewItemsInListMetric(name string) cache.SummaryMetric {
	return noopSummary{}
}
func (m *reflectorMetrics) NewWatchesMetric(name string) cache.CounterMetric { return noopCounter{} }
func (m *reflectorMetrics) NewShortWatchesMetric(name string) cache.CounterMetric {
	return &shortWatches{reg: m.reg, sourceName: "kubernetes", resource: name}
}
func (m *reflectorMetrics) NewWatchDurationMetric(name string) cache.SummaryMetric {
	return noopSummary{}
}
func (m *reflectorMetrics) NewItemsInWatchMetric(name string) cache.SummaryMetric {
	return noopSummary{}
}
func (m *reflectorMetrics) NewLastResourceVersionMetric(name string) cache.GaugeMetric {
	return noopGauge{}
}

type shortWatches struct {
	reg        *registry.Registry
	sourceName string
	resource   string
}

func (s *shortWatches) Inc() {
	s.reg.MarkWatchResync(s.sourceName, s.resource)
}

// -- Noops

type noopGauge struct{}

func (noopGauge) Set(float64) {}

type noopHistogram struct{}

func (noopHistogram) Observe(float64) {}

type noopCounter struct{}

func (noopCounter) Inc() {}

type noopSummary struct{}

func (noopSummary) Observe(float64) {}
