// Package registry holds the in-memory state of all discovered bundles and
// emits Prometheus metrics describing them. It is the single point where
// label sets, metric names, and collision handling are defined.
//
// Concurrency model: an internal RWMutex protects the bundle store. Sources
// call Upsert/Delete (writers); the Prometheus Collect path takes a RLock
// briefly to obtain a list of bundles, then iterates without holding the
// lock. This is sufficient given our scale and avoids the complexity of
// a swap-an-immutable-snapshot pattern.
package registry

import (
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/enix/x509-certificate-exporter/v4/internal/product"
	"github.com/enix/x509-certificate-exporter/v4/pkg/cert"
)

// CollisionPolicy is the strategy for the discriminator label.
type CollisionPolicy int

const (
	CollisionAuto   CollisionPolicy = iota // discriminator only on collisions
	CollisionAlways                        // discriminator always present
	CollisionNever                         // dedup colliding items, no discriminator
)

// Config drives the registry's metric shape and behaviour.
type Config struct {
	ExposeRelative         bool
	ExposePerCertError     bool
	ExposeNotBefore        bool
	// ExposeExpired gates `x509_cert_expired`. Defaults to true at the
	// config-loading layer; passing the zero value here disables the
	// metric entirely.
	ExposeExpired          bool
	// ExposeSAN gates `x509_cert_san`, which emits one series per
	// Subject Alternative Name (DNS or IP) on each certificate.
	// Off by default to keep `/metrics` lean.
	ExposeSAN              bool
	// ExposeDiagnostics enables the exporter's self-introspection
	// metrics (parse / kube API latencies, source scope, namespace
	// informer queue depth). Off by default.
	ExposeDiagnostics      bool
	// Pkcs12InUse, when true, registers the
	// `x509_pkcs12_passphrase_failures_total` counter. The flag is
	// computed by the caller from the source list, so the metric only
	// shows up in `/metrics` when at least one source actually parses
	// PKCS#12 material.
	Pkcs12InUse            bool
	// JksInUse mirrors Pkcs12InUse for the JKS / JCEKS parser. When
	// true, the registry exposes `x509_jks_passphrase_failures_total`.
	JksInUse               bool
	SubjectFields          []string
	IssuerFields           []string
	TrimPathComponents     int
	Collision              CollisionPolicy
	DiscriminatorLength    int
	ExposedSecretLabels    []string
	ExposedConfigMapLabels []string
	ExposedCABundleLabels  []string
	EnableStats            bool
}

// Registry implements cert.Sink and prometheus.Collector.
type Registry struct {
	cfg    Config
	logger *slog.Logger

	mu      sync.RWMutex
	bundles map[string]cert.Bundle // key: ref.String()

	knownSources struct {
		mu  sync.Mutex
		set map[[2]string]struct{}
	}

	lastScrapeDurationNs atomic.Int64

	// Internal stats for the UI
	statsMu    sync.Mutex
	uiErrors   map[string]int64
	uiQueues   map[string]int
	uiResyncs  map[string]int64
	uiPanics   int64
	uiKubeReqs int64

	// Per-source self-metrics.
	sourceUp                 *prometheus.GaugeVec
	sourceErrors             *prometheus.CounterVec
	sourceBundles            *prometheus.GaugeVec
	collisionTotal           *prometheus.CounterVec
	collisionDropped         *prometheus.CounterVec
	scrapeDuration           prometheus.Histogram
	parseDuration            *prometheus.HistogramVec
	panicTotal               *prometheus.CounterVec
	informerScope            *prometheus.GaugeVec
	informerQueueDepth       *prometheus.GaugeVec
	watchResyncs             *prometheus.CounterVec
	transportErrors          *prometheus.CounterVec
	pkcs12PassphraseFailures *prometheus.CounterVec
	jksPassphraseFailures    *prometheus.CounterVec
	kubeRequestDuration      *prometheus.HistogramVec
	buildInfo                prometheus.Gauge

	// Static reusable Descs for cert metrics, keyed by source kind +
	// "with disc" / "without disc".
	descs descTable
}

// New constructs a Registry. Pass a non-nil logger.
func New(cfg Config, logger *slog.Logger) *Registry {
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.DiscriminatorLength <= 0 {
		cfg.DiscriminatorLength = 8
	}
	r := &Registry{
		cfg:       cfg,
		logger:    logger,
		bundles:   map[string]cert.Bundle{},
		uiErrors:  map[string]int64{},
		uiQueues:  map[string]int{},
		uiResyncs: map[string]int64{},
	}
	r.knownSources.set = map[[2]string]struct{}{}
	r.initSelfMetrics()
	r.descs = newDescTable(cfg)
	return r
}

func (r *Registry) initSelfMetrics() {
	r.sourceUp = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "x509_source_up", Help: "1 if the source has produced its first sync, 0 otherwise.",
	}, []string{"source_kind", "source_name"})
	r.sourceErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "x509_source_errors_total", Help: "Errors emitted by sources, by reason code.",
	}, []string{"source_kind", "source_name", "reason"})
	r.sourceBundles = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "x509_source_bundles", Help: "Number of bundles currently tracked per source.",
	}, []string{"source_kind", "source_name"})
	r.collisionTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "x509_cert_collision_total", Help: "Number of label-collision events detected by the registry, regardless of resolution policy. Increments on every scrape while a collision persists — useful as a diagnostic that the config has overlapping rules, but not a data-loss signal on its own. For that, see x509_cert_collision_dropped_total.",
	}, []string{"source_kind"})
	r.collisionDropped = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "x509_cert_collision_dropped_total", Help: "Number of certificate label-collision events that resulted in actual data loss — i.e. one or more colliding items were dropped because the registry is configured with Collision=Never. Stays at 0 under the default CollisionAuto policy (discriminator added) and under CollisionAlways. Alert on this for real silently-invisible certificates.",
	}, []string{"source_kind"})
	r.scrapeDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "x509_scrape_duration_seconds",
		Help:    "Total time spent serving a /metrics scrape.",
		Buckets: []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 5, 10, 30},
	})
	r.panicTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "x509_panic_total", Help: "Goroutine panics caught by recover, by component.",
	}, []string{"component"})
	r.watchResyncs = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "x509_kube_watch_resyncs_total", Help: "Number of forced resyncs (WatchExpired / 410 Gone).",
	}, []string{"source_name", "resource"})
	r.transportErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "x509_kube_transport_errors_total", Help: "Transport-level failures in the kubernetes source's LIST/WATCH loop, by resource and reason. Distinct from x509_source_errors_total (which counts bundle-level parse failures): this counter captures operational issues below the bundle layer — LIST returning an error, WATCH failing to start, the WATCH stream surfacing an Error event, watches flapping (closing within a few seconds of opening), and the namespace informer failing to converge. None of these would otherwise be visible as metrics, only in logs.",
	}, []string{"source_name", "resource", "reason"})
	if r.cfg.ExposeDiagnostics {
		r.parseDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "x509_parse_duration_seconds",
			Help:    "Time spent parsing one bundle, by format.",
			Buckets: []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 5},
		}, []string{"format"})
		r.informerScope = prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "x509_kube_informer_scope", Help: "Scope of a Kubernetes source: 1 for the active scope, 0 otherwise. Metric name kept for dashboard compatibility.",
		}, []string{"source_name", "scope"})
		r.informerQueueDepth = prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "x509_informer_queue_depth", Help: "Current depth of an informer event queue. Populated only by the namespace informer (Secret and ConfigMap watches do not use SharedInformer).",
		}, []string{"source_name", "resource"})
		r.kubeRequestDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "x509_kube_request_duration_seconds",
			Help:    "Latency of Kubernetes API requests issued by the exporter.",
			Buckets: []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 5, 10, 30},
		}, []string{"verb", "resource"})
	}
	if r.cfg.Pkcs12InUse {
		r.pkcs12PassphraseFailures = prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "x509_pkcs12_passphrase_failures_total", Help: "PKCS#12 decoding attempts failed because of a wrong passphrase.",
		}, []string{"source_name"})
	}
	if r.cfg.JksInUse {
		r.jksPassphraseFailures = prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "x509_jks_passphrase_failures_total", Help: "JKS / JCEKS decoding attempts failed because of a wrong passphrase.",
		}, []string{"source_name"})
	}
	variadicBuildInfo := product.VariadicBuildInfo()
	buildLabels := make(prometheus.Labels, len(variadicBuildInfo)/2)
	for i := 0; i < len(variadicBuildInfo); i += 2 {
		buildLabels[variadicBuildInfo[i].(string)] = variadicBuildInfo[i+1].(string)
	}
	r.buildInfo = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "x509_exporter_build_info", Help: "Constant 1, with build labels.",
		ConstLabels: buildLabels,
	})
	r.buildInfo.Set(1)
}

// CacheStats represents statistics about the registry cache.
type CacheStats struct {
	TotalBundles       int
	TotalItems         int
	ByKind             map[string]int
	ByFormat           map[string]int
	LastScrapeDuration time.Duration

	Errors       map[string]int64
	QueueDepths  map[string]int
	WatchResyncs map[string]int64
	Panics       int64
	KubeRequests int64
}

// TrackScrapeDuration saves the duration of the last metrics scrape.
func (r *Registry) TrackScrapeDuration(d time.Duration) {
	if r.cfg.EnableStats {
		r.lastScrapeDurationNs.Store(int64(d))
	}
}

// Stats returns a snapshot of the registry's cache statistics.
func (r *Registry) Stats() CacheStats {
	r.mu.RLock()
	defer r.mu.RUnlock()

	stats := CacheStats{
		TotalBundles:       len(r.bundles),
		ByKind:             make(map[string]int),
		ByFormat:           make(map[string]int),
		LastScrapeDuration: time.Duration(r.lastScrapeDurationNs.Load()),
		Errors:             make(map[string]int64),
		QueueDepths:        make(map[string]int),
		WatchResyncs:       make(map[string]int64),
	}

	for _, b := range r.bundles {
		stats.ByKind[b.Source.Kind]++
		if b.Source.Format != "" {
			stats.ByFormat[b.Source.Format]++
		}
		stats.TotalItems += len(b.Items)
	}

	r.statsMu.Lock()
	for k, v := range r.uiErrors {
		stats.Errors[k] = v
	}
	for k, v := range r.uiQueues {
		stats.QueueDepths[k] = v
	}
	for k, v := range r.uiResyncs {
		stats.WatchResyncs[k] = v
	}
	stats.Panics = r.uiPanics
	stats.KubeRequests = r.uiKubeReqs
	r.statsMu.Unlock()

	return stats
}

// --- cert.Sink implementation ---------------------------------------------

// Upsert stores or replaces a Bundle.
func (r *Registry) Upsert(b cert.Bundle) {
	key := b.Source.String()
	r.mu.Lock()
	r.bundles[key] = b
	r.mu.Unlock()
	r.recordBundleErrors(b)
	r.refreshSourceCounts()
}

// Delete removes the Bundle keyed by ref. No-op if absent.
func (r *Registry) Delete(ref cert.SourceRef) {
	key := ref.String()
	r.mu.Lock()
	delete(r.bundles, key)
	r.mu.Unlock()
	r.refreshSourceCounts()
}

// recordBundleErrors increments error counters from a bundle. Routes
// through MarkSourceError so the UI cache (`/` stats endpoint) sees
// bundle-level errors alongside out-of-bundle ones — historically
// these went straight to the prometheus vec, which left the stats
// page blind to parse/passphrase/etc. failures.
func (r *Registry) recordBundleErrors(b cert.Bundle) {
	for _, e := range b.Errors {
		r.MarkSourceError(b.Source.Kind, b.Source.SourceName, e.Reason)
		args := []any{
			"source_kind", b.Source.Kind,
			"source_name", b.Source.SourceName,
			"location", b.Source.Location,
			"key", b.Source.Key,
			"format", b.Source.Format,
			"reason", e.Reason,
		}
		if e.Err != nil {
			args = append(args, "err", e.Err)
		}
		r.logger.Debug("bundle parse error", args...)
		if e.Reason == cert.ReasonBadPassphrase {
			// Route to the per-format counter when one is registered.
			// Format is set on the SourceRef by every parser-aware
			// emit path (file source, k8s source's secretTypes,
			// configMaps rule), so dispatching here keeps the two
			// counters faithful to which decoder actually failed.
			switch b.Source.Format {
			case cert.FormatPKCS12:
				if r.pkcs12PassphraseFailures != nil {
					r.pkcs12PassphraseFailures.WithLabelValues(b.Source.SourceName).Inc()
				}
			case cert.FormatJKS:
				if r.jksPassphraseFailures != nil {
					r.jksPassphraseFailures.WithLabelValues(b.Source.SourceName).Inc()
				}
			}
		}
	}
}

// refreshSourceCounts refreshes the per-source bundle gauge. Keys that
// are no longer present have their gauge set to 0 (or removed) so that
// stale series do not linger.
func (r *Registry) refreshSourceCounts() {
	r.mu.RLock()
	counts := map[[2]string]int{}
	for _, b := range r.bundles {
		k := [2]string{b.Source.Kind, b.Source.SourceName}
		counts[k]++
	}
	r.mu.RUnlock()
	r.knownSources.mu.Lock()
	defer r.knownSources.mu.Unlock()
	for k := range counts {
		r.knownSources.set[k] = struct{}{}
	}
	for k := range r.knownSources.set {
		v, ok := counts[k]
		if !ok {
			r.sourceBundles.WithLabelValues(k[0], k[1]).Set(0)
			continue
		}
		r.sourceBundles.WithLabelValues(k[0], k[1]).Set(float64(v))
	}
}

// --- helpers exposed to sources -------------------------------------------

// MarkSourceUp sets x509_source_up to up (true => 1).
func (r *Registry) MarkSourceUp(kind, name string, up bool) {
	v := 0.0
	if up {
		v = 1
	}
	r.sourceUp.WithLabelValues(kind, name).Set(v)
}

// MarkSourceError increments x509_source_errors_total for an out-of-bundle
// error (e.g., a walk error not tied to a specific bundle).
// MarkSourceError increments the error counter.
func (r *Registry) MarkSourceError(kind, name, reason string) {
	if r.cfg.EnableStats {
		r.statsMu.Lock()
		r.uiErrors[name+":"+reason]++
		r.statsMu.Unlock()
	}
	r.sourceErrors.WithLabelValues(kind, name, reason).Inc()
}

// ObserveParse observes a parse duration. No-op when diagnostic
// metrics are gated off.
func (r *Registry) ObserveParse(format string, d time.Duration) {
	if r.parseDuration == nil {
		return
	}
	r.parseDuration.WithLabelValues(format).Observe(d.Seconds())
}

// ObserveKubeRequest observes a kubernetes request duration. The UI
// counter still updates so the cache-stats endpoint remains useful
// even when diagnostic histograms are gated off.
func (r *Registry) ObserveKubeRequest(verb, resource string, d time.Duration) {
	if r.cfg.EnableStats {
		r.statsMu.Lock()
		r.uiKubeReqs++
		r.statsMu.Unlock()
	}
	if r.kubeRequestDuration == nil {
		return
	}
	r.kubeRequestDuration.WithLabelValues(verb, resource).Observe(d.Seconds())
}

// MarkPanic increments the panic counter for a component.
func (r *Registry) MarkPanic(component string) {
	if r.cfg.EnableStats {
		r.statsMu.Lock()
		r.uiPanics++
		r.statsMu.Unlock()
	}
	r.panicTotal.WithLabelValues(component).Inc()
}

// MarkInformerScope sets the active scope for a kubernetes source.
// No-op when diagnostic metrics are gated off.
func (r *Registry) MarkInformerScope(sourceName, scope string) {
	if r.informerScope == nil {
		return
	}
	for _, s := range []string{"cluster", "namespace"} {
		v := 0.0
		if s == scope {
			v = 1
		}
		r.informerScope.WithLabelValues(sourceName, s).Set(v)
	}
}

// SetInformerQueueDepth updates the queue depth gauge. The UI cache
// still tracks depth so the cache-stats endpoint reflects backpressure
// even when the diagnostic gauge is gated off.
func (r *Registry) SetInformerQueueDepth(sourceName, resource string, depth int) {
	if r.cfg.EnableStats {
		r.statsMu.Lock()
		r.uiQueues[sourceName+":"+resource] = depth
		r.statsMu.Unlock()
	}
	if r.informerQueueDepth == nil {
		return
	}
	r.informerQueueDepth.WithLabelValues(sourceName, resource).Set(float64(depth))
}

// MarkWatchResync increments the resync counter.
func (r *Registry) MarkWatchResync(sourceName, resource string) {
	if r.cfg.EnableStats {
		r.statsMu.Lock()
		r.uiResyncs[sourceName+":"+resource]++
		r.statsMu.Unlock()
	}
	r.watchResyncs.WithLabelValues(sourceName, resource).Inc()
}

// MarkTransportError increments the kubernetes-source transport error
// counter for (sourceName, resource, reason). The reason should be one
// of the cert.Reason* transport constants — anything else is accepted
// but breaks alert expressions that match on those literals.
func (r *Registry) MarkTransportError(sourceName, resource, reason string) {
	r.transportErrors.WithLabelValues(sourceName, resource, reason).Inc()
}

// PreInitBundleSource materialises counter series at zero for a source
// that emits bundles under (kind, name). Without this, a CounterVec
// series only appears the first time an event fires — so an exporter
// that has been running cleanly shows no `x509_source_errors_total`
// series at all, which dashboards and `rate()`/`increase()` cannot
// distinguish from "metric not reporting". After pre-init the alert
// query already sees a baseline of 0 for every static reason; the
// first real event makes `increase()` jump immediately on the next
// scrape rather than waiting for two samples.
//
// Materialises:
//   - x509_source_errors_total{source_kind=kind, source_name=name,
//     reason=...} for every reason in cert.BundleReasons.
//   - x509_cert_collision_total{source_kind=kind} and
//     x509_cert_collision_dropped_total{source_kind=kind}.
//   - x509_{pkcs12,jks}_passphrase_failures_total{source_name=name}
//     when the corresponding format is in use cluster-wide
//     (Pkcs12InUse / JksInUse on Config). The conservative choice is
//     to pre-init for every source even though only sources that
//     actually parse those formats will ever bump them — series
//     cardinality is bounded by source count, which is small.
//
// Safe to call multiple times; WithLabelValues is idempotent.
func (r *Registry) PreInitBundleSource(kind, name string) {
	for _, reason := range cert.BundleReasons {
		r.sourceErrors.WithLabelValues(kind, name, reason)
	}
	r.collisionTotal.WithLabelValues(kind)
	r.collisionDropped.WithLabelValues(kind)
	if r.pkcs12PassphraseFailures != nil {
		r.pkcs12PassphraseFailures.WithLabelValues(name)
	}
	if r.jksPassphraseFailures != nil {
		r.jksPassphraseFailures.WithLabelValues(name)
	}
}

// PreInitKubeTransport materialises the Kubernetes-source transport
// counter series at zero for the given source name. Companion to
// PreInitBundleSource for k8s sources.
//
// Materialises:
//   - x509_kube_watch_resyncs_total{source_name=name, resource=...}
//   - x509_kube_transport_errors_total{source_name=name, resource=...,
//     reason=...} for every reason in cert.KubeTransportPerResourceReasons.
//   - When namespaceInformer is true, additionally materialises the
//     namespace-informer resync + transport-error series
//     (resource="namespaces", reason="namespace_sync_failed").
//
// Safe to call multiple times.
func (r *Registry) PreInitKubeTransport(name string, resources []string, namespaceInformer bool) {
	for _, resource := range resources {
		r.watchResyncs.WithLabelValues(name, resource)
		for _, reason := range cert.KubeTransportPerResourceReasons {
			r.transportErrors.WithLabelValues(name, resource, reason)
		}
	}
	if namespaceInformer {
		r.watchResyncs.WithLabelValues(name, "namespaces")
		r.transportErrors.WithLabelValues(name, "namespaces", cert.ReasonNamespaceSyncFail)
	}
}

// snapshot copies the bundles map under the read lock.
func (r *Registry) snapshot() []cert.Bundle {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]cert.Bundle, 0, len(r.bundles))
	for _, b := range r.bundles {
		out = append(out, b)
	}
	return out
}
