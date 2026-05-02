// Package server wires up the HTTP endpoints exposed by the exporter.
//
// Endpoints:
//
//	GET /metrics    Prometheus, never 500
//	GET /healthz    200 if process is alive
//	GET /readyz     200 once every source has produced its first sync
//	GET /           landing page
package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/enix/x509-certificate-exporter/v4/pkg/registry"
)

// Readiness is a simple latch flipped to true when all sources have synced.
type Readiness struct {
	ready atomic.Bool
}

// Mark sets the ready flag to true.
func (r *Readiness) Mark() { r.ready.Store(true) }

// Reset returns the flag to false (for tests).
func (r *Readiness) Reset() { r.ready.Store(false) }

// IsReady returns the current state.
func (r *Readiness) IsReady() bool { return r.ready.Load() }

// Options drives the server.
type Options struct {
	Listen       string
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	Registry     prometheus.Gatherer
	Readiness    *Readiness
	Logger       *slog.Logger
	EnableStats  bool
	Stats        *registry.Registry
}

// Build constructs an *http.Server with the right Mux. Caller starts and
// stops it. The exporter-toolkit web config wiring is done in main.go.
func Build(opts Options) *http.Server {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(opts.Registry, promhttp.HandlerOpts{
		ErrorHandling: promhttp.ContinueOnError, // never 500 on partial errors
	}))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok\n")
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		if opts.Readiness != nil && !opts.Readiness.IsReady() {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(w, "syncing\n")
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ready\n")
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}

		statsHTML := ""
		if opts.EnableStats && opts.Stats != nil {
			s := opts.Stats.Stats()

			breakdownKind := renderInt64Map(s.ByKind)
			breakdownFormat := renderInt64Map(s.ByFormat)
			breakdownErrors := renderInt64Map(s.Errors)
			breakdownQueues := renderInt64Map(s.QueueDepths)
			breakdownResyncs := renderInt64Map(s.WatchResyncs)

			statsHTML = fmt.Sprintf(`<h2>Cache Statistics</h2>
<ul>
<li>Total Bundles: %d</li>
<li>Total Items (Certificates): %d</li>
<li>Last Scrape Duration: %s</li>
</ul>
<h3>By Source Kind</h3>
<ul>
%s</ul>
<h3>By Format</h3>
<ul>
%s</ul>
<h2>Operational Metrics</h2>
<ul>
<li>Kubernetes API Requests: %d <br><i><small>Note: May remain at 0 as modern Kubernetes clients use optimized WatchList streaming instead of standard API requests</small></i></li>
<li>Recovered Panics: %d</li>
</ul>
<h3>Errors</h3>
<ul>
%s</ul>
<h3>Informer Queue Depths</h3>
<ul>
%s</ul>
<h3>Informer Watch Resyncs</h3>
<ul>
%s</ul>
`, s.TotalBundles, s.TotalItems, s.LastScrapeDuration, breakdownKind, breakdownFormat, s.KubeRequests, s.Panics, breakdownErrors, breakdownQueues, breakdownResyncs)
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = fmt.Fprintf(w, `<!doctype html>
<html><head><title>x509-certificate-exporter</title></head>
<body><h1>x509-certificate-exporter</h1>
<ul>
<li><a href="/metrics">/metrics</a></li>
<li><a href="/healthz">/healthz</a></li>
<li><a href="/readyz">/readyz</a></li>
</ul>
%s</body></html>`, statsHTML)
	})
	return &http.Server{
		Addr:         opts.Listen,
		Handler:      mux,
		ReadTimeout:  opts.ReadTimeout,
		WriteTimeout: opts.WriteTimeout,
	}
}

// renderInt64Map emits one <li> per key in lexicographic key order, so the
// stats page is stable across refreshes (Go map iteration is randomized).
func renderInt64Map[V int | int64](m map[string]V) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&b, "<li>%s: %d</li>\n", k, m[k])
	}
	return b.String()
}

// Aggregate collects readiness signals from N sources. The Reach method
// returns a function that the source's OnReady callback can call. Once
// all sources have called success or failure, Mark is invoked.
type Aggregate struct {
	r       *Readiness
	pending atomic.Int32
}

// NewAggregate prepares an Aggregate for n sources.
func NewAggregate(r *Readiness, n int) *Aggregate {
	a := &Aggregate{r: r}
	a.pending.Store(int32(n))
	if n == 0 {
		r.Mark()
	}
	return a
}

// Reach returns the per-source callback.
func (a *Aggregate) Reach() func(success bool) {
	return func(success bool) {
		_ = success
		if a.pending.Add(-1) == 0 {
			a.r.Mark()
		}
	}
}

// Run starts srv on its listener and blocks until ctx is cancelled, after
// which it triggers a graceful shutdown.
func Run(ctx context.Context, srv *http.Server, logger *slog.Logger) error {
	errCh := make(chan error, 1)
	go func() {
		err := srv.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()
	select {
	case <-ctx.Done():
		// Fresh context: parent ctx is already canceled here.
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx) //nolint:contextcheck
		logger.Info("http server stopped")
		return ctx.Err()
	case err := <-errCh:
		return err
	}
}
