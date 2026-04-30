package server

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

func nopLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestEndpoints(t *testing.T) {
	r := &Readiness{}
	reg := prometheus.NewRegistry()
	srv := Build(Options{Listen: ":0", Registry: reg, Readiness: r, Logger: nopLogger()})
	ts := httptest.NewServer(srv.Handler)
	defer ts.Close()

	resp, _ := http.Get(ts.URL + "/healthz")
	if resp.StatusCode != 200 {
		t.Fatalf("healthz: %d", resp.StatusCode)
	}
	resp, _ = http.Get(ts.URL + "/readyz")
	if resp.StatusCode != 503 {
		t.Fatalf("readyz before mark: %d", resp.StatusCode)
	}
	r.Mark()
	resp, _ = http.Get(ts.URL + "/readyz")
	if resp.StatusCode != 200 {
		t.Fatalf("readyz after mark: %d", resp.StatusCode)
	}
	resp, _ = http.Get(ts.URL + "/metrics")
	if resp.StatusCode != 200 {
		t.Fatalf("metrics: %d", resp.StatusCode)
	}
	resp, _ = http.Get(ts.URL + "/")
	if resp.StatusCode != 200 {
		t.Fatalf("root: %d", resp.StatusCode)
	}
	resp, _ = http.Get(ts.URL + "/nope")
	if resp.StatusCode != 404 {
		t.Fatalf("not-found: %d", resp.StatusCode)
	}
}

func TestReadinessOps(t *testing.T) {
	r := &Readiness{}
	if r.IsReady() {
		t.Fail()
	}
	r.Mark()
	if !r.IsReady() {
		t.Fail()
	}
	r.Reset()
	if r.IsReady() {
		t.Fail()
	}
}

func TestAggregate(t *testing.T) {
	r := &Readiness{}
	a := NewAggregate(r, 2)
	cb := a.Reach()
	cb(true)
	if r.IsReady() {
		t.Fatal("not ready until all reached")
	}
	cb(false)
	if !r.IsReady() {
		t.Fatal("should be ready")
	}
	// Zero-source aggregate marks immediately.
	r2 := &Readiness{}
	NewAggregate(r2, 0)
	if !r2.IsReady() {
		t.Fail()
	}
}

func TestRunGracefulShutdown(t *testing.T) {
	srv := Build(Options{Listen: "127.0.0.1:0", Registry: prometheus.NewRegistry(), Readiness: &Readiness{}, Logger: nopLogger()})
	// Use httptest.NewServer for accurate shutdown semantics.
	ts := httptest.NewUnstartedServer(srv.Handler)
	ts.Start()
	defer ts.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	go cancel()
	_ = Run(ctx, &http.Server{Addr: "127.0.0.1:0", Handler: srv.Handler}, nopLogger())
}
