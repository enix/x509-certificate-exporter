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

	get := func(path string) int {
		resp, err := http.Get(ts.URL + path)
		if err != nil {
			t.Fatalf("get %s: %v", path, err)
		}
		defer func() { _ = resp.Body.Close() }()
		return resp.StatusCode
	}

	if got := get("/healthz"); got != 200 {
		t.Fatalf("healthz: %d", got)
	}
	if got := get("/readyz"); got != 503 {
		t.Fatalf("readyz before mark: %d", got)
	}
	r.Mark()
	if got := get("/readyz"); got != 200 {
		t.Fatalf("readyz after mark: %d", got)
	}
	if got := get("/metrics"); got != 200 {
		t.Fatalf("metrics: %d", got)
	}
	if got := get("/"); got != 200 {
		t.Fatalf("root: %d", got)
	}
	if got := get("/nope"); got != 404 {
		t.Fatalf("not-found: %d", got)
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
