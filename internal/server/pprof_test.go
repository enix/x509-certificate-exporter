package server

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestBuildPprofRoutes(t *testing.T) {
	srv := BuildPprof(PprofOptions{Listen: ":0"})
	ts := httptest.NewServer(srv.Handler)
	defer ts.Close()
	for _, path := range []string{
		"/debug/pprof/",
		"/debug/pprof/cmdline",
		"/debug/pprof/symbol",
	} {
		resp, err := http.Get(ts.URL + path)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if resp.StatusCode != 200 {
			t.Fatalf("%s: status %d", path, resp.StatusCode)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
}

// Note: importing net/http/pprof unconditionally registers handlers on
// http.DefaultServeMux via its init(). We do not, however, serve
// DefaultServeMux from our metrics server (server.Build mounts its own
// ServeMux), so the pprof endpoints stay isolated to the dedicated pprof
// listener even though DefaultServeMux is polluted.

func TestRunPprofGracefulShutdown(t *testing.T) {
	// Bind a real ephemeral port so ListenAndServe succeeds.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot bind: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	srv := BuildPprof(PprofOptions{Listen: addr})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		RunPprof(ctx, srv, nil)
		close(done)
	}()
	// Cancel right away — we only care about lifecycle, not traffic.
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("RunPprof did not return after cancel")
	}
}

func TestRunPprofServerError(t *testing.T) {
	// Bind on a port we won't release so the second listen fails.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot bind: %v", err)
	}
	defer func() { _ = ln.Close() }()
	srv := BuildPprof(PprofOptions{Listen: ln.Addr().String()})
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	done := make(chan struct{})
	go func() {
		RunPprof(ctx, srv, nil)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("RunPprof did not return after error/timeout")
	}
}
