package server

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/pprof"
	"time"
)

// PprofOptions configure the optional debugging endpoint.
type PprofOptions struct {
	Listen       string
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
}

// BuildPprof constructs an isolated *http.Server exposing the standard
// net/http/pprof routes on its own dedicated ServeMux. Our metrics
// server (server.Build) uses a separate mux and never serves
// http.DefaultServeMux, so the pprof endpoints stay confined to this
// listener even though importing net/http/pprof unavoidably registers
// the same handlers on DefaultServeMux via its init().
func BuildPprof(opts PprofOptions) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	return &http.Server{
		Addr:         opts.Listen,
		Handler:      mux,
		ReadTimeout:  opts.ReadTimeout,
		WriteTimeout: opts.WriteTimeout,
	}
}

// RunPprof starts srv and blocks until ctx is cancelled. A graceful
// shutdown with a short timeout is attempted on exit. Logs at INFO when
// the server starts and stops; reports any non-nominal error.
func RunPprof(ctx context.Context, srv *http.Server, logger *slog.Logger) {
	if logger == nil {
		logger = slog.Default()
	}
	logger.Info("pprof listening", "addr", srv.Addr)
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
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		logger.Info("pprof stopped")
	case err := <-errCh:
		if err != nil {
			logger.Error("pprof server error", "error", err)
		}
	}
}
