// Package log centralises slog initialisation and a few helpers used to
// instrument network-bound operations.
//
// Loggers are explicitly injected; the default logger is only set in
// main.go for the rare site where injection is not practical.
package log

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"
)

// Format selects the handler.
type Format int

const (
	FormatText Format = iota
	FormatJSON
)

// New constructs a new slog.Logger writing to out.
func New(out io.Writer, level slog.Level, format Format) *slog.Logger {
	if out == nil {
		out = os.Stderr
	}
	opts := &slog.HandlerOptions{Level: level}
	switch format {
	case FormatJSON:
		return slog.New(slog.NewJSONHandler(out, opts))
	default:
		return slog.New(slog.NewTextHandler(out, opts))
	}
}

// ParseLevel turns "debug"/"info"/"warn"/"error" into a slog.Level.
func ParseLevel(s string) (slog.Level, error) {
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(strings.ToLower(s))); err != nil {
		return slog.LevelInfo, err
	}
	return lvl, nil
}

// ParseFormat turns "text"/"json" into a Format.
func ParseFormat(s string) Format {
	if strings.EqualFold(s, "json") {
		return FormatJSON
	}
	return FormatText
}

// Timed runs fn and logs its duration at debug level. The returned error is
// fn's. If logger is nil this is just fn().
func Timed(ctx context.Context, logger *slog.Logger, msg string, fn func(context.Context) error, attrs ...slog.Attr) error {
	if logger == nil || !logger.Enabled(ctx, slog.LevelDebug) {
		return fn(ctx)
	}
	start := time.Now()
	err := fn(ctx)
	dur := time.Since(start)
	all := append([]slog.Attr{slog.Int64("duration_ms", dur.Milliseconds())}, attrs...)
	if err != nil {
		all = append(all, slog.String("error", err.Error()))
	}
	logger.LogAttrs(ctx, slog.LevelDebug, msg, all...)
	return err
}
