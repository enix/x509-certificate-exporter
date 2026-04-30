package log

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
)

func TestNewText(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, slog.LevelInfo, FormatText)
	l.Info("hello", "k", "v")
	if !strings.Contains(buf.String(), "hello") || !strings.Contains(buf.String(), "k=v") {
		t.Fatalf("text handler bad output: %q", buf.String())
	}
}

func TestNewJSON(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, slog.LevelInfo, FormatJSON)
	l.Info("hello", "k", "v")
	if !strings.Contains(buf.String(), `"msg":"hello"`) {
		t.Fatalf("json handler bad output: %q", buf.String())
	}
}

func TestNewNilWriterUsesStderr(t *testing.T) {
	if New(nil, slog.LevelInfo, FormatText) == nil {
		t.Fail()
	}
}

func TestParseLevel(t *testing.T) {
	for _, c := range []struct {
		in   string
		want slog.Level
	}{
		{"debug", slog.LevelDebug},
		{"info", slog.LevelInfo},
		{"warn", slog.LevelWarn},
		{"error", slog.LevelError},
		{"DEBUG", slog.LevelDebug},
	} {
		got, err := ParseLevel(c.in)
		if err != nil || got != c.want {
			t.Errorf("ParseLevel(%q) = %v,%v; want %v,nil", c.in, got, err, c.want)
		}
	}
	if _, err := ParseLevel("nope"); err == nil {
		t.Fatal("expected error")
	}
}

func TestParseFormat(t *testing.T) {
	if ParseFormat("json") != FormatJSON || ParseFormat("JSON") != FormatJSON {
		t.Fail()
	}
	if ParseFormat("text") != FormatText || ParseFormat("anything") != FormatText {
		t.Fail()
	}
}

func TestTimedEmitsDuration(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, slog.LevelDebug, FormatText)
	err := Timed(context.Background(), l, "doing work", func(ctx context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "duration_ms=") {
		t.Fatalf("missing duration_ms: %q", buf.String())
	}
}

func TestTimedEmitsError(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, slog.LevelDebug, FormatText)
	want := errors.New("boom")
	got := Timed(context.Background(), l, "x", func(ctx context.Context) error { return want })
	if got != want {
		t.Fatalf("err propagation broken")
	}
	if !strings.Contains(buf.String(), "boom") {
		t.Fatalf("missing error: %q", buf.String())
	}
}

func TestTimedNilLoggerSkips(t *testing.T) {
	called := false
	err := Timed(context.Background(), nil, "x", func(ctx context.Context) error { called = true; return nil })
	if err != nil || !called {
		t.Fail()
	}
}

func TestTimedSkipsWhenNotEnabled(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, slog.LevelInfo, FormatText)
	called := false
	_ = Timed(context.Background(), l, "x", func(ctx context.Context) error { called = true; return nil })
	if !called {
		t.Fail()
	}
	if strings.Contains(buf.String(), "duration_ms") {
		t.Fail()
	}
}
