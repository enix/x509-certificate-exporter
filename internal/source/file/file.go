// Package file implements a Source that scans local files using the
// custom fileglob engine and caches parse results between walks.
package file

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"math/rand/v2"
	"os"
	"sync"
	"time"

	"github.com/enix/x509-certificate-exporter/v4/internal/fileglob"
	"github.com/enix/x509-certificate-exporter/v4/pkg/cert"
)

// Reader fetches the bytes of one path. The default implementation reads
// from the real filesystem.
type Reader interface {
	Read(path string) ([]byte, error)
}

type osReader struct{}

func (osReader) Read(p string) ([]byte, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return io.ReadAll(f)
}

// Options configure a file Source.
type Options struct {
	Name              string
	Patterns          []fileglob.Pattern
	Excludes          []fileglob.Pattern
	Formats           []cert.FormatParser
	FollowSymlinks    bool
	FollowSymlinkDirs bool
	RefreshInterval   time.Duration
	Jitter            float64 // 0..1, fraction of RefreshInterval used as random jitter
	SkipUnchanged     bool
	MaxDepth          int
	Reader            Reader
	WalkFS            fileglob.WalkFS
	ParseOpts         cert.ParseOptions
	// PathMappings is forwarded to fileglob.Options for symlink target
	// translation and scope containment. See fileglob.PathMapping.
	PathMappings []fileglob.PathMapping
	// FirstSyncDone is closed after the first walk completes (success or
	// error). Used to drive /readyz.
	FirstSyncDone chan struct{}
	// OnReady is invoked once the first sync completes (boolean = success).
	OnReady func(success bool)
}

// Source implements cert.Source.
type Source struct {
	opts Options
	log  *slog.Logger

	mu    sync.Mutex
	cache map[string]cacheEntry // key: path
}

type cacheEntry struct {
	mtime  time.Time
	size   int64
	bundle cert.Bundle
}

// New creates a file source.
func New(opts Options, logger *slog.Logger) *Source {
	if opts.Reader == nil {
		opts.Reader = osReader{}
	}
	if opts.RefreshInterval <= 0 {
		opts.RefreshInterval = 30 * time.Second
	}
	if opts.Jitter < 0 || opts.Jitter > 1 {
		opts.Jitter = 0.25
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Source{
		opts:  opts,
		log:   logger.With("source_kind", cert.KindFile, "source_name", opts.Name),
		cache: map[string]cacheEntry{},
	}
}

// Name implements cert.Source.
func (s *Source) Name() string { return s.opts.Name }

// Run implements cert.Source. It performs an initial walk synchronously
// (so /readyz can become ready), then enters a refresh loop until ctx
// is cancelled.
func (s *Source) Run(ctx context.Context, sink cert.Sink) error {
	s.runOnce(ctx, sink, true)
	if s.opts.RefreshInterval == 0 {
		<-ctx.Done()
		return ctx.Err()
	}
	for {
		d := s.opts.RefreshInterval
		if s.opts.Jitter > 0 {
			j := float64(d) * s.opts.Jitter
			delta := (rand.Float64()*2 - 1) * j
			d += time.Duration(delta)
			if d <= 0 {
				d = s.opts.RefreshInterval
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(d):
		}
		s.runOnce(ctx, sink, false)
	}
}

// runOnce performs a single walk + parse, syncs the cache against the result,
// and emits Upsert/Delete to the sink.
func (s *Source) runOnce(ctx context.Context, sink cert.Sink, isFirst bool) {
	start := time.Now()
	wopts := fileglob.Options{
		Includes:          s.opts.Patterns,
		Excludes:          s.opts.Excludes,
		FollowSymlinks:    s.opts.FollowSymlinks,
		FollowSymlinkDirs: s.opts.FollowSymlinkDirs,
		MaxDepth:          s.opts.MaxDepth,
		FS:                s.opts.WalkFS,
		PathMappings:      s.opts.PathMappings,
	}
	results := fileglob.Walk(ctx, wopts)

	seen := map[string]struct{}{}
	walkOK := true
	for r := range results {
		if r.Err != nil {
			walkOK = false
			s.log.Warn("walk error",
				"path", r.Err.Path, "reason", r.Err.Reason, "error", r.Err.Err)
			// Emit a synthetic bundle so the registry can count error reasons.
			sink.Upsert(cert.Bundle{
				Source: cert.SourceRef{
					Kind: cert.KindFile, Format: "pem",
					Location: r.Err.Path, SourceName: s.opts.Name,
				},
				Errors: []cert.ItemError{{Index: -1, Reason: r.Err.Reason, Err: r.Err.Err}},
			})
			continue
		}
		path := r.Entry.Path
		seen[path] = struct{}{}
		s.processEntry(ctx, sink, r.Entry)
	}

	// Emit Delete for paths that disappeared since last walk.
	s.mu.Lock()
	stale := make([]string, 0)
	for p := range s.cache {
		if _, ok := seen[p]; !ok {
			stale = append(stale, p)
		}
	}
	for _, p := range stale {
		delete(s.cache, p)
	}
	s.mu.Unlock()
	for _, p := range stale {
		ref := cert.SourceRef{
			Kind: cert.KindFile, Location: p, SourceName: s.opts.Name, Format: "pem",
		}
		sink.Delete(ref)
		s.log.Debug("file disappeared", "path", p)
	}

	s.log.Debug("walk completed",
		"duration_ms", time.Since(start).Milliseconds(),
		"seen", len(seen), "stale", len(stale))
	if isFirst {
		if s.opts.OnReady != nil {
			s.opts.OnReady(walkOK)
		}
		if s.opts.FirstSyncDone != nil {
			select {
			case <-s.opts.FirstSyncDone:
			default:
				close(s.opts.FirstSyncDone)
			}
		}
	}
}

func (s *Source) processEntry(ctx context.Context, sink cert.Sink, e fileglob.Entry) {
	path := e.Path
	mtime := time.Time{}
	size := int64(0)
	if e.Info != nil {
		mtime = e.Info.ModTime()
		size = e.Info.Size()
	}

	if s.opts.SkipUnchanged {
		s.mu.Lock()
		ce, ok := s.cache[path]
		s.mu.Unlock()
		if ok && ce.mtime.Equal(mtime) && ce.size == size {
			// Re-emit the cached bundle each tick so registry counts stay
			// accurate even if the registry was wiped between scrapes —
			// in practice the registry preserves entries, so this is a
			// no-op when nothing changed. We skip it to save work.
			return
		}
	}

	// Read from the resolved target when this is a symlink the walker
	// already chased: e.LinkTo carries the path that is actually reachable
	// from the exporter's view (translated through PathMappings if needed).
	// Falling back to the symlink path itself would let the OS re-follow
	// the link and miss any translation.
	readPath := path
	if e.LinkTo != "" {
		readPath = e.LinkTo
	}
	data, err := s.opts.Reader.Read(readPath)
	if err != nil {
		reason := classifyReadError(err)
		s.log.Warn("read error", "path", path, "error", err)
		sink.Upsert(cert.Bundle{
			Source: cert.SourceRef{
				Kind: cert.KindFile, Format: "pem",
				Location: path, SourceName: s.opts.Name,
			},
			Errors: []cert.ItemError{{Index: -1, Reason: reason, Err: err}},
		})
		return
	}

	// Try formats in order.
	for _, p := range s.opts.Formats {
		ref := cert.SourceRef{
			Kind: cert.KindFile, Format: p.Format(),
			Location: path, SourceName: s.opts.Name,
		}
		if e.Pattern != "" {
			if ref.Attributes == nil {
				ref.Attributes = map[string]string{}
			}
			ref.Attributes["pattern"] = e.Pattern
		}
		t0 := time.Now()
		b := p.Parse(data, ref, s.opts.ParseOpts)
		_ = time.Since(t0)
		if b.HasFatalError() && len(s.opts.Formats) > 1 {
			// fall through to next parser
			continue
		}
		s.mu.Lock()
		s.cache[path] = cacheEntry{mtime: mtime, size: size, bundle: b}
		s.mu.Unlock()
		sink.Upsert(b)
		return
	}
}

func classifyReadError(err error) string {
	if errors.Is(err, os.ErrNotExist) {
		return cert.ReasonNotFound
	}
	if errors.Is(err, os.ErrPermission) {
		return cert.ReasonPermissionDenied
	}
	return cert.ReasonReadFailed
}
