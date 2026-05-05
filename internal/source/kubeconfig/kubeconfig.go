// Package kubeconfig implements a Source that extracts certificates
// embedded in kubeconfig files (or referenced via certificate-authority/
// client-certificate file paths). Mirrors the existing exporter's
// behaviour: only the four canonical JSONPath-like locations are read.
package kubeconfig

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/enix/x509-certificate-exporter/v4/pkg/cert"
	"github.com/enix/x509-certificate-exporter/v4/pkg/cert/pem"
)

// DefaultRefreshInterval is how often the source re-reads its
// configured kubeconfig paths when Options.RefreshInterval is zero.
const DefaultRefreshInterval = 30 * time.Second

// Options configure a kubeconfig Source.
type Options struct {
	Name            string
	Paths           []string
	RefreshInterval time.Duration
	FirstSyncDone   chan struct{}
	OnReady         func(success bool)
}

// Source implements cert.Source.
type Source struct {
	opts   Options
	log    *slog.Logger
	parser cert.FormatParser

	mu    sync.Mutex
	known map[string]struct{} // refs we last produced; for delete on disappearance
}

func New(opts Options, logger *slog.Logger) *Source {
	if logger == nil {
		logger = slog.Default()
	}
	if opts.RefreshInterval <= 0 {
		opts.RefreshInterval = DefaultRefreshInterval
	}
	return &Source{
		opts:   opts,
		log:    logger.With("source_kind", cert.KindKubeconfig, "source_name", opts.Name),
		parser: pem.New(),
		known:  map[string]struct{}{},
	}
}

func (s *Source) Name() string { return s.opts.Name }

// Run scans each path in opts.Paths and emits one bundle per cert found.
func (s *Source) Run(ctx context.Context, sink cert.Sink) error {
	s.runOnce(ctx, sink, true)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(s.opts.RefreshInterval):
		}
		s.runOnce(ctx, sink, false)
	}
}

func (s *Source) runOnce(ctx context.Context, sink cert.Sink, isFirst bool) {
	seen := map[string]struct{}{}
	allOK := true
	for _, p := range s.opts.Paths {
		if err := ctx.Err(); err != nil {
			return
		}
		s.scan(p, sink, seen, &allOK)
	}
	// Delete anything that disappeared since last cycle.
	s.mu.Lock()
	stale := make([]string, 0)
	for k := range s.known {
		if _, ok := seen[k]; !ok {
			stale = append(stale, k)
		}
	}
	s.known = map[string]struct{}{}
	for k := range seen {
		s.known[k] = struct{}{}
	}
	s.mu.Unlock()
	for _, k := range stale {
		// k = "<path>#<embedded_kind>/<embedded_key>(<idx>)"
		ref := decodeKey(k, s.opts.Name)
		sink.Delete(ref)
	}
	if isFirst {
		if s.opts.OnReady != nil {
			s.opts.OnReady(allOK)
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

// kubeconfigDoc is the minimal subset of kubeconfig we care about.
type kubeconfigDoc struct {
	Clusters []namedCluster `yaml:"clusters"`
	Users    []namedUser    `yaml:"users"`
}
type namedCluster struct {
	Name    string  `yaml:"name"`
	Cluster cluster `yaml:"cluster"`
}
type cluster struct {
	CAData string `yaml:"certificate-authority-data"`
	CAPath string `yaml:"certificate-authority"`
}
type namedUser struct {
	Name string `yaml:"name"`
	User user   `yaml:"user"`
}
type user struct {
	CertData string `yaml:"client-certificate-data"`
	CertPath string `yaml:"client-certificate"`
}

func (s *Source) scan(path string, sink cert.Sink, seen map[string]struct{}, allOK *bool) {
	t0 := time.Now()
	defer func() {
		s.log.Debug("kubeconfig scanned",
			"path", path, "duration_ms", time.Since(t0).Milliseconds())
	}()
	data, err := readFile(path)
	if err != nil {
		*allOK = false
		s.log.Warn("read kubeconfig", "path", path, "error", err)
		ref := cert.SourceRef{Kind: cert.KindKubeconfig, Location: path, SourceName: s.opts.Name, Format: "pem"}
		sink.Upsert(cert.Bundle{
			Source: ref,
			Errors: []cert.ItemError{{Index: -1, Reason: cert.ReasonReadFailed, Err: err}},
		})
		key := encodeKey(path, "", "", -1)
		seen[key] = struct{}{}
		return
	}
	var doc kubeconfigDoc
	if err := yaml.Unmarshal(data, &doc); err != nil {
		*allOK = false
		ref := cert.SourceRef{Kind: cert.KindKubeconfig, Location: path, SourceName: s.opts.Name, Format: "pem"}
		sink.Upsert(cert.Bundle{
			Source: ref,
			Errors: []cert.ItemError{{Index: -1, Reason: cert.ReasonDecodeFailed, Err: err}},
		})
		key := encodeKey(path, "", "", -1)
		seen[key] = struct{}{}
		return
	}
	for _, c := range doc.Clusters {
		s.emit(path, "cluster", c.Name, c.Cluster.CAData, c.Cluster.CAPath, sink, seen)
	}
	for _, u := range doc.Users {
		s.emit(path, "user", u.Name, u.User.CertData, u.User.CertPath, sink, seen)
	}
}

func (s *Source) emit(path, kind, key, b64Data, refPath string, sink cert.Sink, seen map[string]struct{}) {
	var data []byte
	switch {
	case b64Data != "":
		dec, err := base64.StdEncoding.DecodeString(b64Data)
		if err != nil {
			b := cert.Bundle{
				Source: cert.SourceRef{
					Kind: cert.KindKubeconfig, Location: path,
					Key:    fmt.Sprintf("%s/%s", kind, key),
					Format: "pem", SourceName: s.opts.Name,
					Attributes: map[string]string{"embedded_kind": kind, "embedded_key": key},
				},
				Errors: []cert.ItemError{{Index: -1, Reason: cert.ReasonDecodeFailed, Err: err}},
			}
			sink.Upsert(b)
			seen[encodeKey(path, kind, key, 0)] = struct{}{}
			return
		}
		data = dec
	case refPath != "":
		// Resolve relative to the kubeconfig's directory if not absolute.
		actual := refPath
		if !filepath.IsAbs(actual) {
			actual = filepath.Join(filepath.Dir(path), actual)
		}
		raw, err := readFile(actual)
		if err != nil {
			b := cert.Bundle{
				Source: cert.SourceRef{
					Kind: cert.KindKubeconfig, Location: path,
					Key:    fmt.Sprintf("%s/%s", kind, key),
					Format: "pem", SourceName: s.opts.Name,
					Attributes: map[string]string{"embedded_kind": kind, "embedded_key": key},
				},
				Errors: []cert.ItemError{{Index: -1, Reason: cert.ReasonReadFailed, Err: err}},
			}
			sink.Upsert(b)
			seen[encodeKey(path, kind, key, 0)] = struct{}{}
			return
		}
		data = raw
	default:
		// Nothing to read.
		return
	}
	parsed := s.parser.Parse(data, cert.SourceRef{
		Kind: cert.KindKubeconfig, Location: path,
		Key:    fmt.Sprintf("%s/%s", kind, key),
		Format: "pem", SourceName: s.opts.Name,
		Attributes: map[string]string{"embedded_kind": kind, "embedded_key": key},
	}, cert.ParseOptions{})
	sink.Upsert(parsed)
	seen[encodeKey(path, kind, key, 0)] = struct{}{}
}

func encodeKey(path, kind, key string, idx int) string {
	return fmt.Sprintf("%s|%s|%s|%d", path, kind, key, idx)
}

func decodeKey(k, sourceName string) cert.SourceRef {
	// Best-effort reconstruction: we only need enough to call Delete.
	// The fields path|kind|key|idx are joined by '|'.
	var path, kind, key string
	var i int
	parts := []string{}
	cur := ""
	for j := 0; j < len(k); j++ {
		if k[j] == '|' {
			parts = append(parts, cur)
			cur = ""
			continue
		}
		cur += string(k[j])
	}
	parts = append(parts, cur)
	if len(parts) >= 1 {
		path = parts[0]
	}
	if len(parts) >= 2 {
		kind = parts[1]
	}
	if len(parts) >= 3 {
		key = parts[2]
	}
	_ = i
	r := cert.SourceRef{
		Kind: cert.KindKubeconfig, Location: path,
		Format: "pem", SourceName: sourceName,
	}
	if kind != "" || key != "" {
		r.Key = fmt.Sprintf("%s/%s", kind, key)
		r.Attributes = map[string]string{"embedded_kind": kind, "embedded_key": key}
	}
	return r
}

func readFile(p string) ([]byte, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return io.ReadAll(f)
}
