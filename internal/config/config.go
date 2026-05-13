// Package config defines the YAML configuration schema, its validation,
// and the legacy-CLI-flag bridge.
//
// The YAML file is the source of truth. CLI flags exist only as ergonomic
// shortcuts for the most common cases (a few -f, -d paths, an override of
// the listen address, --debug, etc.) and are mapped onto the YAML schema
// at parse time. Anything more complex must live in the YAML file.
package config

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/enix/x509-certificate-exporter/v4/pkg/cert"
	"github.com/enix/x509-certificate-exporter/v4/pkg/fileglob"
)

// Canonical values for Source.Kind in the YAML config. These strings are
// part of the user-facing schema (users write `kind: kubernetes` in their
// YAML) — do not change the literal values without a migration story.
//
// Note: these are NOT the same as the cert.Kind* constants used by the
// registry. A single config Source of kind "kubernetes" produces refs of
// either cert.KindKubeSecret or cert.KindKubeConfigMap depending on the
// resource it observes.
const (
	KindFile       = "file"
	KindKubeconfig = "kubeconfig"
	KindKubernetes = "kubernetes"
	KindCABundle   = "cabundle"
)

// Built-in defaults applied by Default() and re-applied by mergeDefaults()
// when a partial YAML omits a field. Centralised so the two functions
// can never disagree and so other packages (e.g. main.go's pprof
// fallback) reference the same values.
const (
	DefaultListenAddress    = ":9793"
	DefaultPprofAddress     = ":6060"
	DefaultLogLevel         = "info"
	DefaultLogFormat        = "text"
	DefaultReadTimeout      = 10 * time.Second
	DefaultWriteTimeout     = 30 * time.Second
	DefaultFilePollInterval = 30 * time.Second
	DefaultCollisionMode    = "auto" // auto|always|never; see registry.CollisionPolicy
	DefaultCollisionLength  = 8
)

// Top-level configuration.
type Web struct {
	EnableStats bool `yaml:"enableStats"`
}

type Config struct {
	Web         Web         `yaml:"web"`
	Server      Server      `yaml:"server"`
	Log         Log         `yaml:"log"`
	Diagnostics Diagnostics `yaml:"diagnostics"`
	Sources     []Source    `yaml:"sources"`
	Metrics     Metrics     `yaml:"metrics"`
	Cache       Cache       `yaml:"cache"`
}

type Server struct {
	Listen        string        `yaml:"listen"`
	WebConfigFile string        `yaml:"webConfigFile"`
	// ProbeListen, when non-empty, runs a second http.Server on this
	// address serving only /healthz and /readyz over plain HTTP. Lets
	// kubelet probes succeed when the main /metrics port is gated by
	// TLS / mTLS / basic_auth (webConfiguration) or fronted by a
	// kube-rbac-proxy sidecar. Empty disables — probes use the main
	// port.
	ProbeListen   string        `yaml:"probeListen"`
	SystemdSocket bool          `yaml:"systemdSocket"`
	ReadTimeout   time.Duration `yaml:"readTimeout"`
	WriteTimeout  time.Duration `yaml:"writeTimeout"`
}

type Log struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
	Timing bool   `yaml:"timing"`
}

type Diagnostics struct {
	Pprof Pprof `yaml:"pprof"`
}

type Pprof struct {
	Enabled bool   `yaml:"enabled"`
	Listen  string `yaml:"listen"`
}

// Source is a tagged union by Kind.
type Source struct {
	Kind              string        `yaml:"kind"`
	Name              string        `yaml:"name"`
	Paths             []string      `yaml:"paths,omitempty"`
	ExcludePaths      []string      `yaml:"excludePaths,omitempty"`
	FollowSymlinks    *bool         `yaml:"followSymlinks,omitempty"`
	FollowSymlinkDirs bool          `yaml:"followSymlinkDirs,omitempty"`
	RefreshInterval   time.Duration `yaml:"refreshInterval,omitempty"`
	Formats           []string      `yaml:"formats,omitempty"`
	Pkcs12            *Pkcs12       `yaml:"pkcs12,omitempty"`

	// PathMappings declares foreign↔local path-prefix translations applied
	// when resolving symlinks (and the scope within which their targets must
	// remain). Used by the Helm chart's DaemonSet templates to inform the
	// exporter of the host↔volumeMount mapping; a non-empty list also turns
	// on containment, rejecting symlinks that escape any declared scope with
	// reason "out_of_scope_symlink".
	PathMappings []fileglob.PathMapping `yaml:"pathMappings,omitempty"`

	// kubernetes-only
	Kubeconfig string         `yaml:"kubeconfig,omitempty"`
	RateLimit  *RateLimit     `yaml:"rateLimit,omitempty"`
	Namespaces *Namespaces    `yaml:"namespaces,omitempty"`
	Secrets    *SecretsCfg    `yaml:"secrets,omitempty"`
	ConfigMaps *ConfigMapsCfg `yaml:"configMaps,omitempty"`
	Workers    int            `yaml:"workers,omitempty"`

	// cabundle-only
	CABundles *CABundlesCfg `yaml:"cabundles,omitempty"`

	// ListPageSize caps the number of objects returned per LIST API call
	// during the initial sync and on resync. The exporter pages through
	// the API and processes each page inline before fetching the next,
	// so peak memory during sync is roughly proportional to this value
	// times the average object size. Defaults to 50 — raising it makes
	// the initial sync slightly faster (fewer round-trips) at the cost
	// of higher memory peaks; lowering it helps on memory-constrained
	// clusters with very large Helm release secrets or ConfigMaps.
	ListPageSize int64 `yaml:"listPageSize,omitempty"`
}

type Pkcs12 struct {
	Passphrase           string     `yaml:"passphrase,omitempty"`
	PassphraseFile       string     `yaml:"passphraseFile,omitempty"`
	PassphraseSecretRef  *SecretRef `yaml:"passphraseSecretRef,omitempty"`
	PassphraseKey        string     `yaml:"passphraseKey,omitempty"`
	PassphraseAnnotation string     `yaml:"passphraseAnnotation,omitempty"`
	TryEmptyPassphrase   *bool      `yaml:"tryEmptyPassphrase,omitempty"`
}

type SecretRef struct {
	Namespace string `yaml:"namespace"`
	Name      string `yaml:"name"`
	Key       string `yaml:"key"`
}

type RateLimit struct {
	QPS   float64 `yaml:"qps"`
	Burst int     `yaml:"burst"`
}

type Namespaces struct {
	Include       []string `yaml:"include,omitempty"`
	Exclude       []string `yaml:"exclude,omitempty"`
	IncludeLabels []string `yaml:"includeLabels,omitempty"`
	ExcludeLabels []string `yaml:"excludeLabels,omitempty"`
}

type SecretsCfg struct {
	Include       []string        `yaml:"include,omitempty"`
	Exclude       []string        `yaml:"exclude,omitempty"`
	IncludeLabels []string        `yaml:"includeLabels,omitempty"`
	ExcludeLabels []string        `yaml:"excludeLabels,omitempty"`
	Types         []SecretTypeCfg `yaml:"types"`
	ExposeLabels  []string        `yaml:"exposeLabels,omitempty"`
}

type SecretTypeCfg struct {
	Type        string   `yaml:"type"`
	KeyPatterns []string `yaml:"keyPatterns"`
	Format      string   `yaml:"format"`
	Pkcs12      *Pkcs12  `yaml:"pkcs12,omitempty"`
}

type ConfigMapsCfg struct {
	Include      []string `yaml:"include,omitempty"`
	Exclude      []string `yaml:"exclude,omitempty"`
	KeyPatterns  []string `yaml:"keyPatterns"`
	Format       string   `yaml:"format"`
	ExposeLabels []string `yaml:"exposeLabels,omitempty"`
}

// CABundlesCfg drives the `cabundle` source: it watches cluster-scoped
// admission and API-aggregation resources and extracts inline PEM
// `caBundle` fields. Each Resources flag is an opt-in so the chart can
// scope its ClusterRole to the kinds the user enables.
type CABundlesCfg struct {
	// Resources toggles which K8s resource kinds to watch.
	Resources CABundleResources `yaml:"resources"`
	// Include / Exclude are shell-glob patterns on metadata.name.
	Include []string `yaml:"include,omitempty"`
	Exclude []string `yaml:"exclude,omitempty"`
	// IncludeLabels is forwarded as a server-side LabelSelector. Same
	// shape as SecretsCfg.IncludeLabels: "key" or "key=value".
	IncludeLabels []string `yaml:"includeLabels,omitempty"`
	ExcludeLabels []string `yaml:"excludeLabels,omitempty"`
	// ExposeLabels surfaces K8s labels of matched resources as
	// Prometheus labels (prefix `cabundle_label_`).
	ExposeLabels []string `yaml:"exposeLabels,omitempty"`
}

// CABundleResources is the per-kind opt-in.
type CABundleResources struct {
	Mutating      bool `yaml:"mutating"`
	Validating    bool `yaml:"validating"`
	APIService    bool `yaml:"apiservice"`
	CRDConversion bool `yaml:"crdConversion"`
}

type Metrics struct {
	ExposeRelative               bool     `yaml:"exposeRelative"`
	ExposePerCertError           bool     `yaml:"exposePerCertError"`
	ExposeNotBefore              bool     `yaml:"exposeNotBefore"`
	// ExposeExpired controls the per-cert `x509_cert_expired` gauge. It
	// defaults to `true` (the metric is essential for the canonical
	// "is this cert expired" alert); setting it false halves the
	// per-cert series count for users who alert exclusively on
	// `not_after - time()`.
	ExposeExpired                bool     `yaml:"exposeExpired"`
	// ExposeDiagnostics gates a group of self-introspection metrics
	// (parse latency, kube API latency, source scope, namespace
	// informer queue depth) that help debugging the exporter itself
	// but provide no certificate-side signal. Off by default to keep
	// `/metrics` lean.
	ExposeDiagnostics            bool     `yaml:"exposeDiagnostics"`
	ExposeSubjectFields          []string `yaml:"exposeSubjectFields,omitempty"`
	ExposeIssuerFields           []string `yaml:"exposeIssuerFields,omitempty"`
	TrimPathComponents           int      `yaml:"trimPathComponents,omitempty"`
	CollisionDiscriminator       string   `yaml:"collisionDiscriminator,omitempty"` // auto|always|never
	CollisionDiscriminatorLength int      `yaml:"collisionDiscriminatorLength,omitempty"`
}

type Cache struct {
	FilePoll FilePoll `yaml:"filePoll"`
}

type FilePoll struct {
	Interval      time.Duration `yaml:"interval"`
	SkipUnchanged bool          `yaml:"skipUnchanged"`
}

// Default returns a Config with sensible defaults applied.
func Default() Config {
	return Config{
		Web: Web{
			EnableStats: true,
		},
		Server: Server{
			Listen:       DefaultListenAddress,
			ReadTimeout:  DefaultReadTimeout,
			WriteTimeout: DefaultWriteTimeout,
		},
		Log:         Log{Level: DefaultLogLevel, Format: DefaultLogFormat, Timing: true},
		Diagnostics: Diagnostics{Pprof: Pprof{Listen: DefaultPprofAddress}},
		Metrics: Metrics{
			ExposeExpired:                true,
			CollisionDiscriminator:       DefaultCollisionMode,
			CollisionDiscriminatorLength: DefaultCollisionLength,
		},
		Cache: Cache{FilePoll: FilePoll{Interval: DefaultFilePollInterval, SkipUnchanged: true}},
	}
}

// LoadFile loads a YAML config from path.
func LoadFile(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	cfg := Default()
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse config %s: %w", path, err)
	}
	mergeDefaults(&cfg)
	if err := Validate(cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// FindAndLoad locates the config file using the documented search order.
// Returns (cfg, path, error). If path is set on input, only that path is
// considered. If empty, fall back to default locations.
func FindAndLoad(path string) (Config, string, error) {
	if path != "" {
		c, err := LoadFile(path)
		return c, path, err
	}
	candidates := []string{}
	if home, ok := os.LookupEnv("XDG_CONFIG_HOME"); ok && home != "" {
		candidates = append(candidates, filepath.Join(home, "x509-certificate-exporter", "config.yaml"))
	} else if home, ok := os.LookupEnv("HOME"); ok && home != "" {
		candidates = append(candidates, filepath.Join(home, ".config", "x509-certificate-exporter", "config.yaml"))
	}
	candidates = append(candidates, "/etc/x509-certificate-exporter/config.yaml")
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			c, err := LoadFile(p)
			return c, p, err
		}
	}
	return Config{}, "", os.ErrNotExist
}

func mergeDefaults(c *Config) {
	if c.Metrics.CollisionDiscriminator == "" {
		c.Metrics.CollisionDiscriminator = DefaultCollisionMode
	}
	if c.Metrics.CollisionDiscriminatorLength == 0 {
		c.Metrics.CollisionDiscriminatorLength = DefaultCollisionLength
	}
	if c.Server.Listen == "" {
		c.Server.Listen = DefaultListenAddress
	}
	if c.Cache.FilePoll.Interval == 0 {
		c.Cache.FilePoll.Interval = DefaultFilePollInterval
	}
	if c.Log.Level == "" {
		c.Log.Level = DefaultLogLevel
	}
	if c.Log.Format == "" {
		c.Log.Format = DefaultLogFormat
	}
	for i := range c.Sources {
		s := &c.Sources[i]
		if s.FollowSymlinks == nil && s.Kind != KindKubernetes {
			tr := true
			s.FollowSymlinks = &tr
		}
		// RefreshInterval default applies only to poll-based sources (file,
		// kubeconfig). For kubernetes sources the resync period is managed
		// independently via buildKubeSource's own default (30m); applying
		// cache.filePoll.interval there would force a full re-LIST of every
		// Secret and ConfigMap at the poll cadence — far too aggressive on
		// large clusters.
		if s.RefreshInterval == 0 && s.Kind != KindKubernetes {
			s.RefreshInterval = c.Cache.FilePoll.Interval
		}
		if len(s.Formats) == 0 && s.Kind == KindFile {
			s.Formats = []string{cert.FormatPEM}
		}
	}
}

// Validate runs structural checks and returns the first error. Field paths
// are reported with json-pointer-like locations.
func Validate(c Config) error {
	switch c.Metrics.CollisionDiscriminator {
	case "auto", "always", "never":
	default:
		return fmt.Errorf("metrics.collisionDiscriminator: must be one of auto|always|never (got %q)", c.Metrics.CollisionDiscriminator)
	}
	for i, s := range c.Sources {
		if err := validateSource(i, s); err != nil {
			return err
		}
	}
	return nil
}

func validateSource(i int, s Source) error {
	prefix := fmt.Sprintf("sources[%d]", i)
	if s.Name == "" {
		return fmt.Errorf("%s.name: required", prefix)
	}
	switch s.Kind {
	case KindFile:
		if len(s.Paths) == 0 {
			return fmt.Errorf("%s.paths: required for file sources", prefix)
		}
		for _, f := range s.Formats {
			switch f {
			case cert.FormatPEM, cert.FormatPKCS12:
			default:
				return fmt.Errorf("%s.formats: unsupported format %q (must be pem|pkcs12)", prefix, f)
			}
		}
	case KindKubeconfig:
		if len(s.Paths) == 0 {
			return fmt.Errorf("%s.paths: required for kubeconfig sources", prefix)
		}
	case KindKubernetes:
		// nothing strictly required, but we should have either secrets or configmaps configured
		if s.Secrets == nil && s.ConfigMaps == nil {
			return fmt.Errorf("%s: kubernetes source must configure secrets or configMaps", prefix)
		}
		if s.Namespaces != nil {
			if err := validateGlobs(prefix+".namespaces.include", s.Namespaces.Include); err != nil {
				return err
			}
			if err := validateGlobs(prefix+".namespaces.exclude", s.Namespaces.Exclude); err != nil {
				return err
			}
		}
		if s.Secrets != nil {
			if err := validateGlobs(prefix+".secrets.include", s.Secrets.Include); err != nil {
				return err
			}
			if err := validateGlobs(prefix+".secrets.exclude", s.Secrets.Exclude); err != nil {
				return err
			}
		}
		if s.ConfigMaps != nil {
			if err := validateGlobs(prefix+".configMaps.include", s.ConfigMaps.Include); err != nil {
				return err
			}
			if err := validateGlobs(prefix+".configMaps.exclude", s.ConfigMaps.Exclude); err != nil {
				return err
			}
		}
	case KindCABundle:
		if s.CABundles == nil {
			return fmt.Errorf("%s: cabundle source must configure cabundles", prefix)
		}
		r := s.CABundles.Resources
		if !r.Mutating && !r.Validating && !r.APIService && !r.CRDConversion {
			return fmt.Errorf("%s.cabundles.resources: at least one resource kind must be enabled", prefix)
		}
		if err := validateGlobs(prefix+".cabundles.include", s.CABundles.Include); err != nil {
			return err
		}
		if err := validateGlobs(prefix+".cabundles.exclude", s.CABundles.Exclude); err != nil {
			return err
		}
	case "":
		return fmt.Errorf("%s.kind: required", prefix)
	default:
		return fmt.Errorf("%s.kind: unknown kind %q", prefix, s.Kind)
	}
	return nil
}

// validateGlobs surfaces malformed shell-glob patterns at startup rather
// than letting them silently match nothing at runtime. `path.Match`
// returns ErrBadPattern for unclosed brackets, dangling escapes, etc.;
// it is the same matcher used by pkg/source/k8s at evaluation time.
func validateGlobs(field string, patterns []string) error {
	for i, p := range patterns {
		if _, err := path.Match(p, ""); err != nil {
			return fmt.Errorf("%s[%d]: invalid shell-glob pattern %q: %w", field, i, p, err)
		}
	}
	return nil
}

// CLIOverrides describes the legacy CLI flags. The fields are pointers/
// slices so that "unset" is distinguishable from "set to zero value".
type CLIOverrides struct {
	WatchFiles       []string
	WatchDirs        []string
	WatchKubeconf    []string
	WatchKubeSecrets bool
	Listen           string
	WebConfigFile    string
	ProbeListen      string
	Debug            bool
	Profile          bool
}

// ApplyCLI merges legacy CLI flags into a base config. If base is empty
// (no YAML), a fresh config is synthesized.
func ApplyCLI(base Config, ov CLIOverrides) Config {
	if base.Server.Listen == "" {
		base = Default()
	}
	mergeDefaults(&base)
	if ov.Listen != "" {
		base.Server.Listen = ov.Listen
	}
	if ov.WebConfigFile != "" {
		base.Server.WebConfigFile = ov.WebConfigFile
	}
	if ov.ProbeListen != "" {
		base.Server.ProbeListen = ov.ProbeListen
	}
	if ov.Debug {
		base.Log.Level = "debug"
	}
	if ov.Profile {
		base.Diagnostics.Pprof.Enabled = true
	}
	if len(ov.WatchFiles) > 0 {
		base.Sources = append(base.Sources, Source{
			Kind:    KindFile,
			Name:    "cli-files",
			Paths:   ov.WatchFiles,
			Formats: []string{cert.FormatPEM},
		})
	}
	for _, d := range ov.WatchDirs {
		base.Sources = append(base.Sources, Source{
			Kind:    KindFile,
			Name:    "cli-dir-" + sanitize(d),
			Paths:   []string{strings.TrimRight(d, "/") + "/*"},
			Formats: []string{cert.FormatPEM},
		})
	}
	if len(ov.WatchKubeconf) > 0 {
		base.Sources = append(base.Sources, Source{
			Kind:  KindKubeconfig,
			Name:  "cli-kubeconf",
			Paths: ov.WatchKubeconf,
		})
	}
	if ov.WatchKubeSecrets {
		base.Sources = append(base.Sources, Source{
			Kind: KindKubernetes,
			Name: "cli-kube",
			Secrets: &SecretsCfg{
				Types: []SecretTypeCfg{
					{Type: "kubernetes.io/tls", KeyPatterns: []string{`^tls\.crt$`}, Format: cert.FormatPEM},
				},
			},
		})
	}
	mergeDefaults(&base)
	return base
}

func sanitize(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			continue
		}
		b.WriteByte('-')
	}
	out := b.String()
	out = strings.Trim(out, "-")
	if out == "" {
		out = "anon"
	}
	return out
}

// HasSources is a convenience for the startup check.
func HasSources(c Config) bool { return len(c.Sources) > 0 }

// SourcePaths returns all paths from all file/kubeconfig sources, useful
// for logs and tests.
func SourcePaths(c Config) []string {
	var out []string
	for _, s := range c.Sources {
		out = append(out, s.Paths...)
	}
	return out
}

// ErrNoSources is returned when neither YAML nor CLI configures any source.
var ErrNoSources = errors.New("no sources configured (use --config or one of -f/-d/-k/--watch-kube-secrets)")
