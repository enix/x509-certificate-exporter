// Command x509-certificate-exporter is a Prometheus exporter that
// discovers x509 certificates in files and Kubernetes Secrets/ConfigMaps
// and exposes their validity windows as metrics.
//
// Configuration is YAML-driven. A handful of legacy CLI flags are supported
// as ergonomic shortcuts.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/alecthomas/kong"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/enix/x509-certificate-exporter/v4/internal/config"
	"github.com/enix/x509-certificate-exporter/v4/internal/fileglob"
	xlog "github.com/enix/x509-certificate-exporter/v4/internal/log"
	"github.com/enix/x509-certificate-exporter/v4/internal/product"
	"github.com/enix/x509-certificate-exporter/v4/internal/server"
	filesource "github.com/enix/x509-certificate-exporter/v4/internal/source/file"
	k8ssource "github.com/enix/x509-certificate-exporter/v4/internal/source/k8s"
	kcsource "github.com/enix/x509-certificate-exporter/v4/internal/source/kubeconfig"
	"github.com/enix/x509-certificate-exporter/v4/pkg/cert"
	pemparser "github.com/enix/x509-certificate-exporter/v4/pkg/cert/pem"
	pkcs12parser "github.com/enix/x509-certificate-exporter/v4/pkg/cert/pkcs12"
	"github.com/enix/x509-certificate-exporter/v4/pkg/registry"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// CLI is the legacy flag surface. The YAML config is the source of truth;
// CLI flags only override a few headline fields.
type CLI struct {
	Config           string   `name:"config" short:"C" help:"Path to YAML config. If empty, search standard locations."`
	WatchFiles       []string `name:"watch-file" short:"f" help:"Watch a single PEM file. Repeatable."`
	WatchDirs        []string `name:"watch-dir" short:"d" help:"Watch all files in a directory (one level)."`
	WatchKubeconfs   []string `name:"watch-kubeconf" short:"k" help:"Watch certificates embedded in a kubeconfig file."`
	WatchKubeSecrets bool     `name:"watch-kube-secrets" help:"Enable Kubernetes secrets scanning."`
	Listen           string   `name:"listen-address" short:"b" help:"Listen address."`
	WebConfigFile    string   `name:"web.config.file" help:"Exporter-toolkit web configuration file."`
	Debug            bool     `name:"debug" help:"Enable debug logging."`
	Profile          bool     `name:"profile" help:"Enable pprof endpoint on :6060."`
	Version          bool     `name:"version" short:"v" help:"Print version and exit."`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "fatal:", err)
		os.Exit(1)
	}
}

func run() error {
	var cli CLI
	_ = kong.Parse(&cli,
		kong.Name(product.Slug),
		kong.Description(product.Description),
		kong.UsageOnError(),
	)
	if cli.Version {
		fmt.Println(product.BuildInfo().Format(false))
		return nil
	}

	cfg, _, err := config.FindAndLoad(cli.Config)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("load config: %w", err)
	}
	if errors.Is(err, os.ErrNotExist) {
		// No YAML file: synthesize from CLI alone.
		cfg = config.Default()
	}
	cfg = config.ApplyCLI(cfg, config.CLIOverrides{
		WatchFiles: cli.WatchFiles, WatchDirs: cli.WatchDirs,
		WatchKubeconf: cli.WatchKubeconfs, WatchKubeSecrets: cli.WatchKubeSecrets,
		Listen: cli.Listen, WebConfigFile: cli.WebConfigFile,
		Debug: cli.Debug, Profile: cli.Profile,
	})
	if !config.HasSources(cfg) {
		return config.ErrNoSources
	}

	level, err := xlog.ParseLevel(cfg.Log.Level)
	if err != nil {
		return fmt.Errorf("log level %q: %w", cfg.Log.Level, err)
	}
	logger := xlog.New(os.Stderr, level, xlog.ParseFormat(cfg.Log.Format))
	logger.Info("starting", "version", product.BuildInfo().Version, "level", cfg.Log.Level)

	collisionPolicy := registry.CollisionAuto
	switch cfg.Metrics.CollisionDiscriminator {
	case "always":
		collisionPolicy = registry.CollisionAlways
	case "never":
		collisionPolicy = registry.CollisionNever
	}
	exposedSecretLabels, exposedCMLabels := exposedLabelsFromConfig(cfg)
	reg := registry.New(registry.Config{
		ExposeRelative:         cfg.Metrics.ExposeRelative,
		ExposePerCertError:     cfg.Metrics.ExposePerCertError,
		ExposeNotBefore:        cfg.Metrics.ExposeNotBefore,
		ExposeExpired:          cfg.Metrics.ExposeExpired,
		ExposeDiagnostics:      cfg.Metrics.ExposeDiagnostics,
		Pkcs12InUse:            pkcs12InUse(cfg),
		SubjectFields:          cfg.Metrics.ExposeSubjectFields,
		IssuerFields:           cfg.Metrics.ExposeIssuerFields,
		TrimPathComponents:     cfg.Metrics.TrimPathComponents,
		Collision:              collisionPolicy,
		DiscriminatorLength:    cfg.Metrics.CollisionDiscriminatorLength,
		ExposedSecretLabels:    exposedSecretLabels,
		ExposedConfigMapLabels: exposedCMLabels,
		EnableStats:            cfg.Web.EnableStats,
	}, logger)

	k8ssource.RegisterMetrics(reg)

	pReg := prometheus.NewRegistry()
	if err := pReg.Register(reg); err != nil {
		return fmt.Errorf("register collector: %w", err)
	}

	readiness := &server.Readiness{}
	agg := server.NewAggregate(readiness, len(cfg.Sources))

	// Use a manual signal channel so we can log the signal name before
	// cancelling the context. signal.NotifyContext doesn't expose which
	// signal fired, making silent shutdowns hard to diagnose.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		select {
		case sig := <-sigCh:
			logger.Info("received signal, shutting down", "signal", sig.String())
			cancel()
		case <-ctx.Done():
		}
	}()

	for i := range cfg.Sources {
		s := cfg.Sources[i]
		// Wrap the readiness callback so each source flips its own
		// x509_source_up gauge in addition to feeding the aggregator that
		// drives the global /readyz endpoint.
		reach := agg.Reach()
		ready := func(success bool) {
			reg.MarkSourceUp(s.Kind, s.Name, success)
			reach(success)
		}
		src, err := buildSource(ctx, s, cfg, ready, reg, logger)
		if err != nil {
			return fmt.Errorf("source %q: %w", s.Name, err)
		}
		logger.Debug("starting source", "source_name", s.Name, "source_kind", s.Kind)
		go func() {
			defer recoverPanic(reg, "source/"+s.Name, logger)
			if err := src.Run(ctx, reg); err != nil && !errors.Is(err, context.Canceled) {
				logger.Error("source exited with error", "source_name", s.Name, "source_kind", s.Kind, "error", err)
			} else {
				logger.Debug("source stopped", "source_name", s.Name, "source_kind", s.Kind, "reason", err)
			}
		}()
	}

	srv := server.Build(server.Options{
		Listen:       cfg.Server.Listen,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		Registry:     pReg,
		EnableStats:  cfg.Web.EnableStats,
		Stats:        reg,
		Readiness:    readiness,
		Logger:       logger,
	})
	logger.Info("listening", "addr", cfg.Server.Listen)

	if cfg.Diagnostics.Pprof.Enabled {
		listen := cfg.Diagnostics.Pprof.Listen
		if listen == "" {
			listen = ":6060"
		}
		pprofSrv := server.BuildPprof(server.PprofOptions{
			Listen:       listen,
			ReadTimeout:  cfg.Server.ReadTimeout,
			WriteTimeout: cfg.Server.WriteTimeout,
		})
		go func() {
			defer recoverPanic(reg, "pprof", logger)
			server.RunPprof(ctx, pprofSrv, logger)
		}()
	}

	srvErr := make(chan error, 1)
	go func() {
		srvErr <- srv.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		logger.Info("shutdown signal received")
	case err := <-srvErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("server: %w", err)
		}
	}
	shutdownCtx, sCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer sCancel()
	_ = srv.Shutdown(shutdownCtx)
	return nil
}

func recoverPanic(r *registry.Registry, component string, logger *slog.Logger) {
	if rv := recover(); rv != nil {
		logger.Error("goroutine panic", "component", component, "panic", fmt.Sprint(rv))
		r.MarkPanic(component)
	}
}

// pkcs12InUse reports whether any source declares a `pkcs12` format,
// either at the source level (file sources) or per-secret-type
// (kubernetes sources). The result drives whether the registry
// registers the `x509_pkcs12_passphrase_failures_total` counter.
func pkcs12InUse(cfg config.Config) bool {
	for _, s := range cfg.Sources {
		for _, f := range s.Formats {
			if f == "pkcs12" {
				return true
			}
		}
		if s.Secrets != nil {
			for _, t := range s.Secrets.Types {
				if t.Format == "pkcs12" {
					return true
				}
			}
		}
		if s.ConfigMaps != nil && s.ConfigMaps.Format == "pkcs12" {
			return true
		}
	}
	return false
}

func exposedLabelsFromConfig(cfg config.Config) (secrets, configmaps []string) {
	seen := map[string]struct{}{}
	for _, s := range cfg.Sources {
		if s.Secrets != nil {
			for _, l := range s.Secrets.ExposeLabels {
				if _, dup := seen[l]; dup {
					continue
				}
				seen[l] = struct{}{}
				secrets = append(secrets, l)
			}
		}
		if s.ConfigMaps != nil {
			for _, l := range s.ConfigMaps.ExposeLabels {
				if _, dup := seen["cm/"+l]; dup {
					continue
				}
				seen["cm/"+l] = struct{}{}
				configmaps = append(configmaps, l)
			}
		}
	}
	return
}

func buildSource(ctx context.Context, s config.Source, cfg config.Config, ready func(bool), reg *registry.Registry, logger *slog.Logger) (cert.Source, error) {
	switch s.Kind {
	case "file":
		return buildFileSource(s, cfg, ready, logger)
	case "kubeconfig":
		return kcsource.New(kcsource.Options{
			Name: s.Name, Paths: s.Paths,
			RefreshInterval: s.RefreshInterval, OnReady: ready,
		}, logger), nil
	case "kubernetes":
		return buildKubeSource(ctx, s, ready, reg, logger)
	}
	return nil, fmt.Errorf("unknown kind %q", s.Kind)
}

func buildFileSource(s config.Source, cfg config.Config, ready func(bool), logger *slog.Logger) (cert.Source, error) {
	patterns := make([]fileglob.Pattern, 0, len(s.Paths))
	for _, p := range s.Paths {
		c, err := fileglob.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("compile pattern %q: %w", p, err)
		}
		patterns = append(patterns, c)
	}
	excludes := make([]fileglob.Pattern, 0, len(s.ExcludePaths))
	for _, p := range s.ExcludePaths {
		c, err := fileglob.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("compile exclude %q: %w", p, err)
		}
		excludes = append(excludes, c)
	}
	parsers := make([]cert.FormatParser, 0, len(s.Formats))
	parseOpts := cert.ParseOptions{}
	if s.Pkcs12 != nil {
		if s.Pkcs12.Passphrase != "" {
			parseOpts.Pkcs12Passphrase = s.Pkcs12.Passphrase
		}
		if s.Pkcs12.PassphraseFile != "" {
			data, err := os.ReadFile(s.Pkcs12.PassphraseFile)
			if err != nil {
				return nil, fmt.Errorf("read pkcs12 passphraseFile: %w", err)
			}
			parseOpts.Pkcs12Passphrase = trimNewline(string(data))
		}
		if s.Pkcs12.TryEmptyPassphrase != nil {
			parseOpts.Pkcs12TryEmpty = *s.Pkcs12.TryEmptyPassphrase
		} else {
			parseOpts.Pkcs12TryEmpty = true
		}
	}
	for _, f := range s.Formats {
		switch f {
		case "pem":
			parsers = append(parsers, pemparser.New())
		case "pkcs12":
			parsers = append(parsers, pkcs12parser.New())
		}
	}
	follow := true
	if s.FollowSymlinks != nil {
		follow = *s.FollowSymlinks
	}
	return filesource.New(filesource.Options{
		Name: s.Name, Patterns: patterns, Excludes: excludes,
		Formats: parsers, FollowSymlinks: follow, FollowSymlinkDirs: s.FollowSymlinkDirs,
		RefreshInterval: s.RefreshInterval,
		SkipUnchanged:   cfg.Cache.FilePoll.SkipUnchanged,
		ParseOpts:       parseOpts,
		PathMappings:    s.PathMappings,
		OnReady:         ready,
		Jitter:          0.25,
	}, logger), nil
}

func buildKubeSource(ctx context.Context, s config.Source, ready func(bool), reg *registry.Registry, logger *slog.Logger) (cert.Source, error) {
	cfg, err := buildKubeClientConfig(s.Kubeconfig)
	if err != nil {
		return nil, err
	}
	if s.RateLimit != nil {
		cfg.QPS = float32(s.RateLimit.QPS)
		cfg.Burst = s.RateLimit.Burst
	}
	cli, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}

	rules := []k8ssource.SecretTypeRule{}
	if s.Secrets != nil {
		for _, t := range s.Secrets.Types {
			format := t.Format
			if format == "" {
				format = "pem"
			}
			var parser cert.FormatParser
			switch format {
			case "pem":
				parser = pemparser.New()
			case "pkcs12":
				parser = pkcs12parser.New()
			default:
				return nil, fmt.Errorf("secret type %q: unsupported format %q", t.Type, format)
			}
			for _, kp := range t.KeyPatterns {
				re, err := regexp.Compile(kp)
				if err != nil {
					return nil, fmt.Errorf("secret type %q: bad keyPattern %q: %w", t.Type, kp, err)
				}
				rule := k8ssource.SecretTypeRule{
					Type: t.Type, KeyRe: re, Parser: parser,
				}
				if t.Pkcs12 != nil {
					if t.Pkcs12.PassphraseKey != "" {
						rule.PassphraseKey = t.Pkcs12.PassphraseKey
					}
					if t.Pkcs12.TryEmptyPassphrase != nil {
						rule.ParseOpts.Pkcs12TryEmpty = *t.Pkcs12.TryEmptyPassphrase
					} else {
						rule.ParseOpts.Pkcs12TryEmpty = true
					}
				}
				rules = append(rules, rule)
			}
		}
	}
	cmRules := []k8ssource.SecretTypeRule{}
	if s.ConfigMaps != nil {
		format := s.ConfigMaps.Format
		if format == "" {
			format = "pem"
		}
		var parser cert.FormatParser
		switch format {
		case "pem":
			parser = pemparser.New()
		case "pkcs12":
			parser = pkcs12parser.New()
		default:
			return nil, fmt.Errorf("configMaps format %q unsupported", format)
		}
		for _, kp := range s.ConfigMaps.KeyPatterns {
			re, err := regexp.Compile(kp)
			if err != nil {
				return nil, fmt.Errorf("configMaps keyPattern %q: %w", kp, err)
			}
			cmRules = append(cmRules, k8ssource.SecretTypeRule{KeyRe: re, Parser: parser})
		}
	}

	exposedSecretLabels, exposedCMLabels := []string{}, []string{}
	if s.Secrets != nil {
		exposedSecretLabels = s.Secrets.ExposeLabels
	}
	if s.ConfigMaps != nil {
		exposedCMLabels = s.ConfigMaps.ExposeLabels
	}

	ns := ""
	var nsFilter k8ssource.NamespaceFilter
	if s.Namespaces != nil {
		nsFilter = namespaceFilterFromConfig(s.Namespaces)
		// Scope the informer to a single namespace only when the rule
		// can be expressed as one literal name with no other constraint.
		// Otherwise stay cluster-scoped and let the source apply the
		// filter client-side via the namespace cache.
		if len(s.Namespaces.Include) == 1 && !containsGlob(s.Namespaces.Include[0]) &&
			len(s.Namespaces.Exclude) == 0 &&
			len(s.Namespaces.IncludeLabels) == 0 &&
			len(s.Namespaces.ExcludeLabels) == 0 {
			ns = s.Namespaces.Include[0]
			nsFilter = k8ssource.NamespaceFilter{}
		}
	}
	if ns != "" {
		reg.MarkInformerScope(s.Name, "namespace")
	} else {
		reg.MarkInformerScope(s.Name, "cluster")
	}

	var secretSelector k8ssource.Selectors
	var secretFilter k8ssource.SecretFilter
	if s.Secrets != nil {
		secretSelector.LabelSelector = buildLabelSelector(s.Secrets.IncludeLabels, s.Secrets.ExcludeLabels)
		secretFilter.IncludeNames = nonWildcard(s.Secrets.Include)
		secretFilter.ExcludeNames = s.Secrets.Exclude
	}
	var cmSelector k8ssource.Selectors
	var cmFilter k8ssource.SecretFilter
	if s.ConfigMaps != nil {
		// ConfigMapsCfg currently has no IncludeLabels/ExcludeLabels in
		// the YAML schema, but Include/Exclude name globs are honored.
		cmFilter.IncludeNames = nonWildcard(s.ConfigMaps.Include)
		cmFilter.ExcludeNames = s.ConfigMaps.Exclude
	}

	return k8ssource.New(k8ssource.Options{
		Name: s.Name, Client: cli, Namespace: ns,
		ResyncEvery:            refreshOrDefault(s.RefreshInterval, 30*time.Minute),
		ListPageSize:           s.ListPageSize,
		SecretRules:            rules,
		SecretSelector:         secretSelector,
		SecretFilter:           secretFilter,
		ConfigMapRules:         cmRules,
		ConfigMapSelector:      cmSelector,
		ConfigMapFilter:        cmFilter,
		NamespaceFilter:        nsFilter,
		ExposedSecretLabels:    exposedSecretLabels,
		ExposedConfigMapLabels: exposedCMLabels,
		OnReady:                ready,
	}, logger), nil
}

func namespaceFilterFromConfig(n *config.Namespaces) k8ssource.NamespaceFilter {
	return k8ssource.NamespaceFilter{
		IncludeNames:  nonWildcard(n.Include),
		ExcludeNames:  n.Exclude,
		IncludeLabels: n.IncludeLabels,
		ExcludeLabels: n.ExcludeLabels,
	}
}

// nonWildcard drops a single ["*"] entry — that pattern means "everything"
// and is equivalent to "no rule". Anything else is passed through verbatim.
func nonWildcard(names []string) []string {
	if len(names) == 1 && names[0] == "*" {
		return nil
	}
	return names
}

// buildLabelSelector turns IncludeLabels/ExcludeLabels (each entry being
// either "key" or "key=value") into a Kubernetes label-selector string. The
// result is pushed server-side via the informer factory, so no client-side
// matching is needed for label rules on Secrets / ConfigMaps. An empty
// result means "no constraint".
func buildLabelSelector(include, exclude []string) string {
	parts := make([]string, 0, len(include)+len(exclude))
	parts = append(parts, include...)
	for _, l := range exclude {
		if eq := strings.IndexByte(l, '='); eq >= 0 {
			parts = append(parts, l[:eq]+"!="+l[eq+1:])
		} else {
			parts = append(parts, "!"+l)
		}
	}
	return strings.Join(parts, ",")
}

func refreshOrDefault(d, def time.Duration) time.Duration {
	if d <= 0 {
		return def
	}
	return d
}

func containsGlob(s string) bool {
	for _, r := range s {
		if r == '*' || r == '?' || r == '[' {
			return true
		}
	}
	return false
}

func buildKubeClientConfig(kubeconfig string) (*rest.Config, error) {
	if kubeconfig != "" {
		return clientcmd.BuildConfigFromFlags("", kubeconfig)
	}
	if env := os.Getenv("KUBECONFIG"); env != "" {
		return clientcmd.BuildConfigFromFlags("", env)
	}
	if cfg, err := rest.InClusterConfig(); err == nil {
		return cfg, nil
	}
	if home, _ := os.UserHomeDir(); home != "" {
		path := home + "/.kube/config"
		if _, err := os.Stat(path); err == nil {
			return clientcmd.BuildConfigFromFlags("", path)
		}
	}
	return nil, fmt.Errorf("no kubeconfig found and not running in-cluster")
}

func trimNewline(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}
