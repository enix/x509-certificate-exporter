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

	"github.com/KimMachineGun/automemlimit/memlimit"
	"github.com/alecthomas/kong"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/exporter-toolkit/web"
	"go.uber.org/automaxprocs/maxprocs"

	"github.com/enix/x509-certificate-exporter/v4/internal/config"
	xlog "github.com/enix/x509-certificate-exporter/v4/internal/log"
	"github.com/enix/x509-certificate-exporter/v4/internal/product"
	"github.com/enix/x509-certificate-exporter/v4/internal/server"
	"github.com/enix/x509-certificate-exporter/v4/pkg/cert"
	derparser "github.com/enix/x509-certificate-exporter/v4/pkg/cert/der"
	pemparser "github.com/enix/x509-certificate-exporter/v4/pkg/cert/pem"
	pkcs12parser "github.com/enix/x509-certificate-exporter/v4/pkg/cert/pkcs12"
	"github.com/enix/x509-certificate-exporter/v4/pkg/fileglob"
	"github.com/enix/x509-certificate-exporter/v4/pkg/registry"
	cabundlesource "github.com/enix/x509-certificate-exporter/v4/pkg/source/cabundle"
	filesource "github.com/enix/x509-certificate-exporter/v4/pkg/source/file"
	k8ssource "github.com/enix/x509-certificate-exporter/v4/pkg/source/k8s"
	kcsource "github.com/enix/x509-certificate-exporter/v4/pkg/source/kubeconfig"

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
	ProbeListen      string   `name:"probe.listen-address" help:"Listen address for a separate plain-HTTP server exposing only /healthz and /readyz. Useful when --web.config.file gates the main port with TLS / mTLS / basic_auth and kubelet probes can't reach it."`
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
		ProbeListen: cli.ProbeListen,
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

	// Adjust GOMAXPROCS to the cgroup CPU quota — without this, Go on
	// Kubernetes sees the host's full core count and oversubscribes
	// pthread parallelism. automaxprocs is a no-op when no cgroup limit
	// is set (bare-metal / dev shell).
	if _, err := maxprocs.Set(maxprocs.Logger(func(format string, args ...any) {
		logger.Info(fmt.Sprintf(format, args...))
	})); err != nil {
		logger.Warn("failed to apply automaxprocs", "err", err)
	}

	// Adjust GOMEMLIMIT to a fraction of the cgroup memory limit, giving
	// the GC a soft target to settle below before the kernel's OOM
	// killer fires. WithRatio(0.9) leaves 10% headroom for non-Go
	// allocations (CGO buffers, stack growth, runtime overhead).
	if _, err := memlimit.SetGoMemLimitWithOpts(
		memlimit.WithRatio(0.9),
		memlimit.WithProvider(memlimit.FromCgroup),
		memlimit.WithLogger(logger),
	); err != nil {
		// Not running under a memory cgroup — fine, log at debug level
		// only so dev/standalone runs aren't noisy.
		logger.Debug("automemlimit skipped", "err", err)
	}

	collisionPolicy := registry.CollisionAuto
	switch cfg.Metrics.CollisionDiscriminator {
	case "always":
		collisionPolicy = registry.CollisionAlways
	case "never":
		collisionPolicy = registry.CollisionNever
	}
	exposedSecretLabels, exposedCMLabels, exposedCABundleLabels := exposedLabelsFromConfig(cfg)
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
		ExposedCABundleLabels:  exposedCABundleLabels,
		EnableStats:            cfg.Web.EnableStats,
	}, logger)

	k8ssource.RegisterMetrics(reg, logger)

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

	if cfg.Diagnostics.Pprof.Enabled {
		listen := cfg.Diagnostics.Pprof.Listen
		if listen == "" {
			listen = config.DefaultPprofAddress
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

	// Probe-only server. Plain HTTP, /healthz + /readyz only — exists so
	// kubelet probes succeed when the main port is auth-gated. Empty
	// ProbeListen disables; in that case probes use the main port and
	// behave as before.
	if cfg.Server.ProbeListen != "" {
		probeSrv := server.BuildProbe(server.ProbeOptions{
			Listen:       cfg.Server.ProbeListen,
			ReadTimeout:  cfg.Server.ReadTimeout,
			WriteTimeout: cfg.Server.WriteTimeout,
			Readiness:    readiness,
		})
		logger.Info("probe listening", "addr", cfg.Server.ProbeListen)
		go func() {
			defer recoverPanic(reg, "probe", logger)
			if err := server.Run(ctx, probeSrv, logger); err != nil && !errors.Is(err, context.Canceled) {
				logger.Error("probe server exited with error", "error", err)
			}
		}()
	}

	srvErr := make(chan error, 1)
	go func() {
		// exporter-toolkit's ListenAndServe is the canonical way to wire
		// up Prometheus-style web.config.file (TLS, mTLS, basic_auth).
		// When WebConfigFile is empty, it falls back to plain HTTP — same
		// behaviour as net/http's ListenAndServe — so this wrapper is
		// always safe regardless of whether the user opts into auth.
		listenAddrs := []string{cfg.Server.Listen}
		webFlags := &web.FlagConfig{
			WebListenAddresses: &listenAddrs,
			WebConfigFile:      &cfg.Server.WebConfigFile,
		}
		err := web.ListenAndServe(srv, webFlags, logger)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		srvErr <- err
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
			if f == cert.FormatPKCS12 {
				return true
			}
		}
		if s.Secrets != nil {
			for _, t := range s.Secrets.Types {
				if t.Format == cert.FormatPKCS12 {
					return true
				}
			}
		}
		if s.ConfigMaps != nil && s.ConfigMaps.Format == cert.FormatPKCS12 {
			return true
		}
	}
	return false
}

func exposedLabelsFromConfig(cfg config.Config) (secrets, configmaps, cabundles []string) {
	seen := map[string]struct{}{}
	for _, s := range cfg.Sources {
		if s.Secrets != nil {
			for _, l := range s.Secrets.ExposeLabels {
				if _, dup := seen["s/"+l]; dup {
					continue
				}
				seen["s/"+l] = struct{}{}
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
		if s.CABundles != nil {
			for _, l := range s.CABundles.ExposeLabels {
				if _, dup := seen["cb/"+l]; dup {
					continue
				}
				seen["cb/"+l] = struct{}{}
				cabundles = append(cabundles, l)
			}
		}
	}
	return
}

func buildSource(ctx context.Context, s config.Source, cfg config.Config, ready func(bool), reg *registry.Registry, logger *slog.Logger) (cert.Source, error) {
	switch s.Kind {
	case config.KindFile:
		return buildFileSource(s, cfg, ready, logger)
	case config.KindKubeconfig:
		return kcsource.New(kcsource.Options{
			Name: s.Name, Paths: s.Paths,
			RefreshInterval: s.RefreshInterval, OnReady: ready,
		}, logger), nil
	case config.KindKubernetes:
		return buildKubeSource(ctx, s, ready, reg, logger)
	case config.KindCABundle:
		return buildCABundleSource(s, ready, logger)
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
		case cert.FormatPEM:
			parsers = append(parsers, pemparser.New())
		case cert.FormatPKCS12:
			parsers = append(parsers, pkcs12parser.New())
		case cert.FormatDER:
			parsers = append(parsers, derparser.New())
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
	cfg, err := buildKubeClientConfig(s.Kubeconfig, logger)
	if err != nil {
		return nil, err
	}
	logger.Info("kubeconfig loaded", "apiserver_host", cfg.Host)
	if s.RateLimit != nil {
		cfg.QPS = float32(s.RateLimit.QPS)
		cfg.Burst = s.RateLimit.Burst
	}
	cli, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}

	// Pre-flight discovery probe — surfaces RBAC and connectivity
	// issues at startup with a clear log line. Failure is non-fatal:
	// the source's own LIST will retry with backoff and report the
	// same error, just less ergonomically.
	if ver, err := cli.Discovery().ServerVersion(); err != nil {
		logger.Warn("kube-apiserver version probe failed", "err", err)
	} else {
		logger.Info("kube-apiserver reachable", "version", ver.GitVersion)
	}

	rules := []k8ssource.SecretTypeRule{}
	if s.Secrets != nil {
		for _, t := range s.Secrets.Types {
			format := t.Format
			if format == "" {
				format = cert.FormatPEM
			}
			var parser cert.FormatParser
			switch format {
			case cert.FormatPEM:
				parser = pemparser.New()
			case cert.FormatPKCS12:
				parser = pkcs12parser.New()
			case cert.FormatDER:
				parser = derparser.New()
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
			format = cert.FormatPEM
		}
		var parser cert.FormatParser
		switch format {
		case cert.FormatPEM:
			parser = pemparser.New()
		case cert.FormatPKCS12:
			parser = pkcs12parser.New()
		case cert.FormatDER:
			parser = derparser.New()
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
		// Scope the source to a single namespace only when the rule can
		// be expressed as one literal name with no other constraint.
		// Otherwise stay cluster-scoped and let the source apply the
		// filter client-side (label-based rules require the namespace
		// informer to know labels for each namespace seen).
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
		// When all rules target the same Secret type (e.g. kubernetes.io/tls),
		// push a server-side field selector so the API only returns matching
		// secrets. This avoids listing Helm release secrets, SA tokens, etc.
		// which can be large and numerous on production clusters.
		// The Secret.type field selector is supported server-side since k8s 1.7.
		if ft := commonSecretType(rules); ft != "" {
			secretSelector.FieldSelector = "type=" + ft
		}
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

// buildCABundleSource constructs a cabundle Source — watches cluster-
// scoped admission resources and emits one cert ref per (resource,
// webhook entry). Shares the kube client construction logic with
// buildKubeSource; consider extracting if a third K8s-based source is
// added.
func buildCABundleSource(s config.Source, ready func(bool), logger *slog.Logger) (cert.Source, error) {
	cfg, err := buildKubeClientConfig(s.Kubeconfig, logger)
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

	cb := s.CABundles
	opts := cabundlesource.Options{
		Name:       s.Name,
		Client:     cli,
		RESTConfig: cfg,
		Resources: cabundlesource.Resources{
			Mutating:      cb.Resources.Mutating,
			Validating:    cb.Resources.Validating,
			APIService:    cb.Resources.APIService,
			CRDConversion: cb.Resources.CRDConversion,
		},
		ResyncEvery:   refreshOrDefault(s.RefreshInterval, 30*time.Minute),
		IncludeNames:  nonWildcard(cb.Include),
		ExcludeNames:  cb.Exclude,
		LabelSelector: buildLabelSelector(cb.IncludeLabels, cb.ExcludeLabels),
		ExposedLabels: cb.ExposeLabels,
		OnReady:       ready,
	}
	return cabundlesource.New(opts, logger), nil
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
// either "key" or "key=value") into a Kubernetes label-selector string.
// The result is passed as the server-side LabelSelector on every LIST and
// WATCH call, so no client-side matching is needed for label rules on
// Secrets / ConfigMaps. An empty result means "no constraint".
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

// commonSecretType returns the Secret.type shared by all rules, or "" if the
// rules are empty, any rule has no type, or the rules have different types.
// Used to derive a server-side FieldSelector that avoids listing irrelevant
// secrets (Helm releases, SA tokens, docker configs, etc.).
func commonSecretType(rules []k8ssource.SecretTypeRule) string {
	if len(rules) == 0 {
		return ""
	}
	t := rules[0].Type
	if t == "" {
		return ""
	}
	for _, r := range rules[1:] {
		if r.Type != t {
			return ""
		}
	}
	return t
}

// buildKubeClientConfig resolves a kubeconfig from the first source
// available, in priority order:
//
//  1. Explicit YAML field `sources[].kubeconfig`.
//  2. Environment variable `KUBECONFIG`.
//  3. In-cluster ServiceAccount (when running inside a Pod).
//  4. `$HOME/.kube/config`.
//
// Each attempted source is logged so the resolution path is visible
// when troubleshooting auth or unexpected cluster targeting.
func buildKubeClientConfig(kubeconfig string, logger *slog.Logger) (*rest.Config, error) {
	if kubeconfig != "" {
		logger.Info("loading kubeconfig", "from", "explicit", "path", kubeconfig)
		return clientcmd.BuildConfigFromFlags("", kubeconfig)
	}
	if env := os.Getenv("KUBECONFIG"); env != "" {
		logger.Info("loading kubeconfig", "from", "KUBECONFIG", "path", env)
		return clientcmd.BuildConfigFromFlags("", env)
	}
	logger.Info("loading kubeconfig", "from", "in-cluster")
	if cfg, err := rest.InClusterConfig(); err == nil {
		return cfg, nil
	} else if !errors.Is(err, rest.ErrNotInCluster) {
		logger.Debug("in-cluster lookup failed, falling through", "err", err)
	}
	if home, _ := os.UserHomeDir(); home != "" {
		path := home + "/.kube/config"
		if _, err := os.Stat(path); err == nil {
			logger.Info("loading kubeconfig", "from", "home", "path", path)
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
