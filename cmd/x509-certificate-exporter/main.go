package main

import (
	"fmt"
	"math/rand"
	"net/http"
	_ "net/http/pprof"
	"os"
	"path"
	"runtime"
	"strings"
	"time"

	"github.com/enix/x509-certificate-exporter/v3/internal"
	getopt "github.com/pborman/getopt/v2"
	log "github.com/sirupsen/logrus"
)

func main() {
	help := getopt.BoolLong("help", 'h', "show this help message and exit")
	version := getopt.BoolLong("version", 'v', "show version info and exit")

	listenAddress := getopt.StringLong("listen-address", 'b', ":9793", "address on which to bind and expose metrics")
	systemdSocket := func() *bool { b := false; return &b }() // Socket activation only available on Linux
	if runtime.GOOS == "linux" {
		systemdSocket = getopt.BoolLong("web.systemd-socket", 0, "use systemd socket activation listeners instead of port listeners (Linux only)")
	}
	configFile := getopt.StringLong("web.config.file", 0, "", "[EXPERIMENTAL] path to configuration file that can enable TLS or authentication")

	debug := getopt.BoolLong("debug", 0, "enable debug mode")
	trimPathComponents := getopt.IntLong("trim-path-components", 0, 0, "remove <n> leading component(s) from path(s) in label(s)")
	exposeRelativeMetrics := getopt.BoolLong("expose-relative-metrics", 0, "expose additionnal metrics with relative durations instead of absolute timestamps")
	exposeErrorMetrics := getopt.BoolLong("expose-per-cert-error-metrics", 0, "expose additionnal error metric for each certificate indicating wether it has failure(s)")
	exposeLabels := getopt.StringLong("expose-labels", 'l', "one or more comma-separated labels to enable (defaults to all if not specified)")
	profile := getopt.BoolLong("profile", 0, "optionally enable a pprof server to monitor cpu and memory usage at runtime")

	maxCacheDuration := durationFlag(0)
	getopt.FlagLong(&maxCacheDuration, "max-cache-duration", 0, "maximum cache duration for kube secrets. cache is per namespace and randomized to avoid massive requests.")

	files := stringArrayFlag{}
	getopt.FlagLong(&files, "watch-file", 'f', "watch one or more x509 certificate file")

	directories := stringArrayFlag{}
	getopt.FlagLong(&directories, "watch-dir", 'd', "watch one or more directory which contains x509 certificate files (not recursive)")

	yamls := stringArrayFlag{}
	getopt.FlagLong(&yamls, "watch-kubeconf", 'k', "watch one or more Kubernetes client configuration (kind Config) which contains embedded x509 certificates or PEM file paths")

	kubeEnabled := getopt.BoolLong("watch-kube-secrets", 0, "scrape kubernetes secrets and monitor them")

	kubeConfig := getopt.StringLong("kubeconfig", 0, "", "Path to the kubeconfig file to use for requests. Takes precedence over the KUBECONFIG environment variable, and default path (~/.kube/config).", "path")

	kubeSecretTypes := stringArrayFlag{}
	getopt.FlagLong(&kubeSecretTypes, "secret-type", 's', "one or more kubernetes secret type & key to watch (e.g. \"kubernetes.io/tls:tls.crt\"")

	kubeIncludeNamespaces := stringArrayFlag{}
	getopt.FlagLong(&kubeIncludeNamespaces, "include-namespace", 0, "add the given kube namespace to the watch list (when used, all namespaces are excluded by default)")

	kubeExcludeNamespaces := stringArrayFlag{}
	getopt.FlagLong(&kubeExcludeNamespaces, "exclude-namespace", 0, "removes the given kube namespace from the watch list (applied after --include-namespace)")

	kubeIncludeLabels := stringArrayFlag{}
	getopt.FlagLong(&kubeIncludeLabels, "include-label", 0, "add the kube secrets with the given label (or label value if specified) to the watch list (when used, all secrets are excluded by default)")

	kubeExcludeLabels := stringArrayFlag{}
	getopt.FlagLong(&kubeExcludeLabels, "exclude-label", 0, "removes the kube secrets with the given label (or label value if specified) from the watch list (applied after --include-label)")

	getopt.Parse()

	if *help {
		getopt.Usage()
		return
	}

	if *version {
		fmt.Fprintf(os.Stderr, "version %s\n", internal.Version)
		return
	}

	log.Infof("starting %s version %s (%s) (%s)", path.Base(os.Args[0]), internal.Version, internal.Revision, internal.BuildDateTime)

	if *debug {
		log.SetLevel(log.DebugLevel)
	}

	if *profile {
		go func() {
			log.Infoln("pprof server listening on :6060")
			err := http.ListenAndServe(":6060", nil)
			if err != nil {
				log.Fatal(err)
			}
		}()
	}

	exporter := internal.Exporter{
		ListenAddress:         *listenAddress,
		SystemdSocket:         *systemdSocket,
		ConfigFile:            *configFile,
		Files:                 files,
		Directories:           directories,
		YAMLs:                 yamls,
		YAMLPaths:             internal.DefaultYamlPaths,
		TrimPathComponents:    *trimPathComponents,
		MaxCacheDuration:      time.Duration(maxCacheDuration),
		ExposeRelativeMetrics: *exposeRelativeMetrics,
		ExposeErrorMetrics:    *exposeErrorMetrics,
		KubeSecretTypes:       kubeSecretTypes,
		KubeIncludeNamespaces: kubeIncludeNamespaces,
		KubeExcludeNamespaces: kubeExcludeNamespaces,
		KubeIncludeLabels:     kubeIncludeLabels,
		KubeExcludeLabels:     kubeExcludeLabels,
	}

	if getopt.Lookup("expose-labels").Seen() {
		exporter.ExposeLabels = strings.Split(*exposeLabels, ",")
	}

	if *kubeEnabled {
		defaultKubeConfig := path.Join(os.Getenv("HOME"), ".kube", "config")
		kubeConfigEnv := os.Getenv("KUBECONFIG")

		configpath := ""
		if len(*kubeConfig) > 0 {
			configpath = *kubeConfig
		} else if len(kubeConfigEnv) > 0 {
			configpath = kubeConfigEnv
		} else if _, err := os.Stat(defaultKubeConfig); err == nil {
			configpath = defaultKubeConfig
		}

		err := exporter.ConnectToKubernetesCluster(configpath)
		if err != nil {
			log.Fatal(err)
		}
	}

	rand.Seed(time.Now().UnixNano())
	err := exporter.ListenAndServe()
	if err != nil {
		log.Fatal("failed to start server: ", err)
	}
}
