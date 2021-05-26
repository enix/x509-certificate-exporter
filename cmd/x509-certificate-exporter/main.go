package main

import (
	"fmt"
	"math/rand"
	"os"
	"path"
	"strings"
	"time"

	"enix.io/x509-certificate-exporter/internal"
	getopt "github.com/pborman/getopt/v2"
	log "github.com/sirupsen/logrus"
)

func main() {
	help := getopt.BoolLong("help", 'h', "show this help message and exit")
	version := getopt.BoolLong("version", 'v', "show version info and exit")
	port := getopt.IntLong("port", 'p', 9793, "prometheus exporter listening port")
	debug := getopt.BoolLong("debug", 0, "enable debug mode")
	trimPathComponents := getopt.IntLong("trim-path-components", 0, 0, "remove <n> leading component(s) from path(s) in label(s)")
	exposeRelativeMetrics := getopt.BoolLong("expose-relative-metrics", 0, "expose additionnal metrics with relative durations instead of absolute timestamps")
	exposeLabels := getopt.StringLong("expose-labels", 'l', "one or more comma-separated labels to enable (defaults to all if not specified)")

	maxCacheDuration := durationFlag(0)
	getopt.FlagLong(&maxCacheDuration, "max-cache-duration", 0, "maximum cache duration for kube secrets. cache is per namespace and randomized to avoid massive requests.")

	files := stringArrayFlag{}
	getopt.FlagLong(&files, "watch-file", 'f', "watch one or more x509 certificate file")

	directories := stringArrayFlag{}
	getopt.FlagLong(&directories, "watch-dir", 'd', "watch one or more directory which contains x509 certificate files (not recursive)")

	yamls := stringArrayFlag{}
	getopt.FlagLong(&yamls, "watch-kubeconf", 'k', "watch one or more Kubernetes client configuration (kind Config) which contains embedded x509 certificates or PEM file paths")

	kubeEnabled := getopt.BoolLong("watch-kube-secrets", 0, "scrape kubernetes.io/tls secrets and monitor them")

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

	if *debug {
		log.SetLevel(log.DebugLevel)
	}

	exporter := internal.Exporter{
		Port:                  *port,
		Files:                 files,
		Directories:           directories,
		YAMLs:                 yamls,
		YAMLPaths:             internal.DefaultYamlPaths,
		TrimPathComponents:    *trimPathComponents,
		MaxCacheDuration:      time.Duration(maxCacheDuration),
		ExposeRelativeMetrics: *exposeRelativeMetrics,
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
		err := exporter.ConnectToKubernetesCluster("")
		if err != nil {
			log.Warn(err)

			err = exporter.ConnectToKubernetesCluster(path.Join(os.Getenv("HOME"), ".kube/config"))
			if err != nil {
				log.Fatal(err)
			}
		}
	}

	log.Infof("starting %s version %s", path.Base(os.Args[0]), internal.Version)
	rand.Seed(time.Now().UnixNano())
	exporter.ListenAndServe()
}
