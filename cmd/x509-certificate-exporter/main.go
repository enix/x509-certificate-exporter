package main

import (
	"fmt"
	"os"
	"path"

	"enix.io/x509-certificate-exporter/internal"
	getopt "github.com/pborman/getopt/v2"
	log "github.com/sirupsen/logrus"
)

type stringArrayFlag []string

func (s *stringArrayFlag) Set(value string, _ getopt.Option) error {
	*s = append(*s, value)
	return nil
}

func (s *stringArrayFlag) String() string {
	return ""
}

func main() {
	help := getopt.BoolLong("help", 'h', "show this help message and exit")
	version := getopt.BoolLong("version", 'v', "show version info and exit")
	port := getopt.IntLong("port", 'p', 9793, "prometheus exporter listening port")
	debug := getopt.BoolLong("debug", 0, "enable debug mode")
	trimPathComponents := getopt.IntLong("trim-path-components", 0, 0, "remove <n> leading component(s) from path(s) in label(s)")

	files := stringArrayFlag{}
	getopt.FlagLong(&files, "watch-file", 'f', "watch one or more x509 certificate file")

	directories := stringArrayFlag{}
	getopt.FlagLong(&directories, "watch-dir", 'd', "watch one or more directory which contains x509 certificate files (not recursive)")

	yamls := stringArrayFlag{}
	getopt.FlagLong(&yamls, "watch-kubeconf", 'k', "watch one or more Kubernetes client configuration (kind Config) which contains embedded x509 certificates or PEM file paths")

	kubeEnabled := getopt.BoolLong("watch-kube-secrets", 0, "scrape kubernetes.io/tls secrets and monitor them")

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
		Port:               *port,
		Files:              files,
		Directories:        directories,
		YAMLs:              yamls,
		YAMLPaths:          internal.DefaultYamlPaths,
		TrimPathComponents: *trimPathComponents,

		KubeIncludeNamespaces: kubeIncludeNamespaces,
		KubeExcludeNamespaces: kubeExcludeNamespaces,
		KubeIncludeLabels:     kubeIncludeLabels,
		KubeExcludeLabels:     kubeExcludeLabels,
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
	exporter.ListenAndServe()
}
