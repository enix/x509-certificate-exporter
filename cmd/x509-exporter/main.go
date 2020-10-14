package main

import (
	exporter "enix.io/x509-exporter/internal"
	getopt "github.com/pborman/getopt/v2"
	log "github.com/sirupsen/logrus"
)

type stringArrayFlag []string

func (s *stringArrayFlag) Set(value string, option getopt.Option) error {
	*s = append(*s, value)
	return nil
}

func (s *stringArrayFlag) String() string {
	return ""
}

func main() {
	help := getopt.BoolLong("help", 'h', "show this help message and exit")
	port := getopt.IntLong("port", 'p', 9090, "prometheus exporter listening port")
	debug := getopt.BoolLong("debug", 0, "enable debug mode")
	trimPathComponents := getopt.IntLong("trim-path-components", 0, 0, "remove <n> leading component(s) from path(s) in label(s)")

	files := stringArrayFlag{}
	getopt.FlagLong(&files, "watch-file", 'f', "watch one or more x509 certificate file")

	directories := stringArrayFlag{}
	getopt.FlagLong(&directories, "watch-dir", 'd', "watch one or more directory which contains x509 certificate files")

	kubeconfigs := stringArrayFlag{}
	getopt.FlagLong(&kubeconfigs, "watch-kubeconf", 'k', "watch one or more Kubernetes client configuration (kind Config) which contains embedded x509 certificates or PEM file paths")

	getopt.Parse()

	if *help {
		getopt.Usage()
		return
	}

	if len(files)+len(directories)+len(kubeconfigs) == 0 {
		log.Warn("no watch path(s) were specified")
		getopt.Usage()
		return
	}

	log.SetFormatter(&log.TextFormatter{
		DisableColors: false,
		FullTimestamp: true,
	})

	if *debug {
		log.SetLevel(log.DebugLevel)
	}

	exporter := exporter.Exporter{
		Port:               *port,
		Files:              files,
		Directories:        directories,
		YAMLs:              kubeconfigs,
		YAMLPaths:          exporter.DefaultYamlPaths,
		TrimPathComponents: *trimPathComponents,
	}

	exporter.ListenAndServe()
}
