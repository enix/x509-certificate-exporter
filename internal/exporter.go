package internal

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path"
	"time"

	"github.com/patrickmn/go-cache"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
	"k8s.io/client-go/kubernetes"
)

// Exporter : Configuration (from command-line)
type Exporter struct {
	ListenAddress         string
	Files                 []string
	Directories           []string
	YAMLs                 []string
	YAMLPaths             []YAMLCertRef
	TrimPathComponents    int
	MaxCacheDuration      time.Duration
	ExposeRelativeMetrics bool
	ExposeErrorMetrics    bool
	ExposeLabels          []string
	KubeSecretTypes       []string
	KubeIncludeNamespaces []string
	KubeExcludeNamespaces []string
	KubeIncludeLabels     []string
	KubeExcludeLabels     []string

	kubeClient   *kubernetes.Clientset
	listener     net.Listener
	handler      *http.Handler
	server       *http.Server
	isDiscovery  bool
	secretsCache *cache.Cache
}

// ListenAndServe : Convenience function to start exporter
func (exporter *Exporter) ListenAndServe() error {
	exporter.DiscoverCertificates()

	if err := exporter.Listen(); err != nil {
		return err
	}

	return exporter.Serve()
}

// Listen : Listen for requests
func (exporter *Exporter) Listen() error {
	err := prometheus.Register(&collector{exporter: exporter})
	if err != nil {
		if registered, ok := err.(prometheus.AlreadyRegisteredError); ok {
			prometheus.Unregister(registered.ExistingCollector)
			prometheus.MustRegister(&collector{exporter: exporter})
		} else {
			return err
		}
	}

	log.Infof("listening on %s", exporter.ListenAddress)

	listener, err := net.Listen("tcp", exporter.ListenAddress)
	if err != nil {
		return err
	}

	exporter.listener = listener
	return nil
}

// Serve : Actually reply to requests
func (exporter *Exporter) Serve() error {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())

	exporter.server = &http.Server{
		Handler: mux,
	}

	return exporter.server.Serve(exporter.listener)
}

// Shutdown : Properly tear down server
func (exporter *Exporter) Shutdown() error {
	return exporter.server.Shutdown(context.Background())
}

// DiscoverCertificates : Parse all certs in a dry run with verbose logging
func (exporter *Exporter) DiscoverCertificates() {
	exporter.secretsCache = cache.New(exporter.MaxCacheDuration, 5*time.Minute)
	exporter.isDiscovery = true
	certs, errs := exporter.parseAllCertificates()

	certCount := 0
	for _, cert := range certs {
		certCount += len(cert.certificates)
	}
	log.Infof("parsed %d certificates (%d read failures)", certCount, len(errs))

	exporter.isDiscovery = false
}

func (exporter *Exporter) parseAllCertificates() ([]*certificateRef, []*certificateError) {
	output := []*certificateRef{}
	outputErrors := []*certificateError{}
	raiseError := func(err *certificateError) {
		outputErrors = append(outputErrors, err)
		if exporter.isDiscovery && err.err != nil {
			log.Warn(err.err)
		}
	}

	for _, file := range exporter.Files {
		output = append(output, &certificateRef{
			path:   path.Clean(file),
			format: certificateFormatPEM,
		})
	}

	for _, file := range exporter.YAMLs {
		output = append(output, &certificateRef{
			path:      path.Clean(file),
			format:    certificateFormatYAML,
			yamlPaths: exporter.YAMLPaths,
		})
	}

	for _, dir := range exporter.Directories {
		files, err := os.ReadDir(dir)
		if err != nil {
			raiseError(&certificateError{
				err: fmt.Errorf("failed to open directory \"%s\", %s", dir, err.Error()),
			})

			continue
		}

		for _, file := range files {
			if file.IsDir() {
				continue
			}

			output = append(output, &certificateRef{
				path:   path.Clean(path.Join(dir, file.Name())),
				format: certificateFormatPEM,
			})
		}
	}

	if exporter.kubeClient != nil {
		certs, errs := exporter.parseAllKubeSecrets()
		output = append(output, certs...)
		for _, err := range errs {
			raiseError(&certificateError{
				err: err,
			})
		}
	}

	output = unique(output)
	for _, cert := range output {
		err := cert.parse()

		if err != nil || len(cert.certificates) == 0 {
			if err != nil {
				err = fmt.Errorf("failed to parse \"%s\", %s", cert.path, err.Error())
			} else {
				err = fmt.Errorf("no certificate(s) found in \"%s\"", cert.path)
			}

			raiseError(&certificateError{
				err: err,
				ref: cert,
			})
		} else if exporter.isDiscovery {
			log.Infof("%d valid certificate(s) found in \"%s\"", len(cert.certificates), cert.path)
		}
	}

	return output, outputErrors
}
