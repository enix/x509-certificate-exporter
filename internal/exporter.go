package exporter

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"path"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
)

// Exporter : Main configuration parsed from command-line
type Exporter struct {
	Port        int
	Files       []string
	Directories []string
	Kubeconfigs []string

	collector collector
}

// Run : Start exporter and listen for requests
func (exporter *Exporter) Run() {
	exporter.discoverCertificates()

	prometheus.MustRegister(&exporter.collector)
	http.Handle("/metrics", promhttp.Handler())

	listen := fmt.Sprintf(":%d", exporter.Port)
	log.Infof("listening on %s", listen)
	http.ListenAndServe(listen, nil)
}

func (exporter *Exporter) discoverCertificates() {
	exporter.collector.certificates = []string{}

	for _, file := range exporter.Files {
		exporter.checkAndRegisterCertificate(file)
	}

	for _, dir := range exporter.Directories {
		files, err := ioutil.ReadDir(dir)
		if err != nil {
			log.Debug(err)
			log.Warnf("failed to open directory \"%s\", ignoring it", dir)
			continue
		}

		for _, file := range files {
			if file.IsDir() {
				continue
			}

			exporter.checkAndRegisterCertificate(path.Join(dir, file.Name()))
		}
	}

	exporter.collector.certificates = unique(exporter.collector.certificates)
}

func (exporter *Exporter) checkAndRegisterCertificate(path string) {
	_, err := parseCertificate(path)

	if err == nil {
		log.Infof("valid certificate found \"%s\"", path)
		exporter.collector.certificates = append(exporter.collector.certificates, path)
	} else {
		log.Warnf("failed to load \"%s\", ignoring it", path)
	}
}

func parseCertificate(path string) (*x509.Certificate, error) {
	contents, err := ioutil.ReadFile(path)
	if err != nil {
		log.Debug(err)
		return nil, err
	}

	block, rest := pem.Decode(contents)
	if len(rest) > 0 {
		return nil, fmt.Errorf("failed to parse PEM file \"%s\"", path)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Debug(err)
		return nil, err
	}

	return cert, nil
}
