package exporter

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os/exec"
	"path"
	"path/filepath"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
)

// Exporter : Main configuration parsed from command-line
type Exporter struct {
	Port        int
	Files       []string
	Directories []string
	YAMLs       []string
	YAMLPaths   []YAMLCertRef

	listener net.Listener
	handler  *http.Handler
	server   *http.Server
}

// YAMLCertRef : Contains information to access certificates in yaml files
type YAMLCertRef struct {
	CertMatchExpr string
	IDMatchExpr   string
	Format        YAMLCertFormat
}

// YAMLCertFormat : Type of cert encoding in YAML files
type YAMLCertFormat int

// YAMLCertFormat : Impl
const (
	YAMLCertFormatFile   YAMLCertFormat = iota
	YAMLCertFormatBase64                = iota
)

// DefaultYamlPaths : Pre-written paths for some k8s config files
var DefaultYamlPaths = []YAMLCertRef{
	{
		CertMatchExpr: "clusters.[*].cluster.certificate-authority-data",
		IDMatchExpr:   "clusters.[*].name",
		Format:        YAMLCertFormatBase64,
	},
	{
		CertMatchExpr: "clusters.[*].cluster.certificate-authority",
		IDMatchExpr:   "clusters.[*].name",
		Format:        YAMLCertFormatFile,
	},
	{
		CertMatchExpr: "users.[*].user.client-certificate-data",
		IDMatchExpr:   "users.[*].name",
		Format:        YAMLCertFormatBase64,
	},
	{
		CertMatchExpr: "users.[*].user.client-certificate",
		IDMatchExpr:   "users.[*].name",
		Format:        YAMLCertFormatFile,
	},
}

type certificateRef struct {
	path         string
	format       certificateFormat
	yamlPaths    []YAMLCertRef
	certificates []*parsedCertificate
	userIDs      []string
}

type parsedCertificate struct {
	cert        *x509.Certificate
	userID      string
	yqMatchExpr string
}

type certificateFormat int

const (
	certificateFormatPEM  certificateFormat = iota
	certificateFormatYAML                   = iota
)

var isDiscovery = false

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
		}
	}

	listen := fmt.Sprintf(":%d", exporter.Port)
	log.Infof("listening on %s", listen)

	listener, err := net.Listen("tcp", listen)
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
	return exporter.server.Shutdown(context.TODO())
}

// DiscoverCertificates : Parse all certs in a dry run with verbose logging
func (exporter *Exporter) DiscoverCertificates() {
	isDiscovery = true
	exporter.parseAllCertificates()
	isDiscovery = false
}

func (exporter *Exporter) parseAllCertificates() []*certificateRef {
	output := []*certificateRef{}

	for _, file := range exporter.Files {
		output = append(output, &certificateRef{
			path:   file,
			format: certificateFormatPEM,
		})
	}

	for _, file := range exporter.YAMLs {
		output = append(output, &certificateRef{
			path:      file,
			format:    certificateFormatYAML,
			yamlPaths: exporter.YAMLPaths,
		})
	}

	for _, dir := range exporter.Directories {
		files, err := ioutil.ReadDir(dir)
		if err != nil {
			if isDiscovery {
				log.Warnf("failed to open directory \"%s\", %s", dir, err.Error())
			}
			continue
		}

		for _, file := range files {
			if file.IsDir() {
				continue
			}

			output = append(output, &certificateRef{
				path:   path.Join(dir, file.Name()),
				format: certificateFormatPEM,
			})
		}
	}

	output = unique(output)
	for _, cert := range output {
		err := cert.parse()

		if !isDiscovery {
			continue
		}

		if err != nil {
			log.Warnf("failed to load \"%s\", %s", cert.path, err.Error())
		} else if len(cert.certificates) == 0 {
			log.Warnf("no certificate(s) found in \"%s\"", cert.path)
		} else {
			log.Infof("%d valid certificate(s) found in \"%s\"", len(cert.certificates), cert.path)
		}
	}

	return output
}

func (cert *certificateRef) parse() error {
	var err error

	switch cert.format {
	case certificateFormatPEM:
		cert.certificates, err = readAndParsePEMFile(cert.path)
	case certificateFormatYAML:
		cert.certificates, err = readAndParseYAMLFile(cert.path, cert.yamlPaths)
	}

	return err
}

func readAndParsePEMFile(path string) ([]*parsedCertificate, error) {
	contents, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	output := []*parsedCertificate{}
	certs, err := parsePEM(contents)
	if err != nil {
		return nil, err
	}

	for _, cert := range certs {
		output = append(output, &parsedCertificate{cert: cert})
	}

	return output, nil
}

func readAndParseYAMLFile(filePath string, yamlPaths []YAMLCertRef) ([]*parsedCertificate, error) {
	output := []*parsedCertificate{}

	for _, exprs := range yamlPaths {
		rawCerts, err := exec.Command("yq", "r", filePath, exprs.CertMatchExpr).CombinedOutput()
		if err != nil {
			return nil, errors.New(err.Error() + " | stderr: " + string(rawCerts))
		}
		if len(rawCerts) == 0 {
			continue
		}

		var decodedCerts []byte
		if exprs.Format == YAMLCertFormatBase64 {
			decodedCerts = make([]byte, base64.StdEncoding.DecodedLen(len(rawCerts)))
			base64.StdEncoding.Decode(decodedCerts, []byte(rawCerts))
		} else if exprs.Format == YAMLCertFormatFile {
			certPath := path.Join(filepath.Dir(filePath), string(rawCerts))
			decodedCerts, err = ioutil.ReadFile(strings.TrimRight(certPath, "\n"))
			if err != nil {
				if isDiscovery {
					log.Warn(err)
				}
				continue
			}
		}

		certs, err := parsePEM(decodedCerts)
		if err != nil {
			return nil, err
		}

		rawUserIDs, _ := exec.Command("yq", "r", filePath, exprs.IDMatchExpr).Output()
		userIDs := strings.Split(string(rawUserIDs), "\n")
		if len(userIDs) != len(certs) {
			log.Warnf("failed to parse some labels in %s (yq returned nothing for \"%s\")", filePath, exprs.IDMatchExpr)
		}

		for index, cert := range certs {
			output = append(output, &parsedCertificate{
				cert:        cert,
				userID:      userIDs[index],
				yqMatchExpr: exprs.CertMatchExpr,
			})
		}
	}

	return output, nil
}

func parsePEM(data []byte) ([]*x509.Certificate, error) {
	output := []*x509.Certificate{}

	for {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			log.Warnf("tried to parse malformed x509 data, %s", err.Error())
			return nil, err
		}

		output = append(output, cert)
		data = rest
	}

	return output, nil
}
