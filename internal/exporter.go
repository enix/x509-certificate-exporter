package internal

import (
	"context"
	"crypto/x509/pkix"
	"fmt"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/patrickmn/go-cache"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/prometheus/common/promlog"
	"github.com/prometheus/exporter-toolkit/web"
	log "github.com/sirupsen/logrus"
	"k8s.io/client-go/kubernetes"
)

// Exporter : Configuration (from command-line)
type Exporter struct {
	ListenAddress         string
	SystemdSocket         *bool
	ConfigFile            *string
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

	toolkitFlags := web.FlagConfig{
		WebListenAddresses: &[]string{exporter.ListenAddress},
		WebSystemdSocket:   exporter.SystemdSocket,
		WebConfigFile:      exporter.ConfigFile,
	}

	promlogConfig := &promlog.Config{}
	logger := promlog.New(promlogConfig)

	return web.Serve(exporter.listener, exporter.server, &toolkitFlags, logger)
}

// Shutdown : Properly tear down server
func (exporter *Exporter) Shutdown() error {
	if exporter.server != nil {
		return exporter.server.Shutdown(context.Background())
	}

	return nil
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

		for _, existingCertRef := range output {
		checkCertificatePair:
			for existingParsedCertIndex, existingParsedCert := range existingCertRef.certificates {
				for parsedCertIndex, parsedCert := range cert.certificates {
					if parsedCert.cert == existingParsedCert.cert {
						continue
					}

					if exporter.compareCertificates(parsedCert, cert, existingParsedCert, existingCertRef) {
						cert.certificates = append(cert.certificates[:parsedCertIndex], cert.certificates[parsedCertIndex+1:]...)
						raiseError(&certificateError{
							ref: cert,
							err: fmt.Errorf(
								"duplicate certificate: cert n°%d in \"%s\" and cert n°%d in \"%s\"",
								parsedCertIndex+1,
								cert.path,
								existingParsedCertIndex+1,
								existingCertRef.path,
							),
						})

						goto checkCertificatePair
					}
				}
			}
		}
	}

	return output, outputErrors
}

func (exporter *Exporter) compareCertificates(
	leftCert *parsedCertificate,
	leftRef *certificateRef,
	rightCert *parsedCertificate,
	rightRef *certificateRef,
) bool {
	lhsLabels := exporter.getLabels(leftCert, leftRef)
	rhsLabels := exporter.getLabels(rightCert, rightRef)

	if len(lhsLabels) != len(rhsLabels) {
		return false
	}

	for key, value := range lhsLabels {
		if rhsLabels[key] != value {
			return false
		}
	}

	return true
}

func (exporter *Exporter) getLabels(certData *parsedCertificate, ref *certificateRef) map[string]string {
	labels := exporter.getBaseLabels(ref)

	labels["serial_number"] = certData.cert.SerialNumber.String()
	fillLabelsFromName(&certData.cert.Issuer, "issuer", labels)
	fillLabelsFromName(&certData.cert.Subject, "subject", labels)

	if ref.format == certificateFormatYAML {
		kind := strings.Split(certData.yqMatchExpr, ".")[1]
		labels["embedded_kind"] = strings.TrimRight(kind, "s")
	}

	if len(certData.userID) > 0 {
		labels["embedded_key"] = certData.userID
	}

	return labels
}

func (exporter *Exporter) getBaseLabels(ref *certificateRef) map[string]string {
	labels := map[string]string{}

	if ref.format != certificateFormatKubeSecret {
		trimComponentsCount := exporter.TrimPathComponents
		pathComponents := strings.Split(ref.path, "/")
		prefix := ""
		if pathComponents[0] == "" {
			trimComponentsCount++
			prefix = "/"
		}

		labels["filename"] = filepath.Base(ref.path)
		labels["filepath"] = path.Join(prefix, path.Join(pathComponents[trimComponentsCount:]...))
	} else {
		labels["secret_name"] = filepath.Base(ref.path)
		labels["secret_namespace"] = strings.Split(ref.path, "/")[1]
		labels["secret_key"] = ref.kubeSecretKey
	}

	return labels
}

func (exporter *Exporter) unzipLabels(labels map[string]string) ([]string, []string) {
	labelKeys := []string{}
	labelValues := []string{}

	for key, value := range labels {
		if exporter.ExposeLabels == nil {
			labelKeys = append(labelKeys, key)
			labelValues = append(labelValues, value)
			continue
		}

		for _, label := range exporter.ExposeLabels {
			if label == key {
				labelKeys = append(labelKeys, key)
				labelValues = append(labelValues, value)
			}
		}
	}

	return labelKeys, labelValues
}

func fillLabelsFromName(name *pkix.Name, prefix string, output map[string]string) {
	if len(name.Country) > 0 {
		output[fmt.Sprintf("%s_C", prefix)] = name.Country[0]
	}

	if len(name.StreetAddress) > 0 {
		output[fmt.Sprintf("%s_ST", prefix)] = name.StreetAddress[0]
	}

	if len(name.Locality) > 0 {
		output[fmt.Sprintf("%s_L", prefix)] = name.Locality[0]
	}

	if len(name.Organization) > 0 {
		output[fmt.Sprintf("%s_O", prefix)] = name.Organization[0]
	}

	if len(name.OrganizationalUnit) > 0 {
		output[fmt.Sprintf("%s_OU", prefix)] = name.OrganizationalUnit[0]
	}

	if len(name.CommonName) > 0 {
		output[fmt.Sprintf("%s_CN", prefix)] = name.CommonName
	}
}
