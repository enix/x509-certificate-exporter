package internal

import (
	"context"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/patrickmn/go-cache"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/prometheus/common/promlog"
	"github.com/prometheus/exporter-toolkit/web"
	log "github.com/sirupsen/logrus"
	"k8s.io/client-go/kubernetes"
)

// Exporter : Configuration (from command-line)
type Exporter struct {
	ListenAddress         string
	SystemdSocket         bool
	ConfigFile            string
	Files                 []string
	Directories           []string
	YAMLs                 []string
	YAMLPaths             []YAMLCertRef
	TrimPathComponents    int
	MaxCacheDuration      time.Duration
	ExposeRelativeMetrics bool
	ExposeErrorMetrics    bool
	ExposeLabels          []string
	KubeSecretTypes       []KubeSecretType
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

type KubeSecretType struct {
	Type   string
	Regexp *regexp.Regexp
}

func ParseSecretType(s string) (KubeSecretType, error) {
	ty, pattern, found := strings.Cut(s, ":")
	if !found {
		return KubeSecretType{}, errors.New("secret type needs to contain at least a single colon")
	}
	compiled, err := regexp.Compile(pattern)
	if err != nil {
		return KubeSecretType{}, err
	}
	return KubeSecretType{
		Type:   ty,
		Regexp: compiled,
	}, nil
}

func (kst *KubeSecretType) Matches(secretType, key string) bool {
	if kst.Type != secretType {
		return false
	}
	return kst.Regexp.MatchString(key)
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
		WebSystemdSocket:   &exporter.SystemdSocket,
		WebConfigFile:      &exporter.ConfigFile,
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
		refs, errs := exporter.collectMatchingPaths(file, certificateFormatPEM, false)

		for _, err := range errs {
			raiseError(&certificateError{
				err: fmt.Errorf("failed to parse \"%s\": %s", file, err.Error()),
			})
		}

		output = append(output, refs...)
	}

	for _, file := range exporter.YAMLs {
		refs, errs := exporter.collectMatchingPaths(file, certificateFormatYAML, false)

		for _, err := range errs {
			raiseError(&certificateError{
				err: fmt.Errorf("failed to parse \"%s\": %s", file, err.Error()),
			})
		}

		output = append(output, refs...)
	}

	for _, dir := range exporter.Directories {
		refs, errs := exporter.collectMatchingPaths(dir, certificateFormatYAML, true)

		for _, err := range errs {
			raiseError(&certificateError{
				err: fmt.Errorf("failed to parse \"%s\": %s", dir, err.Error()),
			})
		}

		output = append(output, refs...)
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

func (exporter *Exporter) collectMatchingPaths(pattern string, format certificateFormat, directories bool) ([]*certificateRef, []error) {
	output := []*certificateRef{}
	outputErrors := []error{}
	basepath, match := doublestar.SplitPattern(pattern)

	walk := func(filepath string, entry fs.DirEntry) error {
		if directories {
			if !entry.IsDir() {
				return nil
			}

			dir := path.Clean(path.Join(basepath, filepath))
			files, err := os.ReadDir(dir)
			if err != nil {
				outputErrors = append(outputErrors, err)
				return nil
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
		} else {
			output = append(output, &certificateRef{
				path:      path.Clean(path.Join(basepath, filepath)),
				format:    format,
				yamlPaths: exporter.YAMLPaths,
			})
		}

		return nil
	}

	options := []doublestar.GlobOption{
		doublestar.WithFailOnIOErrors(),
		doublestar.WithFailOnPatternNotExist(),
		doublestar.WithNoFollow(),
		doublestar.WithStatFunc(stat),
	}

	if !directories {
		options = append(options, doublestar.WithFilesOnly())
	}

	err := doublestar.GlobWalk(
		os.DirFS(basepath),
		match,
		walk,
		options...,
	)
	if err != nil {
		if errors.Is(err, doublestar.ErrPatternNotExist) {
			return nil, []error{errors.New("no files match \"" + pattern + "\"")}
		}

		return nil, []error{err}
	}

	if len(output) == 0 && len(outputErrors) == 0 {
		// the pattern evaluated to the opposite of what we want
		// i.e. we wanted files but the pattern only matched directories

		if directories {
			return nil, []error{errors.New("no directory match \"" + pattern + "\"")}
		} else {
			return nil, []error{errors.New("no files match \"" + pattern + "\"")}
		}
	}

	return output, outputErrors
}

// compareCertificates compares labels of these two certificates
// and returns true if they are the same
// It would normally run `.getLabels` on both cert/ref combinations,
// but this is a very allocation-heavy method, so we'll unroll it here
func (exporter *Exporter) compareCertificates(
	leftCert *parsedCertificate,
	leftRef *certificateRef,
	rightCert *parsedCertificate,
	rightRef *certificateRef,
) bool {
	// compare base labels
	if leftRef.format != rightRef.format {
		return false
	}
	if filepath.Base(leftRef.path) != filepath.Base(rightRef.path) {
		return false
	}
	if leftRef.format != certificateFormatKubeSecret {
		if trimComponents(leftRef.path, exporter.TrimPathComponents) != trimComponents(rightRef.path, exporter.TrimPathComponents) {
			return false
		}
	} else {
		if leftRef.kubeSecretKey != rightRef.kubeSecretKey {
			return false
		}
		// secret namespace
		if strings.Split(leftRef.path, "/")[1] != strings.Split(rightRef.path, "/")[1] {
			return false
		}
	}

	// non-base labels
	if leftCert.cert.SerialNumber.String() != rightCert.cert.SerialNumber.String() {
		return false
	}
	if !comparePkix(&leftCert.cert.Issuer, &rightCert.cert.Issuer) {
		return false
	}
	if !comparePkix(&leftCert.cert.Subject, &rightCert.cert.Subject) {
		return false
	}

	if leftRef.format == certificateFormatYAML {
		// embedded_kind
		if strings.TrimRight(strings.Split(leftCert.yqMatchExpr, ".")[1], "s") != strings.TrimRight(strings.Split(rightCert.yqMatchExpr, ".")[1], "s") {
			return false
		}
	}
	if leftCert.userID != rightCert.userID {
		return false
	}

	return true
}

func comparePkix(left *pkix.Name, right *pkix.Name) bool {
	if first(left.Country) != first(right.Country) {
		return false
	}
	if first(left.StreetAddress) != first(right.StreetAddress) {
		return false
	}
	if first(left.Locality) != first(right.Locality) {
		return false
	}
	if first(left.Organization) != first(right.Organization) {
		return false
	}
	if first(left.OrganizationalUnit) != first(right.OrganizationalUnit) {
		return false
	}
	if left.CommonName != right.CommonName {
		return false
	}

	return true
}

func first[T any](arr []T) T {
	if len(arr) == 0 {
		return *new(T)
	}
	return arr[0]
}

// getLabels : Generate metrics labels for a given certificate
// WARNING! If you update this function, please make sure that the `compareCertificates` function is updated accordingly.
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

func trimComponents(filepath string, trimCount int) string {
	if trimCount == 0 {
		return filepath
	}
	pathComponents := strings.Split(filepath, "/")
	prefix := ""
	if pathComponents[0] == "" {
		trimCount++
		prefix = "/"
	}
	return path.Join(prefix, path.Join(pathComponents[trimCount:]...))
}

func (exporter *Exporter) getBaseLabels(ref *certificateRef) map[string]string {
	labels := map[string]string{}

	if ref.format != certificateFormatKubeSecret {
		labels["filename"] = filepath.Base(ref.path)
		labels["filepath"] = trimComponents(ref.path, exporter.TrimPathComponents)
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
		output[prefix+"_C"] = name.Country[0]
	}

	if len(name.StreetAddress) > 0 {
		output[prefix+"_ST"] = name.StreetAddress[0]
	}

	if len(name.Locality) > 0 {
		output[prefix+"_L"] = name.Locality[0]
	}

	if len(name.Organization) > 0 {
		output[prefix+"_O"] = name.Organization[0]
	}

	if len(name.OrganizationalUnit) > 0 {
		output[prefix+"_OU"] = name.OrganizationalUnit[0]
	}

	if len(name.CommonName) > 0 {
		output[prefix+"_CN"] = name.CommonName
	}
}

func stat(fsys fs.FS, name string, beforeMeta bool) (fs.FileInfo, bool, error) {
	// name might end in a slash, but Stat doesn't like that
	namelen := len(name)
	if namelen > 1 && name[namelen-1] == '/' {
		name = name[:namelen-1]
	}

	info, err := fs.Stat(fsys, name)
	if errors.Is(err, fs.ErrNotExist) {
		realPath, err := resolveSymlink(fsys, name)
		if err != nil {
			return nil, false, err
		}

		info, err := fs.Stat(fsys, realPath)
		if errors.Is(err, fs.ErrNotExist) {
			return nil, false, doublestar.ErrPatternNotExist
		}

		return info, err == nil, err
	}

	return info, err == nil, err
}
