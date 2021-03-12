package internal

import (
	"crypto/x509/pkix"
	"fmt"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
)

type collector struct {
	exporter *Exporter
}

var (
	certExpiredMetric = "x509_cert_expired"
	certExpiredHelp   = "Indicates if the certificate is expired"
	certExpiredDesc   = prometheus.NewDesc(certExpiredMetric, certExpiredHelp, nil, nil)

	certNotBeforeMetric = "x509_cert_not_before"
	certNotBeforeHelp   = "Indicates the certificate's not before timestamp"
	certNotBeforeDesc   = prometheus.NewDesc(certNotBeforeMetric, certNotBeforeHelp, nil, nil)

	certNotAfterMetric = "x509_cert_not_after"
	certNotAfterHelp   = "Indicates the certificate's not after timestamp"
	certNotAfterDesc   = prometheus.NewDesc(certNotAfterMetric, certNotAfterHelp, nil, nil)

	certErrorsMetric = "x509_read_errors"
	certErrorsHelp   = "Indicates the number of read failure(s)"
	certErrorsDesc   = prometheus.NewDesc(certErrorsMetric, certErrorsHelp, nil, nil)

	certTimestampMetric = "x509_read_timestamp"
	certTimestampHelp   = "Indicates the read timestamp"
	certTimestampDesc   = prometheus.NewDesc(certTimestampMetric, certTimestampHelp, nil, nil)
)

func (collector *collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- certExpiredDesc
	ch <- certNotBeforeDesc
	ch <- certNotAfterDesc
	ch <- certErrorsDesc
	ch <- certTimestampDesc
}

func (collector *collector) Collect(ch chan<- prometheus.Metric) {
	certRefs, certErrors := collector.exporter.parseAllCertificates()

	for index, err := range certErrors {
		if err.err != nil {
			log.Debugf("read error %d: %+v", index+1, err.err)
		} else {
			log.Debugf("read error %d (unknown) on %s", index+1, err.ref.path)
		}
	}

	for _, certRef := range certRefs {
		for _, cert := range certRef.certificates {
			metrics := collector.getMetricsForCertificate(cert, certRef)
			for _, metric := range metrics {
				ch <- metric
			}
		}
	}

	ch <- prometheus.MustNewConstMetric(
		certErrorsDesc,
		prometheus.GaugeValue,
		float64(len(certErrors)),
	)

	ch <- prometheus.MustNewConstMetric(
		certTimestampDesc,
		prometheus.GaugeValue,
		float64(time.Now().Unix()),
	)
}

func (collector *collector) getMetricsForCertificate(certData *parsedCertificate, ref *certificateRef) []prometheus.Metric {
	var trimmedFilePath string
	baseLabels := []string{"serial_number"}

	if ref.format != certificateFormatKubeSecret {
		trimComponentsCount := collector.exporter.TrimPathComponents
		pathComponents := strings.Split(ref.path, "/")
		prefix := ""
		if pathComponents[0] == "" {
			trimComponentsCount++
			prefix = "/"
		}
		trimmedFilePath = path.Join(prefix, path.Join(pathComponents[trimComponentsCount:]...))
		baseLabels = append(baseLabels, "filename", "filepath")
	} else {
		trimmedFilePath = strings.Split(ref.path, "/")[1]
		baseLabels = append(baseLabels, "secret_name", "secret_namespace", "secret_key")
	}

	baseLabelsValue := []string{
		certData.cert.SerialNumber.String(),
		filepath.Base(ref.path),
		trimmedFilePath,
	}

	if ref.format == certificateFormatKubeSecret {
		baseLabelsValue = append(baseLabelsValue, ref.kubeSecretKey)
	}

	issuerLabels, issuerLabelsValue := getLabelsFromName(&certData.cert.Issuer, "issuer")
	subjectLabels, subjectLabelsValue := getLabelsFromName(&certData.cert.Subject, "subject")
	labels := append(baseLabels, append(issuerLabels, subjectLabels...)...)
	labelsValue := append(baseLabelsValue, append(issuerLabelsValue, subjectLabelsValue...)...)

	if ref.format == certificateFormatYAML {
		kind := strings.Split(certData.yqMatchExpr, ".")[1]
		labels = append(labels, "embedded_kind")
		labelsValue = append(labelsValue, strings.TrimRight(kind, "s"))
	}

	if len(certData.userID) > 0 {
		labels = append(labels, "embedded_key")
		labelsValue = append(labelsValue, certData.userID)
	}

	expired := 0.
	if time.Now().Unix() > certData.cert.NotAfter.Unix() {
		expired = 1.
	}

	return []prometheus.Metric{
		prometheus.MustNewConstMetric(
			prometheus.NewDesc(certExpiredMetric, certExpiredHelp, labels, nil),
			prometheus.GaugeValue,
			expired,
			labelsValue...,
		),
		prometheus.MustNewConstMetric(
			prometheus.NewDesc(certNotBeforeMetric, certNotBeforeHelp, labels, nil),
			prometheus.GaugeValue,
			float64(certData.cert.NotBefore.Unix()),
			labelsValue...,
		),
		prometheus.MustNewConstMetric(
			prometheus.NewDesc(certNotAfterMetric, certNotAfterHelp, labels, nil),
			prometheus.GaugeValue,
			float64(certData.cert.NotAfter.Unix()),
			labelsValue...,
		),
	}
}

func getLabelsFromName(name *pkix.Name, prefix string) (labels []string, labelsValue []string) {
	labels = []string{}
	labelsValue = []string{}

	if len(name.Country) > 0 {
		labels = append(labels, fmt.Sprintf("%s_C", prefix))
		labelsValue = append(labelsValue, name.Country[0])
	}
	if len(name.StreetAddress) > 0 {
		labels = append(labels, fmt.Sprintf("%s_ST", prefix))
		labelsValue = append(labelsValue, name.StreetAddress[0])
	}
	if len(name.Locality) > 0 {
		labels = append(labels, fmt.Sprintf("%s_L", prefix))
		labelsValue = append(labelsValue, name.Locality[0])
	}
	if len(name.Organization) > 0 {
		labels = append(labels, fmt.Sprintf("%s_O", prefix))
		labelsValue = append(labelsValue, name.Organization[0])
	}
	if len(name.OrganizationalUnit) > 0 {
		labels = append(labels, fmt.Sprintf("%s_OU", prefix))
		labelsValue = append(labelsValue, name.OrganizationalUnit[0])
	}
	if len(name.CommonName) > 0 {
		labels = append(labels, fmt.Sprintf("%s_CN", prefix))
		labelsValue = append(labelsValue, name.CommonName)
	}

	return
}
