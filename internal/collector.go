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

	certExpiresInMetric = "x509_cert_expires_in_seconds"
	certExpiresInHelp   = "Indicates the remaining time before the certificate's not after timestamp"
	certExpiresInDesc   = prometheus.NewDesc(certExpiresInMetric, certExpiresInHelp, nil, nil)

	certValidSinceMetric = "x509_cert_valid_since_seconds"
	certValidSinceHelp   = "Indicates the elapsed time since the certificate's not before timestamp"
	certValidSinceDesc   = prometheus.NewDesc(certValidSinceMetric, certValidSinceHelp, nil, nil)

	certErrorsMetric = "x509_read_errors"
	certErrorsHelp   = "Indicates the number of read failure(s)"
	certErrorsDesc   = prometheus.NewDesc(certErrorsMetric, certErrorsHelp, nil, nil)
)

func (collector *collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- certExpiredDesc
	ch <- certNotBeforeDesc
	ch <- certNotAfterDesc
	ch <- certErrorsDesc

	if collector.exporter.ExposeRelativeMetrics {
		ch <- certExpiresInDesc
		ch <- certValidSinceDesc
	}
}

func (collector *collector) Collect(ch chan<- prometheus.Metric) {
	certRefs, certErrors := collector.exporter.parseAllCertificates()

	for index, err := range certErrors {
		if err.err != nil {
			log.Debugf("read error %d: %+v", index+1, err.err)
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
}

func (collector *collector) getMetricsForCertificate(certData *parsedCertificate, ref *certificateRef) []prometheus.Metric {
	labels := map[string]string{
		"serial_number": certData.cert.SerialNumber.String(),
	}

	if ref.format != certificateFormatKubeSecret {
		trimComponentsCount := collector.exporter.TrimPathComponents
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

	fillLabelsFromName(&certData.cert.Issuer, "issuer", labels)
	fillLabelsFromName(&certData.cert.Subject, "subject", labels)

	if ref.format == certificateFormatYAML {
		kind := strings.Split(certData.yqMatchExpr, ".")[1]
		labels["embedded_kind"] = strings.TrimRight(kind, "s")
	}

	if len(certData.userID) > 0 {
		labels["embedded_key"] = certData.userID
	}

	expired := 0.
	if time.Now().After(certData.cert.NotAfter) {
		expired = 1.
	}

	labelKeys := []string{}
	labelValues := []string{}
	for key, value := range labels {
		labelKeys = append(labelKeys, key)
		labelValues = append(labelValues, value)
	}

	metrics := []prometheus.Metric{
		prometheus.MustNewConstMetric(
			prometheus.NewDesc(certExpiredMetric, certExpiredHelp, labelKeys, nil),
			prometheus.GaugeValue,
			expired,
			labelValues...,
		),
		prometheus.MustNewConstMetric(
			prometheus.NewDesc(certNotBeforeMetric, certNotBeforeHelp, labelKeys, nil),
			prometheus.GaugeValue,
			float64(certData.cert.NotBefore.Unix()),
			labelValues...,
		),
		prometheus.MustNewConstMetric(
			prometheus.NewDesc(certNotAfterMetric, certNotAfterHelp, labelKeys, nil),
			prometheus.GaugeValue,
			float64(certData.cert.NotAfter.Unix()),
			labelValues...,
		),
	}

	if collector.exporter.ExposeRelativeMetrics {
		metrics = append(metrics, prometheus.MustNewConstMetric(
			prometheus.NewDesc(certExpiresInMetric, certExpiresInHelp, labelKeys, nil),
			prometheus.GaugeValue,
			float64(time.Until(certData.cert.NotAfter).Seconds()),
			labelValues...,
		))

		metrics = append(metrics, prometheus.MustNewConstMetric(
			prometheus.NewDesc(certValidSinceMetric, certValidSinceHelp, labelKeys, nil),
			prometheus.GaugeValue,
			float64(time.Since(certData.cert.NotBefore).Seconds()),
			labelValues...,
		))
	}

	return metrics
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
