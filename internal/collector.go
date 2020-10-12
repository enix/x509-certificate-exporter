package exporter

import (
	"crypto/x509/pkix"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

type collector struct {
	exporter *Exporter
}

var (
	certExpiredDesc = prometheus.NewDesc(
		"x509_cert_expired",
		"Indicates if the certificate is expired.",
		[]string{"filename", "filepath", "serial_number"}, nil,
	)
	certNotBeforeDesc = prometheus.NewDesc(
		"x509_cert_not_before",
		"Indicates the certificate's not before timestamp.",
		[]string{"filename", "filepath", "serial_number"}, nil,
	)
	certNotAfterDesc = prometheus.NewDesc(
		"x509_cert_not_after",
		"Indicates the certificate's not after timestamp.",
		[]string{"filename", "filepath", "serial_number"}, nil,
	)
)

func (collector *collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- certExpiredDesc
	ch <- certNotBeforeDesc
	ch <- certNotAfterDesc
}

func (collector *collector) Collect(ch chan<- prometheus.Metric) {
	certRefs := collector.exporter.parseAllCertificates()

	for _, certRef := range certRefs {
		for _, cert := range certRef.certificates {
			metrics := getMetricsForCertificate(cert, certRef)
			for _, metric := range metrics {
				ch <- metric
			}
		}
	}
}

func getMetricsForCertificate(certData *parsedCertificate, ref *certificateRef) []prometheus.Metric {
	baseLabels := []string{
		"filename",
		"filepath",
		"serial_number",
	}
	baseLabelsValue := []string{
		filepath.Base(ref.path),
		ref.path,
		certData.cert.SerialNumber.String(),
	}

	issuerLabels, issuerLabelsValue := getLabelsFromName(&certData.cert.Issuer, "issuer")
	subjectLabels, subjectLabelsValue := getLabelsFromName(&certData.cert.Subject, "subject")
	labels := append(baseLabels, append(issuerLabels, subjectLabels...)...)
	labelsValue := append(baseLabelsValue, append(issuerLabelsValue, subjectLabelsValue...)...)

	if ref.format == certificateFormatYAML {
		kind := strings.Split(certData.yqMatchExpr, ".")[0]
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
			prometheus.NewDesc(
				"x509_cert_expired",
				"x509 certificate expiration boolean",
				labels,
				nil,
			),
			prometheus.GaugeValue,
			expired,
			labelsValue...,
		),
		prometheus.MustNewConstMetric(
			prometheus.NewDesc(
				"x509_cert_not_before",
				"x509 certificate not before timestamp",
				labels,
				nil,
			),
			prometheus.GaugeValue,
			float64(certData.cert.NotBefore.Unix()),
			labelsValue...,
		),
		prometheus.MustNewConstMetric(
			prometheus.NewDesc(
				"x509_cert_not_after",
				"x509 certificate not after timestamp",
				labels,
				nil,
			),
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
