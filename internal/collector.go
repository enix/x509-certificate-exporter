package exporter

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"path/filepath"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

type collector struct {
	certificates []string
}

func (collector *collector) Describe(ch chan<- *prometheus.Desc) {}

func (collector *collector) Collect(ch chan<- prometheus.Metric) {
	for _, file := range collector.certificates {
		cert, _ := parseCertificate(file)
		metrics := getMetricsForCertificate(cert, file)

		for _, metric := range metrics {
			ch <- metric
		}
	}
}

func getMetricsForCertificate(cert *x509.Certificate, path string) []prometheus.Metric {
	baseLabels := []string{
		"filename",
		"filepath",
		"serial_number",
	}
	baseLabelsValue := []string{
		filepath.Base(path),
		path,
		cert.SerialNumber.String(),
	}

	issuerLabels, issuerLabelsValue := getLabelsFromName(&cert.Issuer, "issuer")
	subjectLabels, subjectLabelsValue := getLabelsFromName(&cert.Subject, "subject")
	labels := append(baseLabels, append(issuerLabels, subjectLabels...)...)
	labelsValue := append(baseLabelsValue, append(issuerLabelsValue, subjectLabelsValue...)...)

	expired := 0.
	if time.Now().Unix() > cert.NotAfter.Unix() {
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
			prometheus.CounterValue,
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
			prometheus.CounterValue,
			float64(cert.NotBefore.Unix()),
			labelsValue...,
		),
		prometheus.MustNewConstMetric(
			prometheus.NewDesc(
				"x509_cert_not_after",
				"x509 certificate not after timestamp",
				labels,
				nil,
			),
			prometheus.CounterValue,
			float64(cert.NotAfter.Unix()),
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
