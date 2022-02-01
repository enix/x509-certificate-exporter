package internal

import (
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

	certErrorMetric = "x509_cert_error"
	certErrorHelp   = "Indicates wether the corresponding secret has read failure(s)"
	certErrorDesc   = prometheus.NewDesc(certErrorMetric, certErrorHelp, nil, nil)

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

	if collector.exporter.ExposeErrorMetrics {
		ch <- certErrorDesc
	}
}

func (collector *collector) Collect(ch chan<- prometheus.Metric) {
	certRefs, certErrors := collector.exporter.parseAllCertificates()

	for _, certRef := range certRefs {
		for _, cert := range certRef.certificates {
			metrics := collector.getMetricsForCertificate(cert, certRef)
			for _, metric := range metrics {
				ch <- metric
			}
		}

		if collector.exporter.ExposeErrorMetrics && len(certRef.certificates) > 0 {
			labelKeys, labelValues := collector.exporter.unzipLabels(collector.exporter.getBaseLabels(certRef))

			ch <- prometheus.MustNewConstMetric(
				prometheus.NewDesc(certErrorMetric, certErrorHelp, labelKeys, nil),
				prometheus.GaugeValue,
				0,
				labelValues...,
			)
		}
	}

	for index, err := range certErrors {
		if err.err != nil {
			log.Debugf("read error %d: %+v", index+1, err.err)
		}

		if collector.exporter.ExposeErrorMetrics && err.ref != nil {
			labelKeys, labelValues := collector.exporter.unzipLabels(collector.exporter.getBaseLabels(err.ref))

			ch <- prometheus.MustNewConstMetric(
				prometheus.NewDesc(certErrorMetric, certErrorHelp, labelKeys, nil),
				prometheus.GaugeValue,
				1,
				labelValues...,
			)
		}
	}

	ch <- prometheus.MustNewConstMetric(
		certErrorsDesc,
		prometheus.GaugeValue,
		float64(len(certErrors)),
	)
}

func (collector *collector) getMetricsForCertificate(certData *parsedCertificate, ref *certificateRef) []prometheus.Metric {
	labels := collector.exporter.getLabels(certData, ref)

	expired := 0.
	if time.Now().After(certData.cert.NotAfter) {
		expired = 1.
	}

	labelKeys, labelValues := collector.exporter.unzipLabels(labels)
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
