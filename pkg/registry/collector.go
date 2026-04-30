package registry

import (
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/enix/x509-certificate-exporter/v4/pkg/cert"
)

// descTable holds the per-metric prometheus.Desc set built from the unified
// schema. Single Desc per metric name; Prometheus allows nothing else.
type descTable struct {
	cfg                          Config
	schema                       *schema
	notBefore, notAfter, expired *prometheus.Desc
	expiresIn, validSince        *prometheus.Desc
	certError                    *prometheus.Desc
}

func newDescTable(cfg Config) descTable {
	includeDisc := cfg.Collision != CollisionNever
	opts := LabelOptions{
		SubjectFields:      cfg.SubjectFields,
		IssuerFields:       cfg.IssuerFields,
		TrimPathComponents: cfg.TrimPathComponents,
	}
	s := newSchema(opts, cfg.ExposedSecretLabels, cfg.ExposedConfigMapLabels, includeDisc)
	t := descTable{cfg: cfg, schema: s}
	t.notBefore = prometheus.NewDesc("x509_cert_not_before", "Unix timestamp of the certificate's NotBefore.", s.names, nil)
	t.notAfter = prometheus.NewDesc("x509_cert_not_after", "Unix timestamp of the certificate's NotAfter.", s.names, nil)
	t.expired = prometheus.NewDesc("x509_cert_expired", "1 if the certificate is expired, 0 otherwise.", s.names, nil)
	if cfg.ExposeRelative {
		t.expiresIn = prometheus.NewDesc("x509_cert_expires_in_seconds", "Seconds until the certificate's NotAfter.", s.names, nil)
		t.validSince = prometheus.NewDesc("x509_cert_valid_since_seconds", "Seconds since the certificate's NotBefore.", s.names, nil)
	}
	if cfg.ExposePerCertError {
		t.certError = prometheus.NewDesc("x509_cert_error", "1 if the corresponding bundle item failed to parse, 0 otherwise.", s.names, nil)
	}
	return t
}

func (t descTable) describe(ch chan<- *prometheus.Desc) {
	ch <- t.notBefore
	ch <- t.notAfter
	ch <- t.expired
	if t.expiresIn != nil {
		ch <- t.expiresIn
	}
	if t.validSince != nil {
		ch <- t.validSince
	}
	if t.certError != nil {
		ch <- t.certError
	}
}

// Describe implements prometheus.Collector.
func (r *Registry) Describe(ch chan<- *prometheus.Desc) {
	r.sourceUp.Describe(ch)
	r.sourceErrors.Describe(ch)
	r.sourceBundles.Describe(ch)
	r.collisionTotal.Describe(ch)
	ch <- r.scrapeDuration.Desc()
	r.parseDuration.Describe(ch)
	r.panicTotal.Describe(ch)
	r.informerScope.Describe(ch)
	r.informerQueueDepth.Describe(ch)
	r.watchResyncs.Describe(ch)
	r.pkcs12PassphraseFailures.Describe(ch)
	r.kubeRequestDuration.Describe(ch)
	ch <- r.buildInfo.Desc()
	r.descs.describe(ch)
}

// Collect implements prometheus.Collector.
func (r *Registry) Collect(ch chan<- prometheus.Metric) {
	startTrack := time.Now()
	defer func() {
		r.TrackScrapeDuration(time.Since(startTrack))
	}()
	start := time.Now()
	defer func() {
		r.scrapeDuration.Observe(time.Since(start).Seconds())
		ch <- r.scrapeDuration
	}()

	r.sourceUp.Collect(ch)
	r.sourceErrors.Collect(ch)
	r.sourceBundles.Collect(ch)
	r.collisionTotal.Collect(ch)
	r.parseDuration.Collect(ch)
	r.panicTotal.Collect(ch)
	r.informerScope.Collect(ch)
	r.informerQueueDepth.Collect(ch)
	r.watchResyncs.Collect(ch)
	r.pkcs12PassphraseFailures.Collect(ch)
	r.kubeRequestDuration.Collect(ch)
	ch <- r.buildInfo

	bundles := r.snapshot()
	r.emitCertMetrics(ch, bundles)
}

type keyedItem struct {
	bundle cert.Bundle
	item   cert.Item
	values []string // values WITHOUT discriminator (length = len(schema.names) or len-1 if disc included)
}

func (r *Registry) emitCertMetrics(ch chan<- prometheus.Metric, bundles []cert.Bundle) {
	groups := map[string]map[string][]keyedItem{} // kind -> labelKey -> items

	opts := LabelOptions{
		SubjectFields:      r.cfg.SubjectFields,
		IssuerFields:       r.cfg.IssuerFields,
		TrimPathComponents: r.cfg.TrimPathComponents,
	}
	for _, b := range bundles {
		for _, it := range b.Items {
			vals := r.descs.schema.values(b, it, opts)
			// Group by labels excluding discriminator slot (if present).
			groupVals := vals
			if r.descs.schema.idxDiscriminator >= 0 {
				groupVals = append([]string{}, vals[:r.descs.schema.idxDiscriminator]...)
			}
			labelKey := strings.Join(groupVals, "\x00")
			if groups[b.Source.Kind] == nil {
				groups[b.Source.Kind] = map[string][]keyedItem{}
			}
			groups[b.Source.Kind][labelKey] = append(groups[b.Source.Kind][labelKey], keyedItem{
				bundle: b, item: it, values: vals,
			})
		}
		if r.cfg.ExposePerCertError {
			r.emitItemErrors(ch, b, opts)
		}
	}

	for kind, byKey := range groups {
		for _, items := range byKey {
			collided := len(items) > 1
			useDisc := r.descs.schema.idxDiscriminator >= 0 &&
				(r.cfg.Collision == CollisionAlways || (collided && r.cfg.Collision == CollisionAuto))
			if collided && r.cfg.Collision == CollisionNever {
				best := items[0]
				for _, it := range items[1:] {
					if it.item.Cert != nil && it.item.Cert.NotAfter.Before(best.item.Cert.NotAfter) {
						best = it
					}
				}
				r.collisionTotal.WithLabelValues(kind).Add(float64(len(items) - 1))
				r.emitItem(ch, best, false)
				continue
			}
			if collided {
				r.collisionTotal.WithLabelValues(kind).Add(float64(len(items) - 1))
			}
			for _, it := range items {
				r.emitItem(ch, it, useDisc)
			}
		}
	}
}

func (r *Registry) emitItem(ch chan<- prometheus.Metric, ki keyedItem, withDisc bool) {
	c := ki.item.Cert
	if c == nil {
		return
	}
	vals := append([]string{}, ki.values...)
	if r.descs.schema.idxDiscriminator >= 0 {
		if withDisc {
			vals[r.descs.schema.idxDiscriminator] = fingerprint(ki.bundle, ki.item, r.cfg.DiscriminatorLength)
		} else {
			vals[r.descs.schema.idxDiscriminator] = ""
		}
	}
	emit := func(d *prometheus.Desc, v float64) {
		if d == nil {
			return
		}
		ch <- prometheus.MustNewConstMetric(d, prometheus.GaugeValue, v, vals...)
	}
	now := time.Now()
	emit(r.descs.notBefore, float64(c.NotBefore.Unix()))
	emit(r.descs.notAfter, float64(c.NotAfter.Unix()))
	expired := 0.0
	if now.After(c.NotAfter) {
		expired = 1
	}
	emit(r.descs.expired, expired)
	emit(r.descs.expiresIn, c.NotAfter.Sub(now).Seconds())
	emit(r.descs.validSince, now.Sub(c.NotBefore).Seconds())
	emit(r.descs.certError, 0)
}

func (r *Registry) emitItemErrors(ch chan<- prometheus.Metric, b cert.Bundle, opts LabelOptions) {
	if r.descs.certError == nil {
		return
	}
	for _, e := range b.Errors {
		if e.Index < 0 {
			continue
		}
		vals := r.descs.schema.values(b, cert.Item{Index: e.Index}, opts)
		ch <- prometheus.MustNewConstMetric(r.descs.certError, prometheus.GaugeValue, 1, vals...)
	}
}
