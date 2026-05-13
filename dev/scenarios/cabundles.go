// CABundle scenarios — cluster-scoped admission resources with inline
// caBundle PEM fields, materialised by the seed and watched by the
// chart's cabundle exporter source.
package scenarios

import (
	"sync"
	"time"
)

// CABundleResourceKind discriminates the K8s resource kind a scenario
// targets. Matches the `cabundle_resource_kind` Prometheus label.
type CABundleResourceKind string

const (
	CABundleKindMutating   CABundleResourceKind = "MutatingWebhookConfiguration"
	CABundleKindValidating CABundleResourceKind = "ValidatingWebhookConfiguration"
)

// CABundleScenario describes one cluster-scoped resource the seed
// creates and the e2e test asserts metrics against.
type CABundleScenario struct {
	Kind     CABundleResourceKind
	Name     string
	Labels   map[string]string
	Webhooks []CABundleWebhook
	// Watched is true when the chart's cabundlesExporter should
	// surface this resource; false-cases verify exclusion.
	Watched bool
}

// CABundleWebhook is one entry inside MWC.Webhooks / VWC.Webhooks. The
// Cert is materialised into a PEM-encoded `caBundle` by the seed; CN
// is what the e2e assertion expects on the resulting series.
type CABundleWebhook struct {
	Name string
	CN   string
}

var (
	caBundlesOnce sync.Once
	caBundlesAll  []CABundleScenario
)

// AllCABundles returns the cabundle scenarios, computed once per
// process. The certs themselves are generated at first call so the
// e2e seed and the e2e test see the same CN strings.
func AllCABundles() []CABundleScenario {
	caBundlesOnce.Do(buildCABundles)
	return caBundlesAll
}

func buildCABundles() {
	caBundlesAll = []CABundleScenario{
		// 1. MWC with two entries — exercises the per-entry emission
		//    and the `cabundle_entry` label.
		{
			Kind: CABundleKindMutating,
			Name: "x509ce-e2e-mwc",
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "x509ce-e2e",
			},
			Watched: true,
			Webhooks: []CABundleWebhook{
				{Name: "first.mwc.x509ce-e2e", CN: "mwc-first.example.test"},
				{Name: "second.mwc.x509ce-e2e", CN: "mwc-second.example.test"},
			},
		},
		// 2. VWC with one entry — exercises the validating informer.
		{
			Kind: CABundleKindValidating,
			Name: "x509ce-e2e-vwc",
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "x509ce-e2e",
			},
			Watched: true,
			Webhooks: []CABundleWebhook{
				{Name: "policy.vwc.x509ce-e2e", CN: "vwc-policy.example.test"},
			},
		},
		// 3. MWC excluded by name pattern — Watched: false. The chart's
		//    excludeNames glob in test/e2e/values.yaml filters this out;
		//    the e2e test asserts NO series carries this resource name.
		{
			Kind: CABundleKindMutating,
			Name: "x509ce-e2e-mwc-ignored",
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "x509ce-e2e",
			},
			Watched: false,
			Webhooks: []CABundleWebhook{
				{Name: "ignored.mwc.x509ce-e2e", CN: "mwc-ignored.example.test"},
			},
		},
	}
}

// CABundleNotAfter is the NotAfter the seed uses for every cabundle
// scenario cert — long enough that the e2e never sees an expired
// series, predictable so the assertions can sanity-check the
// timestamp.
var CABundleNotAfter = time.Now().Add(180 * 24 * time.Hour).UTC().Truncate(time.Second)
