// Package cabundle is a Source that watches Kubernetes cluster-scoped
// admission and API-aggregation resources for inline `caBundle` PEM
// data and emits one certificate ref per (resource, entry) pair.
//
// Supported resources (each gated independently via Options.Resources):
//
//   - admissionregistration.k8s.io/v1 MutatingWebhookConfiguration
//     (one caBundle per .webhooks[] entry; identified by .webhooks[].name)
//   - admissionregistration.k8s.io/v1 ValidatingWebhookConfiguration
//     (same shape)
//
// All four target resources are cluster-scoped; the source therefore
// requires cluster-wide get+list+watch on the corresponding API group
// (see chart/templates/clusterrole-cabundles.yaml).
//
// Empty caBundle fields (e.g. `apiservice.spec.insecureSkipTLSVerify: true`
// or a freshly-created webhook waiting for cert-manager CA injection)
// are skipped silently — they're a normal, expected state, not an error.
package cabundle

import (
	"context"
	"fmt"
	"log/slog"
	"path"
	"sync"
	"time"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	"github.com/enix/x509-certificate-exporter/v4/pkg/cert"
	pemparse "github.com/enix/x509-certificate-exporter/v4/pkg/cert/pem"
)

// Resources gates which K8s resource kinds the source watches. Each is
// opt-in so users can scope the cluster-wide RBAC to the kinds they
// actually care about.
type Resources struct {
	Mutating   bool
	Validating bool
}

// IsZero reports whether no resource kind is enabled. Used by the
// constructor to bail out early on misconfiguration.
func (r Resources) IsZero() bool { return !r.Mutating && !r.Validating }

// Options configures a cabundle Source.
type Options struct {
	Name string
	// Client is a Kubernetes clientset. Must have cluster-wide
	// get+list+watch on every resource kind selected via Resources.
	Client kubernetes.Interface
	// Resources selects which K8s resource kinds to watch.
	Resources Resources
	// ResyncEvery is the SharedInformerFactory resync period. A resync
	// fabricates synthetic Update events for every cached object so
	// the source picks up out-of-band CA rotations the watch may have
	// missed. Defaults to 30 minutes.
	ResyncEvery time.Duration
	// IncludeNames / ExcludeNames are shell-glob patterns applied
	// client-side to the resource's metadata.name. Empty IncludeNames
	// = match everything.
	IncludeNames []string
	ExcludeNames []string
	// LabelSelector is forwarded to the informer's ListWatch so the
	// API server filters at the source.
	LabelSelector string
	// ExposedLabels lists K8s resource labels to surface as Prometheus
	// labels (via SourceRef.Attributes). Same contract as
	// Options.ExposeLabels on the kubernetes Source.
	ExposedLabels []string
	// OnReady is invoked once after the initial informer sync — true
	// on success, false if sync was cancelled or hit a fatal error.
	OnReady func(bool)
}

// DefaultResyncEvery is the fallback for Options.ResyncEvery.
const DefaultResyncEvery = 30 * time.Minute

// resourceKindName maps an enabled-resource flag to the Prometheus
// label value (the K8s Kind, not the lowercased resource plural).
// Surfaced verbatim on the `cabundle_resource_kind` series label.
const (
	kindMutating   = "MutatingWebhookConfiguration"
	kindValidating = "ValidatingWebhookConfiguration"
)

// Source implements cert.Source. Lifecycle: New → Name → Run(ctx, sink).
type Source struct {
	opts   Options
	log    *slog.Logger
	parser pemparse.Parser

	// tracked records the SourceRefs currently in the sink, keyed
	// by ref.String(), grouped per (kind, name) so resource deletes
	// can issue Delete for every entry under that resource. Protected
	// by mu because informer handlers fire from multiple goroutines.
	mu      sync.Mutex
	tracked map[resID]map[string]cert.SourceRef
}

// resID disambiguates two resources of different Kind but same name
// (e.g. a MWC named "foo" and a VWC named "foo").
type resID struct {
	kind string
	name string
}

// New constructs a cabundle Source. The returned Source is inert until
// Run is called.
func New(opts Options, logger *slog.Logger) *Source {
	if logger == nil {
		logger = slog.Default()
	}
	if opts.ResyncEvery <= 0 {
		opts.ResyncEvery = DefaultResyncEvery
	}
	return &Source{
		opts:    opts,
		log:     logger.With("source_kind", "cabundle", "source_name", opts.Name),
		tracked: map[resID]map[string]cert.SourceRef{},
	}
}

// Name returns the configured source name (used as the `source_name`
// label on per-source observability metrics).
func (s *Source) Name() string { return s.opts.Name }

// Run wires up the configured informers and blocks until ctx is
// cancelled. Returns nil on clean shutdown.
func (s *Source) Run(ctx context.Context, sink cert.Sink) error {
	if s.opts.Client == nil {
		return fmt.Errorf("cabundle source %q: no client", s.opts.Name)
	}
	if s.opts.Resources.IsZero() {
		return fmt.Errorf("cabundle source %q: no resources enabled", s.opts.Name)
	}

	factoryOpts := []informers.SharedInformerOption{}
	if s.opts.LabelSelector != "" {
		factoryOpts = append(factoryOpts,
			informers.WithTweakListOptions(func(lo *metav1.ListOptions) {
				lo.LabelSelector = s.opts.LabelSelector
			}))
	}
	factory := informers.NewSharedInformerFactoryWithOptions(
		s.opts.Client, s.opts.ResyncEvery, factoryOpts...)

	var infs []cache.SharedInformer
	if s.opts.Resources.Mutating {
		inf := factory.Admissionregistration().V1().MutatingWebhookConfigurations().Informer()
		_, _ = inf.AddEventHandler(cache.ResourceEventHandlerFuncs{
			AddFunc:    func(obj any) { s.onMWC(sink, obj, false) },
			UpdateFunc: func(_, obj any) { s.onMWC(sink, obj, false) },
			DeleteFunc: func(obj any) { s.onMWC(sink, obj, true) },
		})
		infs = append(infs, inf)
	}
	if s.opts.Resources.Validating {
		inf := factory.Admissionregistration().V1().ValidatingWebhookConfigurations().Informer()
		_, _ = inf.AddEventHandler(cache.ResourceEventHandlerFuncs{
			AddFunc:    func(obj any) { s.onVWC(sink, obj, false) },
			UpdateFunc: func(_, obj any) { s.onVWC(sink, obj, false) },
			DeleteFunc: func(obj any) { s.onVWC(sink, obj, true) },
		})
		infs = append(infs, inf)
	}

	factory.Start(ctx.Done())
	syncOK := waitForCacheSync(ctx, infs)
	if s.opts.OnReady != nil {
		s.opts.OnReady(syncOK)
	}
	if !syncOK {
		if ctx.Err() == nil {
			return fmt.Errorf("cabundle source %q: initial informer sync did not complete", s.opts.Name)
		}
		// Clean shutdown during sync — match the post-Run path (line below) and return nil.
		return nil
	}
	s.log.Debug("cabundle informers synced",
		"mutating", s.opts.Resources.Mutating,
		"validating", s.opts.Resources.Validating,
	)

	<-ctx.Done()
	return nil
}

func waitForCacheSync(ctx context.Context, infs []cache.SharedInformer) bool {
	for _, inf := range infs {
		if !cache.WaitForCacheSync(ctx.Done(), inf.HasSynced) {
			return false
		}
	}
	return true
}

// onMWC handles a MutatingWebhookConfiguration add/update/delete event.
// deleted is true when the event is a delete; in that case obj may be a
// cache.DeletedFinalStateUnknown wrapper.
func (s *Source) onMWC(sink cert.Sink, obj any, deleted bool) {
	mwc := asMWC(obj)
	if mwc == nil {
		return
	}
	if !s.acceptName(mwc.Name) {
		return
	}
	id := resID{kind: kindMutating, name: mwc.Name}
	if deleted {
		s.evictAll(sink, id)
		return
	}
	entries := make([]webhookEntry, 0, len(mwc.Webhooks))
	for _, w := range mwc.Webhooks {
		entries = append(entries, webhookEntry{name: w.Name, caBundle: w.ClientConfig.CABundle})
	}
	s.reconcile(sink, id, entries, mwc.Labels)
}

// onVWC mirrors onMWC for ValidatingWebhookConfiguration.
func (s *Source) onVWC(sink cert.Sink, obj any, deleted bool) {
	vwc := asVWC(obj)
	if vwc == nil {
		return
	}
	if !s.acceptName(vwc.Name) {
		return
	}
	id := resID{kind: kindValidating, name: vwc.Name}
	if deleted {
		s.evictAll(sink, id)
		return
	}
	entries := make([]webhookEntry, 0, len(vwc.Webhooks))
	for _, w := range vwc.Webhooks {
		entries = append(entries, webhookEntry{name: w.Name, caBundle: w.ClientConfig.CABundle})
	}
	s.reconcile(sink, id, entries, vwc.Labels)
}

type webhookEntry struct {
	name     string
	caBundle []byte
}

// reconcile upserts a Bundle for every entry with non-empty caBundle
// and evicts tracked entries no longer present in the resource (or
// whose caBundle just became empty — equivalent for our purposes).
func (s *Source) reconcile(sink cert.Sink, id resID, entries []webhookEntry, labels map[string]string) {
	attrs := s.attributesFromLabels(labels)
	now := map[string]cert.SourceRef{}
	for _, e := range entries {
		if len(e.caBundle) == 0 {
			continue
		}
		ref := cert.SourceRef{
			Kind:       cert.KindKubeCABundle,
			Location:   path.Join(id.kind, id.name),
			Key:        e.name,
			Format:     cert.FormatPEM,
			SourceName: s.opts.Name,
			Attributes: attrs,
		}
		b := s.parser.Parse(e.caBundle, ref, cert.ParseOptions{})
		sink.Upsert(b)
		now[ref.String()] = ref
	}
	s.mu.Lock()
	prev := s.tracked[id]
	for k, ref := range prev {
		if _, kept := now[k]; !kept {
			sink.Delete(ref)
		}
	}
	if len(now) > 0 {
		s.tracked[id] = now
	} else {
		delete(s.tracked, id)
	}
	s.mu.Unlock()
}

// evictAll fires Delete for every tracked entry under id and forgets
// them. Called on resource deletion or when the resource no longer
// matches the name filter.
func (s *Source) evictAll(sink cert.Sink, id resID) {
	s.mu.Lock()
	prev := s.tracked[id]
	delete(s.tracked, id)
	s.mu.Unlock()
	for _, ref := range prev {
		sink.Delete(ref)
	}
}

// attributesFromLabels copies the resource's K8s labels into the
// SourceRef.Attributes map under the `cabundle_label/` prefix so the
// registry can surface them as Prometheus labels per
// Options.ExposedLabels.
func (s *Source) attributesFromLabels(labels map[string]string) map[string]string {
	if len(s.opts.ExposedLabels) == 0 || len(labels) == 0 {
		return nil
	}
	attrs := make(map[string]string, len(s.opts.ExposedLabels))
	for _, l := range s.opts.ExposedLabels {
		if v, ok := labels[l]; ok {
			attrs[cert.AttrCABundleLabelPrefix+l] = v
		}
	}
	if len(attrs) == 0 {
		return nil
	}
	return attrs
}

// acceptName applies the include/exclude name filters using the shared
// shell-glob matcher.
func (s *Source) acceptName(name string) bool {
	for _, pat := range s.opts.ExcludeNames {
		if matchGlob(pat, name) {
			return false
		}
	}
	if len(s.opts.IncludeNames) == 0 {
		return true
	}
	for _, pat := range s.opts.IncludeNames {
		if matchGlob(pat, name) {
			return true
		}
	}
	return false
}

func matchGlob(pat, s string) bool {
	ok, err := path.Match(pat, s)
	return ok && err == nil
}

// asMWC extracts a typed *MutatingWebhookConfiguration from an informer
// event payload, transparently unwrapping cache.DeletedFinalStateUnknown.
func asMWC(obj any) *admissionv1.MutatingWebhookConfiguration {
	if v, ok := obj.(*admissionv1.MutatingWebhookConfiguration); ok {
		return v
	}
	if t, ok := obj.(cache.DeletedFinalStateUnknown); ok {
		if v, ok := t.Obj.(*admissionv1.MutatingWebhookConfiguration); ok {
			return v
		}
	}
	return nil
}

// asVWC mirrors asMWC for ValidatingWebhookConfiguration.
func asVWC(obj any) *admissionv1.ValidatingWebhookConfiguration {
	if v, ok := obj.(*admissionv1.ValidatingWebhookConfiguration); ok {
		return v
	}
	if t, ok := obj.(cache.DeletedFinalStateUnknown); ok {
		if v, ok := t.Obj.(*admissionv1.ValidatingWebhookConfiguration); ok {
			return v
		}
	}
	return nil
}
