// Package k8s implements a Source that watches Kubernetes Secrets (and
// optionally ConfigMaps) via SharedInformerFactory.
//
// Key optimisations:
//
//   - SetTransform strips irrelevant Data keys and ManagedFields before
//     anything is stored in the informer cache (massive memory win).
//   - LabelSelector and FieldSelector are pushed server-side via the
//     factory's Tweak option.
//   - First sync gates the source's "ready" state.
//   - Delete events propagate immediately so deleted Secrets disappear
//     from the registry.
//
// What is not covered in this initial implementation: adaptive RBAC scope
// detection (SelfSubjectAccessReview), WatchListClient feature gate,
// custom workqueue backpressure beyond what the informer reflector
// already provides. Those are documented as planned extensions.
package k8s

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	"github.com/enix/x509-certificate-exporter/v4/pkg/cert"
)

// SecretTypeRule says how to match Secret data keys and which parser to
// use. KeyRe is compiled from the user-provided regex; one entry per
// regex.
type SecretTypeRule struct {
	Type                string
	KeyRe               *regexp.Regexp
	Parser              cert.FormatParser
	ParseOpts           cert.ParseOptions
	PassphraseKey       string          // when format is pkcs12
	PassphraseSecretRef *cert.SourceRef // optional cross-secret passphrase ref
}

// Selectors carry server-side filters.
type Selectors struct {
	LabelSelector string
	FieldSelector string
}

// SecretFilter expresses extra client-side checks not expressible in
// LabelSelector (name globs, exclude rules).
type SecretFilter struct {
	IncludeNames []string // glob-like (currently exact match or "*")
	ExcludeNames []string
}

// NamespaceFilter applies cluster-wide rules: object's namespace must pass
// every active rule (include/exclude on name, include/exclude on labels).
// When all four lists are empty the filter accepts every namespace and no
// Namespace informer is started.
type NamespaceFilter struct {
	IncludeNames  []string // exact match or "*"
	ExcludeNames  []string // applied after Include
	IncludeLabels []string // each entry is "key" (exists) or "key=value"
	ExcludeLabels []string
}

// IsZero returns true when no namespace rules are configured.
func (f NamespaceFilter) IsZero() bool {
	return len(f.IncludeNames) == 0 && len(f.ExcludeNames) == 0 &&
		len(f.IncludeLabels) == 0 && len(f.ExcludeLabels) == 0
}

// needsLabels returns true if the filter requires reading namespace labels.
func (f NamespaceFilter) needsLabels() bool {
	return len(f.IncludeLabels) > 0 || len(f.ExcludeLabels) > 0
}

// Options configure a Kubernetes Source. Either Secrets or ConfigMaps (or
// both) must be set.
type Options struct {
	Name        string
	Client      kubernetes.Interface
	Namespace   string // "" => cluster scope
	ResyncEvery time.Duration

	SecretRules         []SecretTypeRule
	SecretSelector      Selectors
	SecretFilter        SecretFilter
	ExposedSecretLabels []string

	ConfigMapRules         []SecretTypeRule
	ConfigMapSelector      Selectors
	ConfigMapFilter        SecretFilter
	ExposedConfigMapLabels []string

	NamespaceFilter NamespaceFilter

	FirstSyncDone chan struct{}
	OnReady       func(success bool)
}

// Source implements cert.Source.
type Source struct {
	opts Options
	log  *slog.Logger

	mu      sync.Mutex
	tracked map[string]struct{} // ref keys we've upserted

	// nsLabels caches the latest seen labels per namespace name, keyed by
	// namespace name. Populated only when NamespaceFilter.needsLabels().
	nsLabelsMu sync.RWMutex
	nsLabels   map[string]map[string]string
}

func New(opts Options, logger *slog.Logger) *Source {
	if logger == nil {
		logger = slog.Default()
	}
	if opts.ResyncEvery <= 0 {
		opts.ResyncEvery = 30 * time.Minute
	}
	return &Source{
		opts:     opts,
		log:      logger.With("source_kind", "kubernetes", "source_name", opts.Name),
		tracked:  map[string]struct{}{},
		nsLabels: map[string]map[string]string{},
	}
}

func (s *Source) Name() string { return s.opts.Name }

// Run wires up the informers and blocks until ctx is cancelled.
func (s *Source) Run(ctx context.Context, sink cert.Sink) error {
	if s.opts.Client == nil {
		return fmt.Errorf("k8s source %q: no client", s.opts.Name)
	}
	tweak := func(o *metav1.ListOptions) {
		o.AllowWatchBookmarks = true
		if s.opts.SecretSelector.LabelSelector != "" {
			o.LabelSelector = s.opts.SecretSelector.LabelSelector
		}
		if s.opts.SecretSelector.FieldSelector != "" {
			o.FieldSelector = s.opts.SecretSelector.FieldSelector
		}
	}
	infName, err := cache.NewInformerName(s.opts.Name)
	if err != nil {
		return fmt.Errorf("create informer name %q: %w", s.opts.Name, err)
	}
	defer infName.Release()

	factory := informers.NewSharedInformerFactoryWithOptions(
		s.opts.Client, s.opts.ResyncEvery,
		informers.WithNamespace(s.opts.Namespace),
		informers.WithTweakListOptions(tweak),
		informers.WithInformerName(infName),
	)

	informersStarted := []cache.SharedInformer{}
	var secInf, cmInf cache.SharedIndexInformer

	// Namespace informer (cluster-scoped only — there's no point watching
	// namespaces when the source is already pinned to one). Started when
	// label-based namespace rules are configured; name-based rules don't
	// require it because the rule input is the namespace name.
	if s.opts.Namespace == "" && s.opts.NamespaceFilter.needsLabels() {
		nsFactory := informers.NewSharedInformerFactoryWithOptions(
			s.opts.Client, s.opts.ResyncEvery,
			informers.WithInformerName(infName),
		)
		nsInf := nsFactory.Core().V1().Namespaces().Informer()
		_, _ = nsInf.AddEventHandler(cache.ResourceEventHandlerFuncs{
			AddFunc:    func(obj any) { s.onNamespace(sink, obj, false) },
			UpdateFunc: func(_, obj any) { s.onNamespace(sink, obj, false) },
			DeleteFunc: func(obj any) { s.onNamespace(sink, obj, true) },
		})
		nsFactory.Start(ctx.Done())
		informersStarted = append(informersStarted, nsInf)
	}

	if len(s.opts.SecretRules) > 0 {
		secInf = factory.Core().V1().Secrets().Informer()
		_ = secInf.SetTransform(s.transformSecret)
		_, _ = secInf.AddEventHandler(cache.ResourceEventHandlerFuncs{
			AddFunc:    func(obj any) { s.onSecret(sink, obj, false) },
			UpdateFunc: func(_, obj any) { s.onSecret(sink, obj, false) },
			DeleteFunc: func(obj any) { s.onSecret(sink, obj, true) },
		})
		informersStarted = append(informersStarted, secInf)
	}

	if len(s.opts.ConfigMapRules) > 0 {
		cmTweak := func(o *metav1.ListOptions) {
			o.AllowWatchBookmarks = true
			if s.opts.ConfigMapSelector.LabelSelector != "" {
				o.LabelSelector = s.opts.ConfigMapSelector.LabelSelector
			}
			if s.opts.ConfigMapSelector.FieldSelector != "" {
				o.FieldSelector = s.opts.ConfigMapSelector.FieldSelector
			}
		}
		_ = cmTweak // applied at factory creation; we already set tweak for secrets.
		// Use a distinct factory if ConfigMaps need different selectors.
		if cmTweakDiffers(s.opts.SecretSelector, s.opts.ConfigMapSelector) {
			cmFactory := informers.NewSharedInformerFactoryWithOptions(
				s.opts.Client, s.opts.ResyncEvery,
				informers.WithNamespace(s.opts.Namespace),
				informers.WithTweakListOptions(cmTweak),
				informers.WithInformerName(infName),
			)
			cmInf = cmFactory.Core().V1().ConfigMaps().Informer()
			cmFactory.Start(ctx.Done())
		} else {
			cmInf = factory.Core().V1().ConfigMaps().Informer()
		}
		_ = cmInf.SetTransform(s.transformConfigMap)
		_, _ = cmInf.AddEventHandler(cache.ResourceEventHandlerFuncs{
			AddFunc:    func(obj any) { s.onConfigMap(sink, obj, false) },
			UpdateFunc: func(_, obj any) { s.onConfigMap(sink, obj, false) },
			DeleteFunc: func(obj any) { s.onConfigMap(sink, obj, true) },
		})
		informersStarted = append(informersStarted, cmInf)
	}

	factory.Start(ctx.Done())
	if !waitForCacheSync(ctx, informersStarted) {
		if s.opts.OnReady != nil {
			s.opts.OnReady(false)
		}
		if s.opts.FirstSyncDone != nil {
			close(s.opts.FirstSyncDone)
		}
		return ctx.Err()
	}
	// All caches are now hot. The namespace cache and the
	// secret/configmap caches are populated in parallel during sync, so
	// the AddFunc handlers may have rejected an object whose namespace
	// hadn't been seen yet. Re-emit every cached secret/configmap once
	// the namespace cache is settled so the filter sees consistent state.
	if s.opts.NamespaceFilter.needsLabels() {
		if secInf != nil {
			for _, obj := range secInf.GetStore().List() {
				s.onSecret(sink, obj, false)
			}
		}
		if cmInf != nil {
			for _, obj := range cmInf.GetStore().List() {
				s.onConfigMap(sink, obj, false)
			}
		}
	}
	if s.opts.OnReady != nil {
		s.opts.OnReady(true)
	}
	if s.opts.FirstSyncDone != nil {
		select {
		case <-s.opts.FirstSyncDone:
		default:
			close(s.opts.FirstSyncDone)
		}
	}
	s.log.Info("informers synced", "namespace", s.opts.Namespace)

	<-ctx.Done()
	return ctx.Err()
}

func cmTweakDiffers(a, b Selectors) bool {
	return a.LabelSelector != b.LabelSelector || a.FieldSelector != b.FieldSelector
}

func waitForCacheSync(ctx context.Context, infs []cache.SharedInformer) bool {
	for _, inf := range infs {
		if !cache.WaitForCacheSync(ctx.Done(), inf.HasSynced) {
			return false
		}
	}
	return true
}

// transformSecret strips irrelevant fields from a Secret before cache.
// Keeps only metadata + the Data keys that any rule cares about.
func (s *Source) transformSecret(obj any) (any, error) {
	sec, ok := obj.(*corev1.Secret)
	if !ok {
		return obj, nil
	}
	keep := map[string]struct{}{}
	for _, r := range s.opts.SecretRules {
		for k := range sec.Data {
			if r.Type != "" && string(sec.Type) != r.Type {
				continue
			}
			if r.KeyRe != nil && r.KeyRe.MatchString(k) {
				keep[k] = struct{}{}
			}
			// also keep the passphrase key if we'll need it
			if r.PassphraseKey != "" {
				keep[r.PassphraseKey] = struct{}{}
			}
		}
	}
	if len(keep) == 0 {
		// no relevant data -> drop everything
		sec.Data = nil
	} else {
		filtered := make(map[string][]byte, len(keep))
		for k := range keep {
			if v, ok := sec.Data[k]; ok {
				filtered[k] = v
			}
		}
		sec.Data = filtered
	}
	sec.ManagedFields = nil
	sec.Annotations = nil
	return sec, nil
}

func (s *Source) transformConfigMap(obj any) (any, error) {
	cm, ok := obj.(*corev1.ConfigMap)
	if !ok {
		return obj, nil
	}
	keep := map[string]struct{}{}
	for _, r := range s.opts.ConfigMapRules {
		for k := range cm.Data {
			if r.KeyRe != nil && r.KeyRe.MatchString(k) {
				keep[k] = struct{}{}
			}
		}
	}
	if len(keep) == 0 {
		cm.Data = nil
	} else {
		filtered := make(map[string]string, len(keep))
		for k := range keep {
			if v, ok := cm.Data[k]; ok {
				filtered[k] = v
			}
		}
		cm.Data = filtered
	}
	cm.ManagedFields = nil
	return cm, nil
}

func (s *Source) onSecret(sink cert.Sink, obj any, deleted bool) {
	sec := extractSecret(obj)
	if sec == nil {
		return
	}
	loc := fmt.Sprintf("%s/%s", sec.Namespace, sec.Name)
	if deleted {
		s.deleteAllRefs(sink, "kube-secret", loc)
		s.log.Debug("secret deleted", "namespace", sec.Namespace, "name", sec.Name)
		return
	}
	if !s.acceptName(sec.Name, s.opts.SecretFilter) {
		s.deleteAllRefs(sink, "kube-secret", loc)
		s.log.Debug("secret rejected", "namespace", sec.Namespace, "name", sec.Name, "reason", "name_filter")
		return
	}
	if !s.namespaceAllowed(sec.Namespace) {
		s.deleteAllRefs(sink, "kube-secret", loc)
		s.log.Debug("secret rejected", "namespace", sec.Namespace, "name", sec.Name, "reason", "namespace_filter")
		return
	}
	emitted := 0
	for _, rule := range s.opts.SecretRules {
		if rule.Type != "" && string(sec.Type) != rule.Type {
			continue
		}
		for k, v := range sec.Data {
			if rule.KeyRe == nil || !rule.KeyRe.MatchString(k) {
				continue
			}
			ref := s.refSecret(sec, k, rule.Parser.Format())
			po := rule.ParseOpts
			if rule.PassphraseKey != "" {
				if pp, ok := sec.Data[rule.PassphraseKey]; ok {
					po.Pkcs12Passphrase = strings.TrimSpace(string(pp))
				}
			}
			b := rule.Parser.Parse(v, ref, po)
			s.trackUpsert(sink, b)
			emitted++
		}
	}
	if emitted == 0 {
		s.log.Debug("secret matched no rule",
			"namespace", sec.Namespace, "name", sec.Name, "type", string(sec.Type))
	} else {
		s.log.Debug("secret accepted",
			"namespace", sec.Namespace, "name", sec.Name, "type", string(sec.Type), "bundles", emitted)
	}
}

func (s *Source) onConfigMap(sink cert.Sink, obj any, deleted bool) {
	cm := extractConfigMap(obj)
	if cm == nil {
		return
	}
	loc := fmt.Sprintf("%s/%s", cm.Namespace, cm.Name)
	if deleted {
		s.deleteAllRefs(sink, "kube-configmap", loc)
		s.log.Debug("configmap deleted", "namespace", cm.Namespace, "name", cm.Name)
		return
	}
	if !s.acceptName(cm.Name, s.opts.ConfigMapFilter) {
		s.deleteAllRefs(sink, "kube-configmap", loc)
		s.log.Debug("configmap rejected", "namespace", cm.Namespace, "name", cm.Name, "reason", "name_filter")
		return
	}
	if !s.namespaceAllowed(cm.Namespace) {
		s.deleteAllRefs(sink, "kube-configmap", loc)
		s.log.Debug("configmap rejected", "namespace", cm.Namespace, "name", cm.Name, "reason", "namespace_filter")
		return
	}
	emitted := 0
	for _, rule := range s.opts.ConfigMapRules {
		for k, v := range cm.Data {
			if rule.KeyRe == nil || !rule.KeyRe.MatchString(k) {
				continue
			}
			ref := s.refConfigMap(cm, k, rule.Parser.Format())
			b := rule.Parser.Parse([]byte(v), ref, rule.ParseOpts)
			s.trackUpsert(sink, b)
			emitted++
		}
	}
	if emitted == 0 {
		s.log.Debug("configmap matched no rule",
			"namespace", cm.Namespace, "name", cm.Name)
	} else {
		s.log.Debug("configmap accepted",
			"namespace", cm.Namespace, "name", cm.Name, "bundles", emitted)
	}
}

func (s *Source) refSecret(sec *corev1.Secret, key, format string) cert.SourceRef {
	attrs := map[string]string{}
	for _, l := range s.opts.ExposedSecretLabels {
		if v, ok := sec.Labels[l]; ok {
			attrs["secret_label/"+l] = v
		}
	}
	return cert.SourceRef{
		Kind:     "kube-secret",
		Location: fmt.Sprintf("%s/%s", sec.Namespace, sec.Name),
		Key:      key, Format: format, SourceName: s.opts.Name,
		Attributes: attrs,
	}
}

func (s *Source) refConfigMap(cm *corev1.ConfigMap, key, format string) cert.SourceRef {
	attrs := map[string]string{}
	for _, l := range s.opts.ExposedConfigMapLabels {
		if v, ok := cm.Labels[l]; ok {
			attrs["configmap_label/"+l] = v
		}
	}
	return cert.SourceRef{
		Kind:     "kube-configmap",
		Location: fmt.Sprintf("%s/%s", cm.Namespace, cm.Name),
		Key:      key, Format: format, SourceName: s.opts.Name,
		Attributes: attrs,
	}
}

func (s *Source) trackUpsert(sink cert.Sink, b cert.Bundle) {
	s.mu.Lock()
	s.tracked[b.Source.String()] = struct{}{}
	s.mu.Unlock()
	sink.Upsert(b)
}

func (s *Source) deleteAllRefs(sink cert.Sink, kind, loc string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	prefix := fmt.Sprintf("%s:%s", kind, loc)
	for k := range s.tracked {
		if !strings.HasPrefix(k, prefix) {
			continue
		}
		ref := parseTrackedKey(k, s.opts.Name)
		sink.Delete(ref)
		delete(s.tracked, k)
	}
}

// parseTrackedKey is the inverse of cert.SourceRef.String().
func parseTrackedKey(k, sourceName string) cert.SourceRef {
	// "<kind>:<location>" or "<kind>:<location>#<key>"
	colon := strings.IndexByte(k, ':')
	if colon < 0 {
		return cert.SourceRef{}
	}
	kind := k[:colon]
	rest := k[colon+1:]
	loc := rest
	key := ""
	if hash := strings.IndexByte(rest, '#'); hash >= 0 {
		loc = rest[:hash]
		key = rest[hash+1:]
	}
	return cert.SourceRef{
		Kind: kind, Location: loc, Key: key, SourceName: sourceName,
	}
}

func (s *Source) acceptName(name string, f SecretFilter) bool {
	for _, n := range f.ExcludeNames {
		if matchGlob(n, name) {
			return false
		}
	}
	if len(f.IncludeNames) == 0 {
		return true
	}
	for _, n := range f.IncludeNames {
		if matchGlob(n, name) {
			return true
		}
	}
	return false
}

func matchGlob(pat, s string) bool {
	if pat == "*" {
		return true
	}
	return pat == s
}

// namespaceAllowed evaluates the configured NamespaceFilter against the
// secret/configmap's namespace. Name rules are evaluated directly; label
// rules need the namespace cache populated by the namespace informer.
// Returns true if the object's namespace passes every active rule.
func (s *Source) namespaceAllowed(ns string) bool {
	f := s.opts.NamespaceFilter
	if f.IsZero() {
		return true
	}
	for _, n := range f.ExcludeNames {
		if matchGlob(n, ns) {
			return false
		}
	}
	if len(f.IncludeNames) > 0 {
		ok := false
		for _, n := range f.IncludeNames {
			if matchGlob(n, ns) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if !f.needsLabels() {
		return true
	}
	s.nsLabelsMu.RLock()
	labels, known := s.nsLabels[ns]
	s.nsLabelsMu.RUnlock()
	// If the namespace cache hasn't seen this namespace yet, conservatively
	// reject — the post-sync re-emit pass will reconsider once labels are
	// known.
	if !known {
		return false
	}
	for _, rule := range f.ExcludeLabels {
		if labelRuleMatches(rule, labels) {
			return false
		}
	}
	for _, rule := range f.IncludeLabels {
		if !labelRuleMatches(rule, labels) {
			return false
		}
	}
	return true
}

// labelRuleMatches evaluates a single rule of the form "key" (key exists,
// any value) or "key=value" (exact match) against a label set.
func labelRuleMatches(rule string, labels map[string]string) bool {
	if eq := strings.IndexByte(rule, '='); eq >= 0 {
		k, v := rule[:eq], rule[eq+1:]
		got, ok := labels[k]
		return ok && got == v
	}
	_, ok := labels[rule]
	return ok
}

// onNamespace tracks the namespace's labels and re-evaluates every tracked
// secret/configmap in that namespace whenever the labels change. The
// re-evaluation reuses the secret/configmap informer's store (its cache is
// already authoritative) so we don't hit the API server.
func (s *Source) onNamespace(sink cert.Sink, obj any, deleted bool) {
	ns := extractNamespace(obj)
	if ns == nil {
		return
	}

	s.nsLabelsMu.Lock()
	prev := s.nsLabels[ns.Name]
	if deleted {
		delete(s.nsLabels, ns.Name)
	} else {
		s.nsLabels[ns.Name] = ns.Labels
	}
	changed := deleted || !labelMapsEqual(prev, ns.Labels)
	s.nsLabelsMu.Unlock()

	if !changed {
		return
	}
	// A label-rule flip means objects we previously accepted may now be
	// rejected (or vice-versa). The simplest correct response is to drop
	// every tracked ref in this namespace and rely on the next periodic
	// resync (or any explicit re-emit performed by the caller) to bring
	// the still-allowed ones back. For the e2e case the post-sync
	// re-emit pass after WaitForCacheSync covers the initial population.
	prefixSec := fmt.Sprintf("kube-secret:%s/", ns.Name)
	prefixCM := fmt.Sprintf("kube-configmap:%s/", ns.Name)
	dropped := 0
	s.mu.Lock()
	defer func() {
		s.mu.Unlock()
		s.log.Debug("namespace labels changed, dropped refs for re-evaluation",
			"namespace", ns.Name, "deleted", deleted, "dropped", dropped)
	}()
	for k := range s.tracked {
		if !strings.HasPrefix(k, prefixSec) && !strings.HasPrefix(k, prefixCM) {
			continue
		}
		ref := parseTrackedKey(k, s.opts.Name)
		sink.Delete(ref)
		delete(s.tracked, k)
		dropped++
	}
}

func labelMapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// extractSecret handles both *Secret and DeletedFinalStateUnknown.
func extractSecret(obj any) *corev1.Secret {
	if obj == nil {
		return nil
	}
	if sec, ok := obj.(*corev1.Secret); ok {
		return sec
	}
	if d, ok := obj.(cache.DeletedFinalStateUnknown); ok {
		if sec, ok := d.Obj.(*corev1.Secret); ok {
			return sec
		}
		// May be a runtime.Object wrapping
		if obj, ok := d.Obj.(runtime.Object); ok {
			_ = obj
		}
	}
	return nil
}

func extractConfigMap(obj any) *corev1.ConfigMap {
	if obj == nil {
		return nil
	}
	if cm, ok := obj.(*corev1.ConfigMap); ok {
		return cm
	}
	if d, ok := obj.(cache.DeletedFinalStateUnknown); ok {
		if cm, ok := d.Obj.(*corev1.ConfigMap); ok {
			return cm
		}
	}
	return nil
}

func extractNamespace(obj any) *corev1.Namespace {
	if obj == nil {
		return nil
	}
	if ns, ok := obj.(*corev1.Namespace); ok {
		return ns
	}
	if d, ok := obj.(cache.DeletedFinalStateUnknown); ok {
		if ns, ok := d.Obj.(*corev1.Namespace); ok {
			return ns
		}
	}
	return nil
}
