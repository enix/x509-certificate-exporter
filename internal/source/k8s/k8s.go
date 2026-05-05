// Package k8s implements a Source that watches Kubernetes Secrets (and
// optionally ConfigMaps).
//
// Architecture: Secrets and ConfigMaps are observed via a direct paginated
// LIST + WATCH loop, not a client-go SharedInformer. The reason is that
// client-go's pager.List accumulates every page into a single in-memory
// list before yielding to a transform or event handler — on clusters with
// many large objects (Helm release secrets, OPA-policy ConfigMaps) the
// initial sync OOMs the pod before any object can be filtered or freed.
// The direct loop processes each page inline (default 50 objects) and
// drops it before fetching the next, bounding peak memory to roughly
// pageSize × average object size.
//
// Namespaces are still observed via a SharedInformer (small objects, no
// OOM risk; we need a queryable cache of namespace labels). The namespace
// informer is started only when the source declares label-based namespace
// rules.
//
// Key features:
//
//   - Server-side LabelSelector / FieldSelector pushed onto every LIST and
//     WATCH call. The Secret type is automatically translated into a
//     fieldSelector when all secret rules share a single Type.
//   - Initial paginated LIST then WATCH from the returned ResourceVersion;
//     resync timer (default 30 min) re-runs the LIST cycle.
//   - First sync gates the source's "ready" state.
//   - Delete events propagate immediately so deleted Secrets/ConfigMaps
//     disappear from the registry.
//   - A namespace label change short-circuits the resync timer so
//     newly-allowed objects come back without waiting up to ResyncEvery.
//
// What is not covered: adaptive RBAC scope detection
// (SelfSubjectAccessReview), the WatchListClient feature gate (was tested
// during the OOM investigation; it does not avoid the accumulation since
// the DeltaFIFO buffers events before the consumer processes them).
package k8s

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	"github.com/enix/x509-certificate-exporter/v4/pkg/cert"
)

// Built-in defaults applied by New() and the LIST/WATCH loops. Centralised
// so a tweak in one place doesn't drift the others.
const (
	// DefaultResyncEvery is how often the source re-LISTs from scratch
	// even when the WATCH stream is healthy. Defends against missed
	// events and namespace label changes the source can't otherwise
	// detect.
	DefaultResyncEvery = 30 * time.Minute
	// DefaultListPageSize is the per-page Limit used when the user
	// hasn't set Options.ListPageSize. See Options.ListPageSize for the
	// memory/throughput trade-off.
	DefaultListPageSize = 50
	// MaxListPageSize clamps Options.ListPageSize to a value the
	// kube-apiserver will actually serve in one round-trip.
	MaxListPageSize = 1000
	// InitialBackoff is the wait between the first and second retry
	// after a failed LIST. Doubles up to MaxBackoff and is jittered
	// (±25%) to avoid replicas synchronising their retries.
	InitialBackoff = 2 * time.Second
	// MaxBackoff caps the exponential retry delay. Tuned to align with
	// typical etcd-quorum-loss recovery (~30s–1min): a longer cap means
	// the source misses the API server's recovery window and metrics
	// stay stale for minutes after the cluster is healthy again. Stays
	// generous enough to not hammer a sustained outage.
	MaxBackoff = 1 * time.Minute
	// ListRequestTimeout bounds a single LIST call. The k8s client
	// applies no per-request deadline of its own, so a hung apiserver
	// would otherwise pin the source goroutine indefinitely. WATCH calls
	// don't need this guard — the apiserver enforces a ~5–10 min max
	// stream lifetime on its side.
	ListRequestTimeout = 30 * time.Second
	// WatchFlapThreshold classifies a WATCH that closes within this
	// duration as a flap. Such closes trigger a separate backoff on top
	// of the LIST retry logic so that an auth-token-expiry or transient
	// network issue doesn't translate into a tight LIST/WATCH loop.
	WatchFlapThreshold = 5 * time.Second
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

	// ListPageSize is the per-call Limit applied to the paginated initial
	// LIST and to resync re-LISTs. Bounded to [1, 1000]; defaults to 50
	// when zero. Larger values reduce round-trips but raise the peak
	// memory during sync (proportional to average object size).
	ListPageSize int64

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

	// counters incremented per object processed during list/watch.
	// Reset at the start of each list cycle so the value reflects the
	// current cycle's progress (used by the debug memory reporter).
	secretsSeen atomic.Int64
	cmsSeen     atomic.Int64

	// nsLabelsChanged is non-blockingly poked by onNamespace after a
	// label transition so the secrets goroutine can short-circuit its
	// 30-min resync timer and re-list immediately. Buffer of 1 coalesces
	// rapid bursts.
	nsLabelsChanged chan struct{}
}

func New(opts Options, logger *slog.Logger) *Source {
	if logger == nil {
		logger = slog.Default()
	}
	if opts.ResyncEvery <= 0 {
		opts.ResyncEvery = DefaultResyncEvery
	}
	switch {
	case opts.ListPageSize <= 0:
		opts.ListPageSize = DefaultListPageSize
	case opts.ListPageSize > MaxListPageSize:
		opts.ListPageSize = MaxListPageSize
	}
	return &Source{
		opts:            opts,
		log:             logger.With("source_kind", "kubernetes", "source_name", opts.Name),
		tracked:         map[string]struct{}{},
		nsLabels:        map[string]map[string]string{},
		nsLabelsChanged: make(chan struct{}, 1),
	}
}

func (s *Source) Name() string { return s.opts.Name }

// Run wires up the namespace informer (when needed) and the Secret /
// ConfigMap direct watches, then blocks until ctx is cancelled.
//
// Secrets and ConfigMaps each run their own paginated LIST + WATCH loop
// (see runSecretsDirect / runConfigMapsDirect). The Namespace informer
// is the only client-go SharedInformer still in use; it is created only
// when the source declares label-based namespace rules.
func (s *Source) Run(ctx context.Context, sink cert.Sink) error {
	if s.opts.Client == nil {
		return fmt.Errorf("k8s source %q: no client", s.opts.Name)
	}
	scope := "cluster"
	if s.opts.Namespace != "" {
		scope = "namespace"
	}
	runStart := time.Now()
	s.log.Debug("kubernetes source starting",
		"scope", scope,
		"namespace", s.opts.Namespace,
		"resync_every", s.opts.ResyncEvery,
		"secret_rules", len(s.opts.SecretRules),
		"configmap_rules", len(s.opts.ConfigMapRules),
	)

	infName, err := cache.NewInformerName(s.opts.Name)
	if err != nil {
		return fmt.Errorf("create informer name %q: %w", s.opts.Name, err)
	}
	defer infName.Release()

	// --- Namespace informer (unchanged: small objects, no OOM risk) ---
	// Cluster-scoped only; label-based namespace rules require it.
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
		// Namespace labels must be known before we process any secret, so
		// we sync the namespace cache first before starting the secret list.
		nsSyncStart := time.Now()
		s.log.Debug("waiting for namespace informer sync")
		if !waitForCacheSync(ctx, []cache.SharedInformer{nsInf}) {
			s.log.Error("namespace informer sync did not complete",
				"cause", ctx.Err(), "elapsed", time.Since(nsSyncStart))
			s.signalReady(false)
			return ctx.Err()
		}
		s.log.Debug("namespace informer synced", "elapsed", time.Since(nsSyncStart))
	}

	// --- Secrets and ConfigMaps: direct paginated LIST + WATCH ---
	// Both resources use the same memory-safe approach (replaces the
	// SharedInformer that would accumulate all objects via pager.List
	// before our transform could fire). Each goroutine signals its
	// initial sync via a dedicated channel.
	secretsSynced := make(chan struct{})
	cmsSynced := make(chan struct{})
	var secretsDone, cmsDone chan struct{}

	if len(s.opts.SecretRules) > 0 {
		secretsDone = make(chan struct{})
		go func() {
			defer close(secretsDone)
			s.runSecretsDirect(ctx, sink, secretsSynced)
		}()
	} else {
		close(secretsSynced)
	}

	if len(s.opts.ConfigMapRules) > 0 {
		cmsDone = make(chan struct{})
		go func() {
			defer close(cmsDone)
			s.runConfigMapsDirect(ctx, sink, cmsSynced)
		}()
	} else {
		close(cmsSynced)
	}

	// Memory reporter: only runs during the initial sync (debug only).
	// Stops as soon as ready is signalled — in steady state pprof is
	// the right tool, not 1Hz STW ReadMemStats.
	syncCtx, syncCancel := context.WithCancel(ctx)
	defer syncCancel()
	if s.log.Enabled(ctx, slog.LevelDebug) {
		go s.runMemoryReporter(syncCtx)
	}

	s.log.Debug("waiting for initial sync",
		"secrets", len(s.opts.SecretRules) > 0,
		"configmaps", len(s.opts.ConfigMapRules) > 0,
	)
	for _, ch := range []<-chan struct{}{secretsSynced, cmsSynced} {
		select {
		case <-ctx.Done():
			s.signalReady(false)
			return ctx.Err()
		case <-ch:
		}
	}
	syncCancel()
	s.signalReady(true)
	s.log.Info("initial sync complete",
		"namespace", s.opts.Namespace, "elapsed", time.Since(runStart))

	// Block until cancelled; the secrets/configmaps goroutines run their
	// own loops driven by ctx.
	<-ctx.Done()
	s.log.Debug("kubernetes source stopping", "cause", ctx.Err())
	if secretsDone != nil {
		<-secretsDone
	}
	if cmsDone != nil {
		<-cmsDone
	}
	return ctx.Err()
}

// runMemoryReporter logs heap stats once a second until ctx is cancelled.
// Used during the initial sync to correlate memory growth with the count
// of secrets/configmaps already processed. ReadMemStats does a brief STW,
// so we deliberately stop it as soon as the initial sync completes.
func (s *Source) runMemoryReporter(ctx context.Context) {
	t := time.NewTicker(1 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			var ms runtime.MemStats
			runtime.ReadMemStats(&ms)
			s.log.Debug("memory",
				"secrets_seen", s.secretsSeen.Load(),
				"cms_seen", s.cmsSeen.Load(),
				"heap_alloc_mb", ms.HeapAlloc>>20,
				"heap_inuse_mb", ms.HeapInuse>>20,
				"heap_sys_mb", ms.HeapSys>>20,
				"next_gc_mb", ms.NextGC>>20,
				"num_gc", ms.NumGC,
			)
		}
	}
}

func (s *Source) signalReady(success bool) {
	if s.opts.OnReady != nil {
		s.opts.OnReady(success)
	}
	if s.opts.FirstSyncDone != nil {
		select {
		case <-s.opts.FirstSyncDone:
		default:
			close(s.opts.FirstSyncDone)
		}
	}
}

// runSecretsDirect is the memory-safe replacement for the Secrets
// SharedInformer. It loops:
//
//  1. Paginated LIST (Limit=50): processes each page inline so the GC can
//     reclaim each batch before the next is fetched. Peak memory is bounded
//     to ~50 secrets at a time regardless of cluster size.
//  2. WATCH from the list's ResourceVersion: processes incremental events.
//  3. On watch error / channel close: go back to step 1 (full resync).
//  4. On resync timer: go back to step 1.
//
// The goroutine exits when ctx is cancelled.
func (s *Source) runSecretsDirect(ctx context.Context, sink cert.Sink, firstSyncDone chan<- struct{}) {
	listBackoff := InitialBackoff
	watchBackoff := InitialBackoff
	resync := time.NewTicker(s.opts.ResyncEvery)
	defer resync.Stop()
	firstSync := true

	for {
		rv, err := s.listSecretPages(ctx, sink)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			// Jittered exponential backoff (±25%, capped at MaxBackoff).
			// Without jitter several replicas retry in lockstep when the
			// API server flakes.
			jittered := time.Duration(float64(listBackoff) * (0.75 + rand.Float64()*0.5))
			s.log.Error("secret list failed, will retry", "err", err, "backoff", jittered)
			select {
			case <-ctx.Done():
				return
			case <-time.After(jittered):
				listBackoff = min(listBackoff*2, MaxBackoff)
				continue
			}
		}
		listBackoff = InitialBackoff

		if firstSync {
			firstSync = false
			close(firstSyncDone)
		}

		needResync, flap := s.watchSecretLoop(ctx, sink, rv, resync.C)
		if !needResync {
			return // ctx cancelled
		}
		if flap {
			// Watch closed (or failed to start) within WatchFlapThreshold:
			// avoid the tight LIST→WATCH-close→LIST loop by sleeping for
			// an exponentially-increasing, jittered backoff before the
			// next iteration. Tracked separately from listBackoff because
			// LIST and WATCH have independent failure modes.
			jittered := time.Duration(float64(watchBackoff) * (0.75 + rand.Float64()*0.5))
			s.log.Warn("secret watch flapped, backing off before re-list", "wait", jittered)
			select {
			case <-ctx.Done():
				return
			case <-time.After(jittered):
				watchBackoff = min(watchBackoff*2, MaxBackoff)
			}
		} else {
			watchBackoff = InitialBackoff
		}
		s.log.Debug("resyncing secrets (full relist)")
	}
}

// listSecretPages fetches all secrets page by page (Limit=ListPageSize), calls
// onSecret for each, and releases each page to the GC before fetching the
// next. After the full list, refs for secrets that no longer exist are
// removed from the registry.
func (s *Source) listSecretPages(ctx context.Context, sink cert.Sink) (rv string, err error) {
	var cont string
	seen := map[string]struct{}{}
	page := 0
	listStart := time.Now()
	// Reset the counter at the start of each list cycle so the debug
	// reporter shows progress for THIS cycle, not a cumulative total.
	s.secretsSeen.Store(0)

	for {
		var list *corev1.SecretList
		listCtx, cancel := context.WithTimeout(ctx, ListRequestTimeout)
		list, err = s.opts.Client.CoreV1().Secrets(s.opts.Namespace).List(listCtx, metav1.ListOptions{
			LabelSelector: s.opts.SecretSelector.LabelSelector,
			FieldSelector: s.opts.SecretSelector.FieldSelector,
			Limit:         s.opts.ListPageSize,
			Continue:      cont,
		})
		cancel()
		if err != nil {
			return
		}
		page++
		s.log.Debug("secret list page", "page", page, "count", len(list.Items), "more", list.Continue != "")

		for i := range list.Items {
			sec := &list.Items[i]
			s.secretsSeen.Add(1)
			seen[sec.Namespace+"/"+sec.Name] = struct{}{}
			s.onSecret(sink, sec, false)
		}

		rv = list.ResourceVersion
		cont = list.Continue

		// Drop the only reference to this page so its objects become
		// GC-eligible before the next API call allocates the next batch.
		// We don't force a GC: with the heap target tracking, the GC
		// already keeps up at this allocation rate.
		list = nil

		if cont == "" {
			break
		}
	}

	s.log.Debug("secret list complete",
		"pages", page,
		"total", len(seen),
		"elapsed", time.Since(listStart),
	)
	s.deleteAbsentRefs(sink, cert.KindKubeSecret, seen)
	return
}

// watchSecretLoop watches secrets from rv, processing events until the watch
// closes, an error occurs, or the resync timer fires.
//
// Returns:
//
//   - needResync: true if the caller should re-list, false if ctx was cancelled.
//   - flap: true when the watch closed because of an error/EOF within
//     WatchFlapThreshold of starting. The caller uses this to apply an
//     extra backoff on top of any LIST retry, so an auth-token-expiry or
//     network blip that re-establishes a watch only to immediately drop
//     it doesn't translate into a tight LIST/WATCH loop.
func (s *Source) watchSecretLoop(ctx context.Context, sink cert.Sink, rv string, resyncC <-chan time.Time) (needResync, flap bool) {
	watcher, err := s.opts.Client.CoreV1().Secrets(s.opts.Namespace).Watch(ctx, metav1.ListOptions{
		LabelSelector:       s.opts.SecretSelector.LabelSelector,
		FieldSelector:       s.opts.SecretSelector.FieldSelector,
		ResourceVersion:     rv,
		AllowWatchBookmarks: true,
	})
	if err != nil {
		if ctx.Err() != nil {
			return false, false
		}
		s.log.Error("secret watch start failed, triggering resync", "err", err)
		return true, true // failed to even open the stream — treat like a flap
	}
	defer watcher.Stop()
	started := time.Now()
	s.log.Debug("watching secrets", "resource_version", rv)

	for {
		select {
		case <-ctx.Done():
			return false, false
		case <-resyncC:
			s.log.Debug("resync timer fired")
			return true, false
		case <-s.nsLabelsChanged:
			s.log.Debug("namespace labels changed, triggering immediate resync")
			return true, false
		case event, ok := <-watcher.ResultChan():
			if !ok {
				flap := time.Since(started) < WatchFlapThreshold
				s.log.Debug("secret watch channel closed, triggering resync", "flap", flap)
				return true, flap
			}
			switch event.Type {
			case watch.Added, watch.Modified:
				if sec, ok := event.Object.(*corev1.Secret); ok {
					s.onSecret(sink, sec, false)
				}
			case watch.Deleted:
				if sec, ok := event.Object.(*corev1.Secret); ok {
					s.onSecret(sink, sec, true)
				}
			case watch.Bookmark:
				// Bookmarks advance the API server's notion of the watch
				// resourceVersion. We deliberately don't track them: any
				// disconnect or resync triggers a full re-LIST that
				// obtains a fresh RV, so locally bookkeeping bookmark
				// RVs would be pure dead state.
			case watch.Error:
				flap := time.Since(started) < WatchFlapThreshold
				s.log.Error("secret watch error event, triggering resync",
					"event", fmt.Sprintf("%v", event.Object), "flap", flap)
				return true, flap
			}
		}
	}
}

// deleteAbsentRefs removes from the cert registry any ref of the given
// kind ("kube-secret" or "kube-configmap") whose location ("namespace/name")
// is not present in seen. Called after each full list to clean up objects
// that disappeared while the watch was disconnected (or, for the very first
// list, that disappeared between previous runs).
func (s *Source) deleteAbsentRefs(sink cert.Sink, kind string, seen map[string]struct{}) {
	prefix := kind + ":"
	s.mu.Lock()
	defer s.mu.Unlock()
	for k := range s.tracked {
		if !strings.HasPrefix(k, prefix) {
			continue
		}
		loc := k[len(prefix):]
		if h := strings.IndexByte(loc, '#'); h >= 0 {
			loc = loc[:h]
		}
		if _, ok := seen[loc]; !ok {
			ref := parseTrackedKey(k, s.opts.Name)
			sink.Delete(ref)
			delete(s.tracked, k)
		}
	}
}

func waitForCacheSync(ctx context.Context, infs []cache.SharedInformer) bool {
	for _, inf := range infs {
		if !cache.WaitForCacheSync(ctx.Done(), inf.HasSynced) {
			return false
		}
	}
	return true
}

// runConfigMapsDirect is the memory-safe replacement for the ConfigMap
// SharedInformer. Same shape as runSecretsDirect: paginated LIST + WATCH
// with each page processed inline so the GC can reclaim before the next
// page arrives. Listed here instead of in the informer because client-go's
// pager.List accumulates all pages before yielding, which OOMs on clusters
// with many large ConfigMaps (Helm hooks, OPA policies, kubeadm cluster-info).
func (s *Source) runConfigMapsDirect(ctx context.Context, sink cert.Sink, firstSyncDone chan<- struct{}) {
	listBackoff := InitialBackoff
	watchBackoff := InitialBackoff
	resync := time.NewTicker(s.opts.ResyncEvery)
	defer resync.Stop()
	firstSync := true

	for {
		rv, err := s.listConfigMapPages(ctx, sink)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			jittered := time.Duration(float64(listBackoff) * (0.75 + rand.Float64()*0.5))
			s.log.Error("configmap list failed, will retry", "err", err, "backoff", jittered)
			select {
			case <-ctx.Done():
				return
			case <-time.After(jittered):
				listBackoff = min(listBackoff*2, MaxBackoff)
				continue
			}
		}
		listBackoff = InitialBackoff

		if firstSync {
			firstSync = false
			close(firstSyncDone)
		}

		needResync, flap := s.watchConfigMapLoop(ctx, sink, rv, resync.C)
		if !needResync {
			return // ctx cancelled
		}
		if flap {
			jittered := time.Duration(float64(watchBackoff) * (0.75 + rand.Float64()*0.5))
			s.log.Warn("configmap watch flapped, backing off before re-list", "wait", jittered)
			select {
			case <-ctx.Done():
				return
			case <-time.After(jittered):
				watchBackoff = min(watchBackoff*2, MaxBackoff)
			}
		} else {
			watchBackoff = InitialBackoff
		}
		s.log.Debug("resyncing configmaps (full relist)")
	}
}

// listConfigMapPages fetches all configmaps page by page (Limit=ListPageSize) and
// processes each page inline. Mirrors listSecretPages.
func (s *Source) listConfigMapPages(ctx context.Context, sink cert.Sink) (rv string, err error) {
	var cont string
	seen := map[string]struct{}{}
	page := 0
	listStart := time.Now()
	s.cmsSeen.Store(0)

	for {
		var list *corev1.ConfigMapList
		listCtx, cancel := context.WithTimeout(ctx, ListRequestTimeout)
		list, err = s.opts.Client.CoreV1().ConfigMaps(s.opts.Namespace).List(listCtx, metav1.ListOptions{
			LabelSelector: s.opts.ConfigMapSelector.LabelSelector,
			FieldSelector: s.opts.ConfigMapSelector.FieldSelector,
			Limit:         s.opts.ListPageSize,
			Continue:      cont,
		})
		cancel()
		if err != nil {
			return
		}
		page++
		s.log.Debug("configmap list page", "page", page, "count", len(list.Items), "more", list.Continue != "")

		for i := range list.Items {
			cm := &list.Items[i]
			s.cmsSeen.Add(1)
			seen[cm.Namespace+"/"+cm.Name] = struct{}{}
			s.onConfigMap(sink, cm, false)
		}

		rv = list.ResourceVersion
		cont = list.Continue
		list = nil

		if cont == "" {
			break
		}
	}

	s.log.Debug("configmap list complete",
		"pages", page,
		"total", len(seen),
		"elapsed", time.Since(listStart),
	)
	s.deleteAbsentRefs(sink, cert.KindKubeConfigMap, seen)
	return
}

// watchConfigMapLoop is the WATCH counterpart to watchSecretLoop. See
// that function's doc-comment for the meaning of needResync and flap.
func (s *Source) watchConfigMapLoop(ctx context.Context, sink cert.Sink, rv string, resyncC <-chan time.Time) (needResync, flap bool) {
	watcher, err := s.opts.Client.CoreV1().ConfigMaps(s.opts.Namespace).Watch(ctx, metav1.ListOptions{
		LabelSelector:       s.opts.ConfigMapSelector.LabelSelector,
		FieldSelector:       s.opts.ConfigMapSelector.FieldSelector,
		ResourceVersion:     rv,
		AllowWatchBookmarks: true,
	})
	if err != nil {
		if ctx.Err() != nil {
			return false, false
		}
		s.log.Error("configmap watch start failed, triggering resync", "err", err)
		return true, true
	}
	defer watcher.Stop()
	started := time.Now()
	s.log.Debug("watching configmaps", "resource_version", rv)

	for {
		select {
		case <-ctx.Done():
			return false, false
		case <-resyncC:
			s.log.Debug("resync timer fired (configmaps)")
			return true, false
		case <-s.nsLabelsChanged:
			s.log.Debug("namespace labels changed, triggering immediate resync (configmaps)")
			return true, false
		case event, ok := <-watcher.ResultChan():
			if !ok {
				flap := time.Since(started) < WatchFlapThreshold
				s.log.Debug("configmap watch channel closed, triggering resync", "flap", flap)
				return true, flap
			}
			switch event.Type {
			case watch.Added, watch.Modified:
				if cm, ok := event.Object.(*corev1.ConfigMap); ok {
					s.onConfigMap(sink, cm, false)
				}
			case watch.Deleted:
				if cm, ok := event.Object.(*corev1.ConfigMap); ok {
					s.onConfigMap(sink, cm, true)
				}
			case watch.Bookmark:
				// See watchSecretLoop's matching case for why bookmark
				// RVs are intentionally ignored.
			case watch.Error:
				flap := time.Since(started) < WatchFlapThreshold
				s.log.Error("configmap watch error event, triggering resync",
					"event", fmt.Sprintf("%v", event.Object), "flap", flap)
				return true, flap
			}
		}
	}
}

func (s *Source) onSecret(sink cert.Sink, obj any, deleted bool) {
	sec := extractSecret(obj)
	if sec == nil {
		return
	}
	loc := fmt.Sprintf("%s/%s", sec.Namespace, sec.Name)
	if deleted {
		s.deleteAllRefs(sink, cert.KindKubeSecret, loc)
		s.log.Debug("secret deleted", "namespace", sec.Namespace, "name", sec.Name)
		return
	}
	if !s.acceptName(sec.Name, s.opts.SecretFilter) {
		s.deleteAllRefs(sink, cert.KindKubeSecret, loc)
		s.log.Debug("secret rejected", "namespace", sec.Namespace, "name", sec.Name, "reason", cert.ReasonNameFilter)
		return
	}
	if !s.namespaceAllowed(sec.Namespace) {
		s.deleteAllRefs(sink, cert.KindKubeSecret, loc)
		s.log.Debug("secret rejected", "namespace", sec.Namespace, "name", sec.Name, "reason", cert.ReasonNamespaceFilter)
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
		s.deleteAllRefs(sink, cert.KindKubeConfigMap, loc)
		s.log.Debug("configmap deleted", "namespace", cm.Namespace, "name", cm.Name)
		return
	}
	if !s.acceptName(cm.Name, s.opts.ConfigMapFilter) {
		s.deleteAllRefs(sink, cert.KindKubeConfigMap, loc)
		s.log.Debug("configmap rejected", "namespace", cm.Namespace, "name", cm.Name, "reason", cert.ReasonNameFilter)
		return
	}
	if !s.namespaceAllowed(cm.Namespace) {
		s.deleteAllRefs(sink, cert.KindKubeConfigMap, loc)
		s.log.Debug("configmap rejected", "namespace", cm.Namespace, "name", cm.Name, "reason", cert.ReasonNamespaceFilter)
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
			attrs[cert.AttrSecretLabelPrefix+l] = v
		}
	}
	return cert.SourceRef{
		Kind:     cert.KindKubeSecret,
		Location: fmt.Sprintf("%s/%s", sec.Namespace, sec.Name),
		Key:      key, Format: format, SourceName: s.opts.Name,
		Attributes: attrs,
	}
}

func (s *Source) refConfigMap(cm *corev1.ConfigMap, key, format string) cert.SourceRef {
	attrs := map[string]string{}
	for _, l := range s.opts.ExposedConfigMapLabels {
		if v, ok := cm.Labels[l]; ok {
			attrs[cert.AttrConfigMapLabelPrefix+l] = v
		}
	}
	return cert.SourceRef{
		Kind:     cert.KindKubeConfigMap,
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

// deleteAllRefs scans the entire tracked set looking for entries that
// match a given (kind, location). On large clusters with high churn of
// namespace labels (which call deleteAllRefs on every namespace event)
// this O(total-refs) loop becomes the dominant cost in onNamespace.
//
// TODO(perf): replace s.tracked with a two-level index
// `map[kind+":"+namespace+"/"]map[string]struct{}` so deleteAllRefs only
// walks refs that actually live in the affected namespace. Deferred
// until we observe the bottleneck in practice — see Lot 4 of the audit
// plan.
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
// secret/configmap in that namespace whenever the labels change. We drop
// every ref in the affected namespace, then poke `nsLabelsChanged` so the
// secret/configmap goroutines short-circuit their resync timer and re-list
// immediately — newly-allowed objects come back without waiting for the
// 30-min cycle, newly-rejected ones are simply not re-emitted.
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
	// Wake up the secrets list+watch loop so newly-allowed secrets in this
	// namespace come back without waiting for the 30-min resync timer.
	// Non-blocking: the channel has buffer 1, so concurrent label changes
	// coalesce into a single resync.
	select {
	case s.nsLabelsChanged <- struct{}{}:
	default:
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
		if obj, ok := d.Obj.(kruntime.Object); ok {
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
