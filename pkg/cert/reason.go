package cert

// Canonical reason codes for ItemError. These appear as the "reason" label
// of x509_source_errors_total, so they form a stable contract.
const (
	ReasonBadPEM             = "bad_pem"
	ReasonBadCRL             = "bad_crl"
	ReasonBadDER             = "bad_der"
	ReasonBadJKS             = "bad_jks"
	ReasonNoCertificateFound = "no_certificate_found"
	ReasonBadPKCS12          = "bad_pkcs12"
	ReasonBadPassphrase      = "bad_passphrase"
	ReasonReadFailed         = "read_failed"
	ReasonPermissionDenied   = "permission_denied"
	ReasonNotFound           = "not_found"
	ReasonAPIError           = "api_error"
	ReasonDecodeFailed       = "decode_failed"
	ReasonBrokenSymlink      = "broken_symlink"
	ReasonOutOfScopeSymlink  = "out_of_scope_symlink"
	ReasonParseTimeout       = "parse_timeout"
	ReasonWalkError          = "walk_error"
	ReasonRateLimited        = "rate_limited"
	// ReasonHTTPPrefix is concatenated with the HTTP status code (e.g.
	// "http_503", "http_401") to form the reason for kube-apiserver
	// errors that don't map to a more specific cause.
	ReasonHTTPPrefix = "http_"

	// ReasonNameFilter / ReasonNamespaceFilter are not exposed as
	// Prometheus reasons today — they appear only as the "reason" key
	// of debug logs when an object is rejected by client-side filters.
	// Centralised here so the wording stays consistent.
	ReasonNameFilter      = "name_filter"
	ReasonNamespaceFilter = "namespace_filter"

	// Kubernetes-source transport reasons. Surface as the `reason` label
	// of x509_kube_transport_errors_total. Distinct from the bundle
	// reasons above: these describe what went wrong below the bundle
	// layer (LIST/WATCH/informer), not what went wrong parsing a
	// certificate. Kept here so call sites in pkg/source/k8s and the
	// alerting rules stay in lockstep on spelling.
	ReasonListFailed         = "list_failed"
	ReasonWatchStartFailed   = "watch_start_failed"
	ReasonWatchErrorEvent    = "watch_error_event"
	ReasonWatchFlapped       = "watch_flapped"
	ReasonNamespaceSyncFail  = "namespace_sync_failed"
)

// BundleReasons enumerates every static reason that may appear as a
// label on `x509_source_errors_total`. Used by Registry pre-init to
// materialise counter series at zero so they show up in /metrics and
// in rate()/increase() the moment the first event lands — without
// it, the absence-of-series ambiguity ("counter at 0" vs. "metric not
// reporting") leaks into dashboards and alerts.
//
// HTTP-status reasons (`http_NNN`) are deliberately excluded — they're
// dynamic and would require enumerating every code that the kube
// apiserver might surface. Alerts aggregating across `reason` (the
// pattern used by the chart's SourceErrors[Sustained] alert) still see
// the static-reason baseline series, so the alert query is well-defined
// before any error has fired.
var BundleReasons = []string{
	ReasonBadPEM,
	ReasonBadCRL,
	ReasonBadDER,
	ReasonBadJKS,
	ReasonBadPKCS12,
	ReasonBadPassphrase,
	ReasonNoCertificateFound,
	ReasonReadFailed,
	ReasonPermissionDenied,
	ReasonNotFound,
	ReasonAPIError,
	ReasonDecodeFailed,
	ReasonBrokenSymlink,
	ReasonOutOfScopeSymlink,
	ReasonParseTimeout,
	ReasonWalkError,
	ReasonRateLimited,
}

// KubeTransportPerResourceReasons enumerates the static reasons that
// may appear as the `reason` label of `x509_kube_transport_errors_total`
// for `resource in {secrets, configmaps}`. The namespace-informer
// reason is separate (a single `namespace_sync_failed` value bound to
// `resource="namespaces"`); see Registry.PreInitKubeTransport.
var KubeTransportPerResourceReasons = []string{
	ReasonListFailed,
	ReasonWatchStartFailed,
	ReasonWatchErrorEvent,
	ReasonWatchFlapped,
}
