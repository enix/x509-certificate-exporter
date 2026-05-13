package cert

// Canonical reason codes for ItemError. These appear as the "reason" label
// of x509_source_errors_total, so they form a stable contract.
const (
	ReasonBadPEM             = "bad_pem"
	ReasonBadCRL             = "bad_crl"
	ReasonBadDER             = "bad_der"
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
)
